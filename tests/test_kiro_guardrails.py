"""Tests for the Kiro guardrail scripts against a mock BalkanID API. Standard library only.

Run: python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import agent_credentials  # noqa: E402
import guardrails  # noqa: E402
import kiro_config as kc  # noqa: E402
import kiro_hook  # noqa: E402
import register_agent  # noqa: E402
import service_account_gate  # noqa: E402
from mock_balkanid import MockBalkanID  # noqa: E402

AGENT = "infra-helper"
PROFILE = "--profile balkanid-agent-infra-helper"


class Sandbox(unittest.TestCase):
    """Each test gets a private copy of .kiro/ and a private state dir."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        shutil.copytree(ROOT / ".kiro", self.tmp / ".kiro")
        patches = {
            "AGENTS_DIR": self.tmp / ".kiro" / "agents",
            "BALKANID_DIR": self.tmp / ".kiro" / "balkanid",
            "REGISTRATIONS_FILE": self.tmp / ".kiro" / "balkanid" / "registrations.json",
            "GUARDRAILS_FILE": self.tmp / ".kiro" / "balkanid" / "guardrails.json",
            "ROOT": self.tmp,
        }
        for name, value in patches.items():
            p = mock.patch.object(kc, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.mock = MockBalkanID().__enter__()
        self.addCleanup(self.mock.__exit__, None, None, None)
        env = {
            "BALKANID_SKIP_DOTENV": "1",
            "BALKANID_KIRO_STATE_DIR": str(self.tmp / "state"),
            "BALKANID_PUBLIC_API_URL": self.mock.url,
            "API_KEY_ID": "test-key",
            "API_KEY_SECRET": "test-secret",
            "BALKANID_AGENT_OWNER_EMAIL": "owner@example.com",
            "INTEGRATION_ID": "int-aws-1",
            "POLL_SECONDS": "1",
            "POLL_TIMEOUT_SECONDS": "5",
            "GQL_MAX_RETRIES": "1",
        }
        p = mock.patch.dict(os.environ, env, clear=False)
        p.start()
        self.addCleanup(p.stop)
        for key in ("CI", "GITHUB_ACTIONS", "AWS_PROFILE"):
            os.environ.pop(key, None)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def run_cli(self, main, argv, stdin: str = ""):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), mock.patch.object(sys, "stdin", io.StringIO(stdin)):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def register(self, status="approved"):
        self.mock.next_status = status
        code, out, err = self.run_cli(register_agent.main, ["--agent", AGENT])
        return code, out, err

    def hook(self, tool_name, tool_input):
        event = {"hook_event_name": "PreToolUse", "cwd": str(self.tmp), "session_id": "s1",
                 "tool_name": tool_name, "tool_input": tool_input}
        return self.run_cli(kiro_hook.main, ["pre-tool-use", "--agent", AGENT], json.dumps(event))


class GuardrailPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = guardrails.load_policy(ROOT / ".kiro" / "balkanid" / "guardrails.json")

    def decide(self, tool, inp):
        return guardrails.evaluate(self.policy, AGENT, tool, inp)

    def test_plain_read_allowed(self):
        self.assertEqual(self.decide("read", {"path": "src/app.py"}).outcome, "allow")

    def test_aws_cli_without_agent_profile_denied(self):
        d = self.decide("shell", {"command": "aws s3 ls"})
        self.assertEqual((d.outcome, d.rule_id), ("deny", "agent-identity-required"))

    def test_aws_cli_with_developer_profile_denied(self):
        d = self.decide("shell", {"command": "aws s3 ls --profile dev-admin"})
        self.assertEqual(d.rule_id, "agent-identity-required")

    def test_aws_cli_with_agent_profile_allowed(self):
        self.assertEqual(self.decide("shell", {"command": f"aws s3 ls {PROFILE}"}).outcome, "allow")

    def test_developer_credentials_denied(self):
        for cmd in ("cat ~/.aws/credentials", "aws configure export-credentials", "printenv"):
            with self.subTest(cmd=cmd):
                self.assertEqual(self.decide("shell", {"command": cmd}).rule_id, "developer-credentials")

    def test_privilege_escalation_denied(self):
        d = self.decide("shell", {"command": f"aws iam attach-role-policy --role-name x {PROFILE}"})
        self.assertEqual(d.rule_id, "privilege-escalation")

    def test_tampering_denied(self):
        d = self.decide("write", {"path": ".kiro/agents/infra-helper.json", "content": "{}"})
        self.assertEqual(d.rule_id, "guardrail-tampering")

    def test_destructive_denied(self):
        d = self.decide("shell", {"command": "terraform destroy -auto-approve"})
        self.assertEqual(d.rule_id, "destructive-operations")

    def test_secrets_are_sensitive(self):
        d = self.decide("shell", {"command": f"aws secretsmanager get-secret-value --secret-id db {PROFILE}"})
        self.assertEqual((d.outcome, d.rule_id), ("sensitive", "secrets-read"))
        self.assertEqual(d.grant["source_name"], "BalkanIDAgentSecretsRead")
        self.assertEqual(d.duration_seconds, 900)

    def test_mcp_tool_input_is_inspected(self):
        d = self.decide("@aws-api/call_aws", {"cli_command": "aws secretsmanager get-secret-value --secret-id x"})
        self.assertEqual(d.outcome, "sensitive")

    def test_production_is_sensitive(self):
        d = self.decide("shell", {"command": f"aws ecs list-services --cluster payments-prod {PROFILE}"})
        self.assertEqual((d.outcome, d.rule_id), ("sensitive", "production-access"))
        d = self.decide("shell", {"command": f"aws ecs list-services --cluster payments-staging {PROFILE}"})
        self.assertEqual(d.outcome, "allow")

    def test_subagent_requires_registered_child(self):
        self.assertEqual(self.decide("subagent", {"agent": "db-reader"}).rule_id, "subagent-not-registered")
        self.policy["_allowed_subagents"] = ["db-reader"]
        self.assertEqual(self.decide("subagent", {"agent": "db-reader"}).outcome, "allow")
        self.assertEqual(self.decide("subagent", {"agent": "admin-bot"}).outcome, "deny")


class ConfigLintTests(Sandbox):
    def test_example_agent_is_governable(self):
        self.assertEqual(kc.lint_agent(AGENT, kc.load_agent(AGENT)), [])

    def test_missing_pre_tool_hook_is_rejected(self):
        cfg = kc.load_agent(AGENT)
        cfg["hooks"] = [h for h in cfg["hooks"] if h["trigger"] != "PreToolUse"]
        self.assertTrue(any("PreToolUse" in p for p in kc.lint_agent(AGENT, cfg)))

    def test_aws_mcp_without_agent_profile_is_rejected(self):
        cfg = kc.load_agent(AGENT)
        cfg["mcpServers"]["aws-api"]["env"]["AWS_PROFILE"] = "default"
        self.assertTrue(any("AWS_PROFILE" in p for p in kc.lint_agent(AGENT, cfg)))

    def test_fingerprint_changes_with_config(self):
        cfg = kc.load_agent(AGENT)
        a = kc.fingerprint(cfg)
        cfg["tools"].append("web_fetch")
        self.assertNotEqual(a, kc.fingerprint(cfg))


class RegistrationTests(Sandbox):
    def test_register_approved_records_request(self):
        code, out, _ = self.register("approved")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["status"], "approved")
        reg = kc.registration(AGENT)
        self.assertEqual(reg["config_sha256"], kc.fingerprint(kc.load_agent(AGENT)))
        sent = self.mock.created[0]
        self.assertEqual(sent["requestType"], "AGENT_ACCESS")
        self.assertEqual(sent["payload"]["agentAccess"]["agentType"], "kiro")
        self.assertEqual(sent["payload"]["agentAccess"]["metadata"]["config_sha256"], reg["config_sha256"])

    def test_register_denied_fails_closed(self):
        code, out, _ = self.register("denied")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["status"], "denied")

    def test_verify(self):
        self.register("approved")
        code, _, _ = self.run_cli(register_agent.main, ["--agent", AGENT, "--verify"])
        self.assertEqual(code, 0)
        self.mock.set_status(kc.registration(AGENT)["request_id"], "rejected")
        code, _, _ = self.run_cli(register_agent.main, ["--agent", AGENT, "--verify"])
        self.assertEqual(code, 1)

    def test_service_account_payload(self):
        inp = service_account_gate.build_input(AGENT, "owner@example.com", "int-aws-1")
        self.assertEqual(inp["requestType"], "CREATE_SERVICE_ACCOUNT")
        self.assertEqual(inp["payload"]["entity"]["name"], "kiro-agent-infra-helper")


class HookTests(Sandbox):
    def test_unregistered_agent_is_blocked(self):
        code, _, err = self.hook("read", {"path": "README.md"})
        self.assertEqual(code, kiro_hook.BLOCK)
        self.assertIn("not registered", err)

    def test_approved_agent_allowed(self):
        self.register()
        code, _, err = self.hook("read", {"path": "README.md"})
        self.assertEqual(code, 0, err)

    def test_changed_config_is_blocked(self):
        self.register()
        cfg = kc.load_agent(AGENT)
        cfg["tools"].append("web_fetch")
        kc.agent_path(AGENT).write_text(json.dumps(cfg))
        code, _, err = self.hook("read", {"path": "README.md"})
        self.assertEqual(code, kiro_hook.BLOCK)
        self.assertIn("changed since BalkanID approved", err)

    def test_revoked_approval_is_blocked_after_cache(self):
        self.register()
        self.mock.set_status(kc.registration(AGENT)["request_id"], "rejected")
        shutil.rmtree(Path(os.environ["BALKANID_KIRO_STATE_DIR"]) / "status", ignore_errors=True)
        code, _, err = self.hook("read", {"path": "README.md"})
        self.assertEqual(code, kiro_hook.BLOCK)
        self.assertIn("denied", err)

    def test_deny_rule_blocks(self):
        self.register()
        code, _, err = self.hook("shell", {"command": "aws s3 ls --profile admin"})
        self.assertEqual(code, kiro_hook.BLOCK)
        self.assertIn("agent-identity-required", err)

    def test_sensitive_without_service_account_is_blocked(self):
        self.register()
        code, _, err = self.hook("shell", {"command": f"aws secretsmanager get-secret-value --secret-id db {PROFILE}"})
        self.assertEqual(code, kiro_hook.BLOCK)
        self.assertIn("setup_agent_profile.py", err)

    def test_sensitive_requests_grant_then_allows_after_approval(self):
        self.register()
        kc.update_registration(AGENT, service_account_identity_id="ident-42")
        cmd = {"command": f"aws secretsmanager get-secret-value --secret-id db {PROFILE}"}

        self.mock.next_status = "pending"
        code, _, err = self.hook("shell", cmd)
        self.assertEqual(code, kiro_hook.BLOCK)
        self.assertIn("Requested in BalkanID", err)
        grant_req = self.mock.created[-1]
        self.assertEqual(grant_req["requestType"], "SERVICE_ACCOUNT_ASSIGNMENT")
        self.assertEqual(grant_req["duration"], 900)
        self.assertEqual(grant_req["payload"]["entity"]["entity"], "ident-42")
        self.assertEqual(grant_req["payload"]["entity"]["scimPayload"]["grants"][0]["source_name"], "BalkanIDAgentSecretsRead")

        code, _, err = self.hook("shell", cmd)  # still pending, no duplicate request
        self.assertEqual(code, kiro_hook.BLOCK)
        self.assertIn("Waiting on BalkanID request", err)
        self.assertEqual(len(self.mock.created), 2)

        self.mock.set_status("req-2", "approved")
        code, _, err = self.hook("shell", cmd)
        self.assertEqual(code, 0, err)

    def test_sensitive_denied_is_not_re_requested(self):
        self.register()
        kc.update_registration(AGENT, service_account_identity_id="ident-42")
        cmd = {"command": f"aws secretsmanager get-secret-value --secret-id db {PROFILE}"}
        self.mock.next_status = "pending"
        self.hook("shell", cmd)
        self.mock.set_status("req-2", "denied")
        code, _, err = self.hook("shell", cmd)
        self.assertEqual(code, kiro_hook.BLOCK)
        self.assertIn("denied", err)
        self.assertEqual(len(self.mock.created), 2)

    def test_step_up_required_is_explained(self):
        self.register()
        kc.update_registration(AGENT, service_account_identity_id="ident-42")
        self.mock.step_up_required = True
        code, _, err = self.hook("shell", {"command": f"aws kms decrypt --ciphertext-blob x {PROFILE}"})
        self.assertEqual(code, kiro_hook.BLOCK)
        self.assertIn("step-up verification", err)

    def test_api_outage_uses_recent_cache_then_fails_closed(self):
        self.register()
        self.assertEqual(self.hook("read", {"path": "a"})[0], 0)
        os.environ["BALKANID_PUBLIC_API_URL"] = "http://127.0.0.1:9/api/public"
        status_dir = Path(os.environ["BALKANID_KIRO_STATE_DIR"]) / "status"
        for f in status_dir.glob("*.json"):  # make the cache old enough to force a re-check
            data = json.loads(f.read_text())
            data["checked_at"] -= 600
            f.write_text(json.dumps(data))
        self.assertEqual(self.hook("read", {"path": "a"})[0], 0)  # within max stale window
        os.environ["BALKANID_MAX_STALE_SECONDS"] = "1"
        code, _, err = self.hook("read", {"path": "a"})
        self.assertEqual(code, kiro_hook.BLOCK)
        self.assertIn("unknown", err)

    def test_session_start_and_end(self):
        code, _, err = self.run_cli(kiro_hook.main, ["session-start", "--agent", AGENT], "{}")
        self.assertEqual(code, 1)
        self.register()
        code, out, _ = self.run_cli(kiro_hook.main, ["session-start", "--agent", AGENT], "{}")
        self.assertEqual(code, 0)
        self.assertIn("--profile balkanid-agent-infra-helper", out)

        creds = Path(os.environ["BALKANID_KIRO_STATE_DIR"]) / "credentials"
        creds.mkdir(parents=True, exist_ok=True)
        (creds / f"{AGENT}.json").write_text("{}")
        code, out, _ = self.run_cli(kiro_hook.main, ["session-end", "--agent", AGENT], "{}")
        self.assertEqual(code, 0)
        self.assertFalse((creds / f"{AGENT}.json").exists())

    def test_audit_log_has_no_raw_input(self):
        self.register()
        self.hook("shell", {"command": "aws s3 ls --profile admin super-secret-arg"})
        log = (Path(os.environ["BALKANID_KIRO_STATE_DIR"]) / "audit.jsonl").read_text()
        self.assertNotIn("super-secret-arg", log)
        self.assertIn("agent-identity-required", log)


class CredentialProcessTests(Sandbox):
    def fake_aws(self):
        script = self.tmp / "aws"
        script.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "assert 'AWS_PROFILE' not in __import__('os').environ\n"
            "args = sys.argv[1:]\n"
            "open(sys.argv[0] + '.args', 'w').write(json.dumps(args))\n"
            "print(json.dumps({'Credentials': {'AccessKeyId': 'ASIAEXAMPLE', 'SecretAccessKey': 's', "
            "'SessionToken': 't', 'Expiration': '2099-01-01T00:00:00Z'}}))\n"
        )
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        os.environ["AWS_CLI"] = str(script)
        os.environ["AWS_PROFILE"] = "balkanid-agent-infra-helper"
        return script

    def test_unregistered_agent_gets_no_credentials(self):
        self.fake_aws()
        code, out, err = self.run_cli(agent_credentials.main, ["--agent", AGENT])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")

    def test_issues_short_lived_tagged_credentials(self):
        script = self.fake_aws()
        self.register()
        kc.update_registration(AGENT, role_arn="arn:aws:iam::123456789012:role/balkanid-kiro-agents/kiro-agent-infra-helper")
        code, out, err = self.run_cli(agent_credentials.main, ["--agent", AGENT])
        self.assertEqual(code, 0, err)
        creds = json.loads(out)
        self.assertEqual(creds["Version"], 1)
        self.assertEqual(creds["AccessKeyId"], "ASIAEXAMPLE")
        args = json.loads(Path(str(script) + ".args").read_text())
        self.assertIn("--source-identity", args)
        self.assertIn("Key=balkanid-agent,Value=infra-helper", args)
        self.assertEqual(args[args.index("--duration-seconds") + 1], "900")
        Path(str(script) + ".args").unlink()
        code, out2, _ = self.run_cli(agent_credentials.main, ["--agent", AGENT])  # served from cache
        self.assertEqual(out, out2)
        self.assertFalse(Path(str(script) + ".args").exists())


if __name__ == "__main__":
    unittest.main()


class ReviewRegressionTests(Sandbox):
    """Regressions for issues found in the pre-publication security review."""

    ROLE = "arn:aws:iam::123456789012:role/balkanid-kiro-agents/kiro-agent-infra-helper"

    def test_credentials_refuse_any_role_but_the_agents_own(self):
        import balkanid_api  # noqa: F401
        self.register()
        kc.update_registration(AGENT, role_arn="arn:aws:iam::123456789012:role/DeveloperAdmin")
        code, out, err = self.run_cli(agent_credentials.main, ["--agent", AGENT])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("refusing role", err)

    def test_setup_profile_rejects_foreign_role(self):
        import setup_agent_profile
        code, _, _ = 0, "", ""
        with self.assertRaises(SystemExit):
            self.run_cli(setup_agent_profile.main, ["--agent", AGENT, "--role-arn", "arn:aws:iam::1:role/admin",
                                                    "--skip-identity-lookup"])
        code, out, err = self.run_cli(setup_agent_profile.main, ["--agent", AGENT, "--role-arn", self.ROLE,
                                                                 "--skip-identity-lookup"])
        self.assertEqual(code, 0, err)

    def test_unreadable_hook_input_blocks(self):
        self.register()
        for stdin in ("", "not json", "[]", json.dumps({"toolName": "shell", "toolInput": {"command": "cat ~/.aws/credentials"}})):
            with self.subTest(stdin=stdin[:20]):
                code, _, err = self.run_cli(kiro_hook.main, ["pre-tool-use", "--agent", AGENT], stdin)
                self.assertEqual(code, kiro_hook.BLOCK)

    def test_approval_must_be_agent_access_for_this_config(self):
        self.register()
        good = kc.registration(AGENT)["request_id"]
        # Swap in an unrelated approved request id (for example a USER_ACCESS approval)
        self.mock.requests["req-other"] = {"id": "req-other", "status": "approved", "requestType": "USER_ACCESS",
                                           "metadata": {}}
        kc.update_registration(AGENT, request_id="req-other")
        code, _, err = self.hook("read", {"path": "README.md"})
        self.assertEqual(code, kiro_hook.BLOCK)
        self.assertIn("unbound", err)
        code, _, _ = self.run_cli(register_agent.main, ["--agent", AGENT, "--verify"])
        self.assertEqual(code, 1)
        # An AGENT_ACCESS approval for a different config fingerprint is not enough either
        self.mock.requests["req-old"] = {"id": "req-old", "status": "approved", "requestType": "AGENT_ACCESS",
                                         "metadata": {"agentAccess": {"metadata": {"config_sha256": "0" * 64}}}}
        kc.update_registration(AGENT, request_id="req-old")
        code, _, _ = self.run_cli(register_agent.main, ["--agent", AGENT, "--verify"])
        self.assertEqual(code, 1)
        kc.update_registration(AGENT, request_id=good)
        code, _, _ = self.run_cli(register_agent.main, ["--agent", AGENT, "--verify"])
        self.assertEqual(code, 0)

    def test_profile_rule_bypasses_closed(self):
        policy = guardrails.load_policy(kc.GUARDRAILS_FILE)
        for cmd in (f"aws s3 ls {PROFILE}; aws s3 ls", "aws s3 ls --profile balkanid-agent-infra-helper-x",
                    "/usr/local/bin/aws s3 ls", '"aws" s3 ls', f"AWS_PROFILE=default aws s3 ls {PROFILE}",
                    f"aws --region us-east-1 iam attach-role-policy --role-name x {PROFILE}",
                    "cat .env", "printenv API_KEY_SECRET", "rm -rf ~/", "git push origin +main",
                    "python3 scripts/setup_agent_profile.py --agent infra-helper --role-arn x"):
            with self.subTest(cmd=cmd):
                self.assertEqual(guardrails.evaluate(policy, AGENT, "shell", {"command": cmd}).outcome, "deny")
        for tool in ("str_replace", "fs_append", "delete_file"):
            d = guardrails.evaluate(policy, AGENT, tool, {"path": ".kiro/agents/infra-helper.json"})
            self.assertEqual(d.rule_id, "guardrail-tampering")

    def test_subagent_names_are_exact(self):
        policy = guardrails.load_policy(kc.GUARDRAILS_FILE)
        policy["_allowed_subagents"] = ["db-reader"]
        self.assertEqual(guardrails.evaluate(policy, AGENT, "subagent", {"agent": "evil", "note": "db-reader"}).outcome, "deny")
        self.assertEqual(guardrails.evaluate(policy, AGENT, "subagent", {"agent": "db-reader-admin"}).outcome, "deny")
        self.assertEqual(guardrails.evaluate(policy, AGENT, "subagent", {"agent": "db-reader"}).outcome, "allow")

    def test_grant_reason_does_not_leak_arguments(self):
        self.register()
        kc.update_registration(AGENT, service_account_identity_id="ident-42")
        self.mock.next_status = "pending"
        self.hook("shell", {"command": f"aws {PROFILE} secretsmanager get-secret-value --secret-id prod/db-password-XYZ"})
        reason = self.mock.created[-1]["reason"]
        self.assertNotIn("XYZ", reason)
        self.assertIn("aws secretsmanager get-secret-value", reason)

    def test_future_cache_timestamp_is_ignored(self):
        self.register()
        rid = kc.registration(AGENT)["request_id"]
        self.mock.set_status(rid, "denied")
        status = Path(os.environ["BALKANID_KIRO_STATE_DIR"]) / "status" / f"{rid}.json"
        status.parent.mkdir(parents=True, exist_ok=True)
        status.write_text(json.dumps({"state": "approved", "checked_at": 4102444800,
                                      "config_sha256": kc.fingerprint(kc.load_agent(AGENT)), "request_type": "AGENT_ACCESS"}))
        code, _, _ = self.hook("read", {"path": "README.md"})
        self.assertEqual(code, kiro_hook.BLOCK)

    def test_denied_grant_is_never_re_requested_automatically(self):
        self.register()
        kc.update_registration(AGENT, service_account_identity_id="ident-42")
        cmd = {"command": f"aws secretsmanager get-secret-value --secret-id db {PROFILE}"}
        self.mock.next_status = "pending"
        self.hook("shell", cmd)
        self.mock.set_status("req-2", "denied")
        grant = Path(os.environ["BALKANID_KIRO_STATE_DIR"]) / "grants" / AGENT / "secrets-read.json"
        data = json.loads(grant.read_text())
        data["created_at"] -= 86400 * 2  # long ago
        grant.write_text(json.dumps(data))
        code, _, err = self.hook("shell", cmd)
        self.assertEqual(code, kiro_hook.BLOCK)
        self.assertEqual(len(self.mock.created), 2)
        self.assertIn("clear-grant", err)
        self.run_cli(kiro_hook.main, ["clear-grant", "--agent", AGENT, "--rule", "secrets-read"])
        self.hook("shell", cmd)
        self.assertEqual(len(self.mock.created), 3)

    def test_session_end_only_clears_this_agent(self):
        creds = Path(os.environ["BALKANID_KIRO_STATE_DIR"]) / "credentials"
        creds.mkdir(parents=True, exist_ok=True)
        (creds / f"{AGENT}.json").write_text("{}")
        (creds / f"{AGENT}-2.json").write_text("{}")
        self.run_cli(kiro_hook.main, ["session-end", "--agent", AGENT], "{}")
        self.assertFalse((creds / f"{AGENT}.json").exists())
        self.assertTrue((creds / f"{AGENT}-2.json").exists())


class ApprovalParsingTests(unittest.TestCase):
    def test_denied_always_wins(self):
        import balkanid_api as api
        self.assertEqual(api.approval_outcome("completed", "denied"), "denied")
        self.assertEqual(api.approval_outcome("not_approved", None), "denied")
        self.assertEqual(api.approval_outcome("unapproved", None), "denied")
        self.assertIsNone(api.approval_outcome("pending_approval", None))
        self.assertEqual(api.approval_outcome(None, "approved"), "approved")
