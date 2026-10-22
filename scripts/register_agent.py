#!/usr/bin/env python3
"""Register a Kiro custom agent with BalkanID and wait for approval (AGENT_ACCESS).

The request names a human owner, the agent's purpose, the IAM role it will run as, and a
fingerprint of the exact agent config. Approval is recorded in .kiro/balkanid/registrations.json,
which is committed with the agent so reviewers can see what was approved.

  python3 scripts/register_agent.py --agent infra-helper                 # lint, request, wait
  python3 scripts/register_agent.py --agent infra-helper --lint-only     # no API calls
  python3 scripts/register_agent.py --agent infra-helper --verify        # CI: approved and unchanged?
  python3 scripts/register_agent.py --agent db-reader --parent infra-helper   # child (subagent)

Exit 0 only when the current config is approved. Fails closed on deny or timeout.
"""

from __future__ import annotations

import argparse
import json
import sys

import balkanid_api as api
import kiro_config as kc

AGENT_TYPE = "kiro"


def build_input(agent: str, config: dict, sha: str, owner: str, args: argparse.Namespace) -> dict:
    purpose = args.purpose or config.get("description") or f"Kiro custom agent {agent}"
    metadata = {
        "platform": "kiro",
        "config_path": f".kiro/agents/{agent}.json",
        "config_sha256": sha,
        "aws_profile": kc.agent_profile(agent),
        "ephemeral_credentials_seconds": int(api.env_optional("AGENT_CREDENTIAL_SECONDS", "900")),
        **kc.summarize(config),
    }
    if args.parent:
        metadata["parent_agent"] = args.parent
    repo = api.env_optional("GITHUB_REPOSITORY")
    if repo:
        metadata["repository"] = repo

    agent_access: dict = {
        "action": "CREATE",
        "name": f"kiro/{agent}",
        "agentType": AGENT_TYPE,
        "description": purpose,
        "metadata": metadata,
    }
    integration = api.env_optional("INTEGRATION_ID")
    if integration:
        agent_access["integrationId"] = integration
    role_arn = args.role_arn or api.env_optional("AGENT_ROLE_ARN")
    if role_arn:
        agent_access["intendedIamRoleArn"] = role_arn

    return {
        "requestType": "AGENT_ACCESS",
        "employeeEmail": owner,
        "reason": purpose,
        "runAsync": False,
        "payload": {"agentAccess": agent_access},
    }


def verify(agent: str, sha: str) -> int:
    reg = kc.registration(agent)
    if not reg.get("request_id"):
        api.log_stderr(f"{agent}: no BalkanID registration in {kc.REGISTRATIONS_FILE.relative_to(kc.ROOT)}")
        return 1
    if reg.get("config_sha256") != sha:
        api.log_stderr(f"{agent}: config changed since approval; run register_agent.py again")
        return 1
    url, key_id, secret = api.api_client_from_env()
    state = api.request_state(url, key_id, secret, reg["request_id"])
    api.log_stderr(f"{agent}: request {reg['request_id']} is {state}")
    return 0 if state == "approved" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Register a Kiro agent with BalkanID")
    parser.add_argument("--agent", required=True, help="agent name (file .kiro/agents/<name>.json)")
    parser.add_argument("--purpose", default="", help="why this agent exists (defaults to its description)")
    parser.add_argument("--parent", default="", help="parent agent, when this agent runs as a subagent")
    parser.add_argument("--role-arn", default="", help="IAM role this agent will run as")
    parser.add_argument("--lint-only", action="store_true", help="validate the config, no API calls")
    parser.add_argument("--verify", action="store_true", help="check the recorded approval is live and current")
    parser.add_argument("--no-wait", action="store_true", help="create the request and exit without waiting")
    args = parser.parse_args(argv)

    api.load_dotenv()
    config = kc.load_agent(args.agent)
    sha = kc.fingerprint(config)

    problems = kc.lint_agent(args.agent, config)
    if args.parent:
        parent_reg = kc.registration(args.parent)
        if not parent_reg.get("request_id"):
            problems.append(f"parent agent {args.parent!r} is not registered")
    if problems:
        for p in problems:
            api.log_stderr(f"{args.agent}: {p}")
        return 1
    api.log_stderr(f"{args.agent}: config ok sha256={sha[:12]}")
    if args.lint_only:
        return 0
    if args.verify:
        return verify(args.agent, sha)

    owner = api.env("BALKANID_AGENT_OWNER_EMAIL")
    url, key_id, secret = api.api_client_from_env()
    poll_s, timeout_s = api.poll_settings()

    who = api.redact_identifier(owner) if api.ci_mode() else owner
    api.log_stderr(f"requesting BalkanID approval for kiro/{args.agent} owner={who}")
    request_id = api.create_request(url, key_id, secret, build_input(args.agent, config, sha, owner, args))
    kc.update_registration(
        args.agent,
        request_id=request_id,
        config_sha256=sha,
        owner=owner,
        parent=args.parent or None,
        integration_id=api.env_optional("INTEGRATION_ID") or None,
        role_arn=(args.role_arn or api.env_optional("AGENT_ROLE_ARN")) or None,
    )
    api.log_stderr(f"request_id={request_id} recorded in {kc.REGISTRATIONS_FILE.relative_to(kc.ROOT)}")

    if args.no_wait:
        print(json.dumps({"agent": args.agent, "request_id": request_id, "status": "pending"}))
        return 0

    try:
        api.poll_request(
            url, key_id, secret, request_id,
            wait_provisioning=False, poll_s=poll_s, timeout_s=timeout_s, label="AGENT_ACCESS",
        )
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        print(json.dumps({"agent": args.agent, "request_id": request_id, "status": "denied" if code == 1 else "failed"}))
        return code or 1

    print(json.dumps({"agent": args.agent, "request_id": request_id, "status": "approved", "config_sha256": sha}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
