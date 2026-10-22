#!/usr/bin/env python3
"""Kiro hook entry point for BalkanID agent guardrails.

Wired into each governed agent's config (.kiro/agents/<name>.json):

  SessionStart -> kiro_hook.py session-start --agent <name>
  PreToolUse   -> kiro_hook.py pre-tool-use  --agent <name>   (every tool, no matcher)
  SessionEnd   -> kiro_hook.py session-end   --agent <name>

Kiro passes the hook context as JSON on stdin (hook_event_name, cwd, session_id, and for
PreToolUse tool_name and tool_input). A non-zero exit from a PreToolUse command blocks the
tool call and sends stderr back to the agent, so every refusal below explains what to do.

Fail closed: if the agent is not approved, its config changed since approval, or BalkanID
cannot be reached and the cached status is stale, tool calls are blocked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import balkanid_api as api  # noqa: E402
import guardrails  # noqa: E402
import kiro_config as kc  # noqa: E402

BLOCK = 2  # any non-zero blocks a Kiro PreToolUse tool call; 2 is also the Claude Code convention


def read_event():
    """Parsed hook JSON, or None if stdin is empty or not JSON (callers fail closed)."""
    raw = sys.stdin.read() if not sys.stdin.isatty() else ""
    if not raw.strip():
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def hook_api_defaults() -> None:
    # Hooks run inline with the agent, so keep network waits short. Worst case for a sensitive
    # call is two API calls x 2 attempts x 8s plus backoff, inside the 60s hook timeout.
    os.environ.setdefault("GQL_MAX_RETRIES", "2")
    os.environ.setdefault("GQL_RETRY_BACKOFF_SECONDS", "1")
    os.environ.setdefault("GQL_TIMEOUT_SECONDS", "8")


def _json_load(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _json_save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def audit(agent: str, event: dict, outcome: str, rule: str = "", request_id: str = "") -> None:
    event = event if isinstance(event, dict) else {}
    tool_input = json.dumps(event.get("tool_input"), sort_keys=True, default=str)
    record = {
        "ts": int(time.time()),
        "agent": agent,
        "session_id": str(event.get("session_id", "")),
        "event": str(event.get("hook_event_name", "")),
        "tool": str(event.get("tool_name", "")),
        "input_sha256": hashlib.sha256(tool_input.encode()).hexdigest(),
        "outcome": outcome,
        "rule": rule,
        "request_id": request_id,
    }
    try:
        with open(kc.state_dir() / "audit.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass


def _bound(node: dict, request_type: str, config_sha256: str) -> bool:
    """Is this approved request really the one we think it is?"""
    if not api.request_type_is(node, request_type):
        return False
    if config_sha256:
        return config_sha256 in [str(v) for v in api.find_in_metadata(node.get("metadata"), "config_sha256")]
    return True


def cached_request_state(
    request_id: str,
    cache_seconds: int,
    max_stale_seconds: int,
    *,
    request_type: str,
    config_sha256: str = "",
) -> str:
    """Live BalkanID status with a short cache.

    Returns approved | denied | pending | missing | unbound | unknown. "unbound" means the
    request exists and is approved but is not the expected type, or does not carry the
    expected config fingerprint, so it cannot vouch for this agent.
    """
    path = kc.state_dir() / "status" / f"{request_id}.json"
    cached = _json_load(path)
    now = time.time()
    checked_at = cached.get("checked_at", 0)
    trusted_cache = (
        cached
        and isinstance(checked_at, (int, float))
        and checked_at <= now + 5  # a timestamp from the future is forged or broken: ignore it
        and cached.get("config_sha256", "") == config_sha256
        and cached.get("request_type", "") == request_type
    )
    if trusted_cache and now - checked_at < cache_seconds:
        return cached.get("state", "unknown")
    try:
        url, key_id, secret = api.api_client_from_env()
        state, node = api.request_check(url, key_id, secret, request_id)
    except SystemExit as exc:
        api.log_stderr(f"BalkanID status check failed: {exc}")
        if trusted_cache and cached.get("state") == "approved" and now - checked_at < max_stale_seconds:
            return "approved"
        return "unknown"
    if state == "approved" and not _bound(node, request_type, config_sha256):
        if api.env_optional("BALKANID_ALLOW_UNBOUND_APPROVAL").lower() not in ("1", "true", "yes"):
            state = "unbound"
    _json_save(path, {"state": state, "checked_at": now, "config_sha256": config_sha256, "request_type": request_type})
    return state


def registration_check(agent: str, policy: dict) -> tuple[bool, str, dict]:
    """Is this exact agent config approved in BalkanID right now?"""
    config = kc.load_agent(agent)
    current = kc.fingerprint(config)
    reg = kc.registration(agent)
    if not reg.get("request_id"):
        return False, (
            f"Agent {agent!r} is not registered with BalkanID. A human owner must run "
            f"`python3 scripts/register_agent.py --agent {agent}` and get it approved."
        ), reg
    if reg.get("config_sha256") != current:
        return False, (
            f"Agent {agent!r} changed since BalkanID approved it (approved {str(reg.get('config_sha256', ''))[:12]}, "
            f"now {current[:12]}). Re-register the new config before using it."
        ), reg
    cache_s = int(policy.get("status_cache_seconds", 300))
    max_stale = int(api.env_optional("BALKANID_MAX_STALE_SECONDS", "3600"))
    state = cached_request_state(reg["request_id"], cache_s, max_stale,
                                 request_type="AGENT_ACCESS", config_sha256=current)
    if state != "approved":
        hint = (" The recorded request is not an AGENT_ACCESS approval for this exact config."
                if state == "unbound" else "")
        return False, (
            f"BalkanID approval for agent {agent!r} is {state} (request {reg['request_id']}).{hint} "
            "Tools stay blocked until it is approved."
        ), reg
    return True, "", reg


def allowed_subagents(agent: str) -> list[str]:
    agents = kc.load_registrations().get("agents") or {}
    return sorted(name for name, entry in agents.items() if entry.get("parent") == agent)


def redacted_summary(tool_name: str, tool_input) -> str:
    """What to show an approver without leaking arguments (which may hold secrets)."""
    for text in guardrails.flatten_strings(tool_input):
        m = re.search(r"\baws\b(?:\s+--?[\w-]+(?:[ =][^\s-][^\s]*)?)*\s+([a-z0-9-]+)\s+([a-z0-9-]+)", text)
        if m:
            return f"{tool_name}: aws {m.group(1)} {m.group(2)}"
    return f"{tool_name}"


def grant_path(agent: str, rule_id: str) -> Path:
    return kc.state_dir() / "grants" / agent / f"{rule_id}.json"


def sensitive_check(agent: str, reg: dict, decision: guardrails.Decision, event: dict, policy: dict) -> tuple[bool, str, str]:
    """Allow only while a BalkanID grant for this rule is approved and inside its window."""
    path = grant_path(agent, decision.rule_id)
    grant = _json_load(path)
    now = time.time()

    if grant.get("request_id"):
        rid = str(grant["request_id"])
        created_at = float(grant.get("created_at") or 0)
        duration = int(grant.get("duration_seconds") or 0)
        # The window is measured from when the request was raised, so the hook never allows
        # longer than BalkanID does. BalkanID also removes the grant policy at the end.
        window_end = created_at + duration
        # Re-check live while pending; once approved, a one-minute cache is enough.
        cache_s = 60 if grant.get("approved_seen") else 0
        state = cached_request_state(rid, cache_s, 0, request_type="SERVICE_ACCOUNT_ASSIGNMENT")
        if state == "approved" and now < window_end:
            if not grant.get("approved_seen"):
                grant["approved_seen"] = now
                _json_save(path, grant)
            return True, "", rid
        if state in ("pending", "unknown") and now < window_end:
            return False, (
                f"{decision.message} Waiting on BalkanID request {rid} ({state}). "
                "Retry after the approver completes step-up verification and approves."
            ), rid
        if state in ("denied", "missing", "unbound"):
            return False, (
                f"{decision.message} BalkanID request {rid} is {state}. Do not retry; tell the user. "
                f"The owner can clear it with: python3 scripts/kiro_hook.py clear-grant --agent {agent} "
                f"--rule {decision.rule_id}"
            ), rid
        # approved or pending, but the window has passed: raise a fresh request below

    identity_id = reg.get("service_account_identity_id")
    integration_id = reg.get("integration_id") or api.env_optional("INTEGRATION_ID")
    if not identity_id or not integration_id or not decision.grant:
        return False, (
            f"{decision.message} This agent has no BalkanID service account to grant against; "
            "run scripts/setup_agent_profile.py first."
        ), ""

    inp = {
        "requestType": "SERVICE_ACCOUNT_ASSIGNMENT",
        "reason": f"Kiro agent {agent} needs '{decision.rule_id}' "
                  f"({redacted_summary(str(event.get('tool_name', '')), event.get('tool_input'))})",
        "duration": decision.duration_seconds,
        "payload": {
            "entity": {
                "provisioningOption": "app",
                "integrationId": integration_id,
                "entity": identity_id,
                "scimPayload": {"grants": [decision.grant], "revokes": []},
            }
        },
    }
    try:
        url, key_id, secret = api.api_client_from_env()
        created = api.create_request_raw(url, key_id, secret, inp)
    except SystemExit as exc:
        return False, f"{decision.message} Could not reach BalkanID to request access ({exc}).", ""

    if created.get("stepUpRequired"):
        return False, (
            f"{decision.message} BalkanID requires step-up verification before this request can be raised. "
            "The owner should complete MFA in BalkanID, then retry."
        ), ""
    request_id = created.get("id") or ""
    if not created.get("success") or not request_id:
        return False, f"{decision.message} BalkanID did not accept the access request.", ""

    _json_save(path, {"request_id": request_id, "created_at": now, "duration_seconds": decision.duration_seconds})
    return False, (
        f"{decision.message} Requested in BalkanID as {request_id} for {decision.duration_seconds // 60} minutes. "
        "Do not work around this. Tell the user approval is pending and retry once approved."
    ), request_id


def cmd_pre_tool_use(agent: str, event) -> int:
    if not isinstance(event, dict) or not isinstance(event.get("tool_name"), str) or not event["tool_name"].strip():
        audit(agent, event if isinstance(event, dict) else {}, "blocked", "unrecognized-input")
        print("[BalkanID] guardrail could not read the tool call from Kiro; blocking.", file=sys.stderr)
        return BLOCK

    policy = guardrails.load_policy(kc.GUARDRAILS_FILE)
    ok, why, reg = registration_check(agent, policy)
    if not ok:
        audit(agent, event, "blocked", "unregistered")
        print(why, file=sys.stderr)
        return BLOCK

    policy["_allowed_subagents"] = allowed_subagents(agent)
    decision = guardrails.evaluate(policy, agent, event["tool_name"], event.get("tool_input"))

    if decision.outcome == "deny":
        audit(agent, event, "denied", decision.rule_id)
        print(f"[BalkanID] {decision.message} (rule: {decision.rule_id})", file=sys.stderr)
        return BLOCK

    if decision.outcome == "sensitive":
        allowed, why, request_id = sensitive_check(agent, reg, decision, event, policy)
        audit(agent, event, "allowed" if allowed else "held", decision.rule_id, request_id)
        if not allowed:
            print(f"[BalkanID] {why}", file=sys.stderr)
            return BLOCK
        return 0

    audit(agent, event, "allowed")
    return 0


def cmd_session_start(agent: str, event: dict) -> int:
    policy = guardrails.load_policy(kc.GUARDRAILS_FILE)
    ok, why, reg = registration_check(agent, policy)
    audit(agent, event, "session-start" if ok else "session-start-blocked")
    if not ok:
        print(f"[BalkanID] {why}", file=sys.stderr)
        return 1
    profile = kc.agent_profile(agent)
    print(
        f"BalkanID governance is active for agent '{agent}' (approved request {reg['request_id']}, "
        f"owner {reg.get('owner', 'on file')}). Run every AWS CLI command with --profile {profile}; "
        "that identity is scoped to this agent and expires automatically. You cannot use the developer's "
        "credentials. Secrets, production and customer data need a BalkanID approval: if a tool call is "
        "held for approval, tell the user and wait rather than looking for another way."
    )
    return 0


def cmd_session_end(agent: str, event) -> int:
    removed = 0
    path = kc.state_dir() / "credentials" / f"{agent}.json"
    if path.exists():
        try:
            path.unlink()
            removed = 1
        except OSError:
            pass
    audit(agent, event if isinstance(event, dict) else {}, "session-end", request_id=str(removed))
    print(f"BalkanID: cleared {removed} cached credential set(s) for agent '{agent}'.")
    return 0


def cmd_clear_grant(agent: str, rule: str) -> int:
    """Human-only: forget a denied or stuck sensitive-grant request so the hook may ask again."""
    path = grant_path(agent, rule)
    if path.exists():
        path.unlink()
        print(f"cleared grant state for {agent}/{rule}")
    else:
        print(f"no grant state for {agent}/{rule}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["session-start", "pre-tool-use", "session-end", "clear-grant"])
    parser.add_argument("--agent", required=True)
    parser.add_argument("--rule", default="", help="clear-grant: the sensitive rule id")
    args = parser.parse_args(argv)

    api.load_dotenv()
    hook_api_defaults()
    if args.mode == "clear-grant":
        if not args.rule:
            parser.error("clear-grant needs --rule")
        return cmd_clear_grant(args.agent, args.rule)
    event = read_event()
    try:
        if args.mode == "pre-tool-use":
            return cmd_pre_tool_use(args.agent, event)
        if args.mode == "session-start":
            return cmd_session_start(args.agent, event if isinstance(event, dict) else {})
        return cmd_session_end(args.agent, event)
    except SystemExit as exc:
        # Anything unexpected (missing config, bad JSON) blocks rather than allows.
        print(f"[BalkanID] guardrail error, blocking: {exc}", file=sys.stderr)
        return BLOCK
    except Exception as exc:  # noqa: BLE001 - fail closed on any bug
        print(f"[BalkanID] guardrail error, blocking: {type(exc).__name__}: {exc}", file=sys.stderr)
        return BLOCK


if __name__ == "__main__":
    sys.exit(main())
