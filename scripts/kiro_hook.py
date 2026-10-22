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
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import balkanid_api as api  # noqa: E402
import guardrails  # noqa: E402
import kiro_config as kc  # noqa: E402

BLOCK = 2  # any non-zero blocks a Kiro PreToolUse tool call; 2 is also the Claude Code convention
DENIAL_COOLDOWN_SECONDS = 600  # after a denial, do not re-raise the same request for 10 minutes


def read_event() -> dict:
    raw = sys.stdin.read() if not sys.stdin.isatty() else ""
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def hook_api_defaults() -> None:
    # Hooks run inline with the agent, so keep network waits short.
    os.environ.setdefault("GQL_MAX_RETRIES", "2")
    os.environ.setdefault("GQL_RETRY_BACKOFF_SECONDS", "1")
    os.environ.setdefault("GQL_TIMEOUT_SECONDS", "10")


def _json_load(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def _json_save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def audit(agent: str, event: dict, outcome: str, rule: str = "", request_id: str = "") -> None:
    tool_input = json.dumps(event.get("tool_input"), sort_keys=True, default=str)
    record = {
        "ts": int(time.time()),
        "agent": agent,
        "session_id": event.get("session_id", ""),
        "event": event.get("hook_event_name", ""),
        "tool": event.get("tool_name", ""),
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


def cached_request_state(request_id: str, cache_seconds: int, max_stale_seconds: int) -> str:
    """Live BalkanID status with a short cache. Returns approved|denied|pending|missing|unknown."""
    path = kc.state_dir() / "status" / f"{request_id}.json"
    cached = _json_load(path)
    now = time.time()
    if cached and now - cached.get("checked_at", 0) < cache_seconds:
        return cached.get("state", "unknown")
    try:
        url, key_id, secret = api.api_client_from_env()
        state = api.request_state(url, key_id, secret, request_id)
    except SystemExit as exc:
        api.log_stderr(f"BalkanID status check failed: {exc}")
        if cached and cached.get("state") == "approved" and now - cached.get("checked_at", 0) < max_stale_seconds:
            return "approved"
        return "unknown"
    _json_save(path, {"state": state, "checked_at": now})
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
            f"Agent {agent!r} changed since BalkanID approved it (approved {reg.get('config_sha256', '')[:12]}, "
            f"now {current[:12]}). Re-register the new config before using it."
        ), reg
    cache_s = int(policy.get("status_cache_seconds", 300))
    max_stale = int(api.env_optional("BALKANID_MAX_STALE_SECONDS", "3600"))
    state = cached_request_state(reg["request_id"], cache_s, max_stale)
    if state != "approved":
        return False, (
            f"BalkanID approval for agent {agent!r} is {state} (request {reg['request_id']}). "
            "Tools stay blocked until it is approved."
        ), reg
    return True, "", reg


def allowed_subagents(agent: str) -> list[str]:
    agents = kc.load_registrations().get("agents") or {}
    return sorted(name for name, entry in agents.items() if entry.get("parent") == agent)


def sensitive_check(agent: str, reg: dict, decision: guardrails.Decision, event: dict, policy: dict) -> tuple[bool, str, str]:
    """Allow only while a BalkanID grant for this rule is approved and unexpired."""
    path = kc.state_dir() / "grants" / agent / f"{decision.rule_id}.json"
    grant = _json_load(path)
    now = time.time()

    if grant.get("request_id"):
        approved_at = grant.get("approved_at")
        if approved_at and now < approved_at + grant.get("duration_seconds", 0):
            return True, "", grant["request_id"]
        if not approved_at:
            state = cached_request_state(grant["request_id"], 0, 0)  # always live while pending
            if state == "approved":
                grant["approved_at"] = now
                _json_save(path, grant)
                return True, "", grant["request_id"]
            if state in ("pending", "unknown"):
                return False, (
                    f"{decision.message} Waiting on BalkanID request {grant['request_id']} ({state}). "
                    "Retry after the approver completes step-up verification and approves."
                ), grant["request_id"]
            if state == "denied" and now - grant.get("created_at", 0) < DENIAL_COOLDOWN_SECONDS:
                return False, (
                    f"{decision.message} BalkanID denied request {grant['request_id']}. "
                    "Do not retry; tell the user the access was refused."
                ), grant["request_id"]
        # expired, missing, or denied long enough ago: ask again

    identity_id = reg.get("service_account_identity_id")
    integration_id = reg.get("integration_id") or api.env_optional("INTEGRATION_ID")
    if not identity_id or not integration_id or not decision.grant:
        return False, (
            f"{decision.message} This agent has no BalkanID service account to grant against; "
            "run scripts/setup_agent_profile.py first."
        ), ""

    command_preview = " ".join(guardrails.flatten_strings(event.get("tool_input")))[:300]
    inp = {
        "requestType": "SERVICE_ACCOUNT_ASSIGNMENT",
        "reason": f"Kiro agent {agent} needs '{decision.rule_id}' for: {command_preview}",
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


def cmd_pre_tool_use(agent: str, event: dict) -> int:
    policy = guardrails.load_policy(kc.GUARDRAILS_FILE)
    ok, why, reg = registration_check(agent, policy)
    if not ok:
        audit(agent, event, "blocked", "unregistered")
        print(why, file=sys.stderr)
        return BLOCK

    policy["_allowed_subagents"] = allowed_subagents(agent)
    decision = guardrails.evaluate(policy, agent, event.get("tool_name", ""), event.get("tool_input"))

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


def cmd_session_end(agent: str, event: dict) -> int:
    removed = 0
    for path in (kc.state_dir() / "credentials").glob(f"{agent}*.json"):
        try:
            path.unlink()
            removed += 1
        except OSError:
            pass
    audit(agent, event, "session-end", request_id=str(removed))
    print(f"BalkanID: cleared {removed} cached credential set(s) for agent '{agent}'.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["session-start", "pre-tool-use", "session-end"])
    parser.add_argument("--agent", required=True)
    args = parser.parse_args(argv)

    api.load_dotenv()
    hook_api_defaults()
    event = read_event()
    try:
        if args.mode == "pre-tool-use":
            return cmd_pre_tool_use(args.agent, event)
        if args.mode == "session-start":
            return cmd_session_start(args.agent, event)
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
