#!/usr/bin/env python3
"""Kiro agent config helpers: load, fingerprint, lint, and track BalkanID registrations.

A Kiro custom agent is a JSON file in .kiro/agents/<name>.json. BalkanID approves a
specific version of that file: the SHA-256 of its canonical JSON. Any change to tools,
MCP servers, permissions or hooks produces a new fingerprint and needs a new approval.

Registrations live in .kiro/balkanid/registrations.json and are committed alongside the
agent config, so reviewers see which BalkanID request approved which config version.
Request ids are not secrets; approval status is always re-checked live against BalkanID.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

# BALKANID_KIRO_ROOT lets CI verify a pull request's .kiro/ data with trusted scripts from the base branch.
ROOT = Path(os.environ.get("BALKANID_KIRO_ROOT") or Path(__file__).resolve().parent.parent).resolve()
AGENTS_DIR = ROOT / ".kiro" / "agents"
BALKANID_DIR = ROOT / ".kiro" / "balkanid"
REGISTRATIONS_FILE = BALKANID_DIR / "registrations.json"
GUARDRAILS_FILE = BALKANID_DIR / "guardrails.json"

AGENT_PROFILE_PREFIX = "balkanid-agent-"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")  # matches terraform/agent-role

# Hooks every governed agent must carry. Without the PreToolUse hook nothing is enforced.
REQUIRED_HOOK_TRIGGERS = {
    "SessionStart": "session-start",
    "PreToolUse": "pre-tool-use",
    "SessionEnd": "session-end",
}

# Paths the agent must never read or write: the developer's own credentials.
REQUIRED_DENY_PATHS = ("~/.aws/**",)


def agent_path(name: str) -> Path:
    return AGENTS_DIR / f"{name}.json"


def load_agent(name: str) -> dict:
    path = agent_path(name)
    if not path.is_file():
        raise SystemExit(f"agent config not found: {path.relative_to(ROOT)}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def fingerprint(config: dict) -> str:
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def agent_profile(name: str) -> str:
    return f"{AGENT_PROFILE_PREFIX}{name}"


ROLE_PATH = "/balkanid-kiro-agents/"


def expected_role_re(name: str) -> re.Pattern:
    """The only role an agent's credentials may ever come from (created by terraform/agent-role)."""
    return re.compile(rf"^arn:aws:iam::\d{{12}}:role{re.escape(ROLE_PATH)}kiro-agent-{re.escape(name)}$")


def role_arn_ok(name: str, arn: str) -> bool:
    return bool(expected_role_re(name).match(arn or ""))


def _hook_commands(config: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for hook in config.get("hooks") or []:
        if not isinstance(hook, dict):
            continue
        if hook.get("enabled") is False:
            continue
        action = hook.get("action") or {}
        if action.get("type") != "command":
            continue
        out.setdefault(hook.get("trigger", ""), []).append(action.get("command", ""))
    return out


def lint_agent(name: str, config: dict) -> list[str]:
    """Return a list of problems. Empty list means the config is governable."""
    problems: list[str] = []
    if not NAME_RE.match(name):
        problems.append(f"agent name {name!r} must be lowercase letters, digits and hyphens")
    if config.get("name") and config["name"] != name:
        problems.append(f"config name {config['name']!r} does not match file name {name!r}")

    hooks = _hook_commands(config)
    for trigger, mode in REQUIRED_HOOK_TRIGGERS.items():
        commands = hooks.get(trigger, [])
        wanted = f"kiro_hook.py {mode} --agent {name}"
        if not any(wanted in cmd for cmd in commands):
            problems.append(f"missing {trigger} hook running: python3 scripts/{wanted}")

    for hook in config.get("hooks") or []:
        if isinstance(hook, dict) and hook.get("trigger") == "PreToolUse" and "kiro_hook.py pre-tool-use" in (
            (hook.get("action") or {}).get("command", "")
        ):
            if hook.get("matcher") not in (None, "", "*", ".*"):
                problems.append("the BalkanID PreToolUse hook must match every tool (omit matcher or use \"*\")")

    rules = ((config.get("permissions") or {}).get("rules")) or []
    denied_paths = {
        pattern
        for rule in rules
        if isinstance(rule, dict) and rule.get("effect") == "deny"
        for pattern in (rule.get("match") or [])
    }
    for required in REQUIRED_DENY_PATHS:
        if required not in denied_paths:
            problems.append(f"permissions.rules must deny {required!r} (developer credentials)")

    profile = agent_profile(name)
    for server_name, server in (config.get("mcpServers") or {}).items():
        env_block = (server or {}).get("env") or {}
        joined = " ".join([server.get("command", "")] + [str(a) for a in server.get("args") or []]).lower()
        if "aws" in server_name.lower() or "aws" in joined:
            if env_block.get("AWS_PROFILE") != profile:
                problems.append(
                    f"MCP server {server_name!r} talks to AWS but does not set env AWS_PROFILE={profile!r}"
                )
    return problems


def summarize(config: dict) -> dict:
    """Small, reviewable summary sent to BalkanID as request metadata."""
    rules = ((config.get("permissions") or {}).get("rules")) or []
    return {
        "tools": config.get("tools") or [],
        "mcp_servers": sorted((config.get("mcpServers") or {}).keys()),
        "hooks": sorted({h.get("trigger", "") for h in config.get("hooks") or [] if isinstance(h, dict)}),
        "deny_rules": sum(1 for r in rules if isinstance(r, dict) and r.get("effect") == "deny"),
        "model": config.get("model", ""),
    }


def load_registrations() -> dict:
    if not REGISTRATIONS_FILE.is_file():
        return {"version": 1, "agents": {}}
    with open(REGISTRATIONS_FILE, encoding="utf-8") as fh:
        data = json.load(fh)
    data.setdefault("version", 1)
    data.setdefault("agents", {})
    return data


def save_registrations(data: dict) -> None:
    BALKANID_DIR.mkdir(parents=True, exist_ok=True)
    tmp = REGISTRATIONS_FILE.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, REGISTRATIONS_FILE)


def registration(name: str) -> dict:
    return (load_registrations().get("agents") or {}).get(name) or {}


def update_registration(name: str, **fields) -> dict:
    data = load_registrations()
    entry = data["agents"].setdefault(name, {})
    entry.update({k: v for k, v in fields.items() if v is not None})
    save_registrations(data)
    return entry


def state_dir() -> Path:
    """Per-developer cache for status checks, short-lived credentials and the audit log."""
    base = os.environ.get("BALKANID_KIRO_STATE_DIR") or os.path.join(
        os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "balkanid-kiro"
    )
    path = Path(base)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path
