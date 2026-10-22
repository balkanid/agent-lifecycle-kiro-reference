#!/usr/bin/env python3
"""Evaluate a Kiro tool call against the local guardrail policy (.kiro/balkanid/guardrails.json).

Pure functions, no network. kiro_hook.py calls evaluate() for every PreToolUse event.

Decision order:
  1. deny rules            -> "deny"       (auto-deny, never reaches BalkanID)
  2. AWS CLI profile rule  -> "deny"       (agent must run as its own BalkanID-issued identity)
  3. sensitive rules       -> "sensitive"  (needs a live, approved BalkanID grant)
  4. otherwise             -> "allow"

The guardrail file is the client-side half. The server-side half is the agent's IAM role
and its permissions boundary: even if a hook were bypassed, the role cannot do more than
BalkanID approved.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

SHELL_TOOLS = {"shell", "execute_bash", "execute_cmd", "executebash", "execute_pwsh", "executepwsh"}
SUBAGENT_TOOLS = {"subagent", "use_subagent", "delegate"}
SUBAGENT_NAME_KEYS = ("agent", "agent_name", "agentName", "name", "subagent", "subagent_name", "target_agent")

# An AWS CLI invocation anywhere in a command segment: bare, by path, or quoted.
AWS_CLI_RE = re.compile(r"""(^|[\s;&|(`$/'"])aws(\.exe)?['"]?\s+\S""", re.IGNORECASE)
SEGMENT_SPLIT_RE = re.compile(r"\|\||&&|[;|&\n]|\$\(|`")


@dataclass
class Decision:
    outcome: str  # allow | deny | sensitive
    rule_id: str = ""
    message: str = ""
    grant: dict = field(default_factory=dict)
    duration_seconds: int = 0


def load_policy(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        policy = json.load(fh)
    for section in ("deny", "sensitive"):
        for rule in policy.get(section, []):
            rule["_compiled"] = [re.compile(p, re.IGNORECASE) for p in rule.get("patterns", [])]
    return policy


def normalize_tool(name: str) -> str:
    base = (name or "").strip()
    return base.lower()


def flatten_strings(value) -> list[str]:
    """Collect every string inside tool_input. Kiro tool input shapes vary by tool and version."""
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(flatten_strings(v))
    elif isinstance(value, (list, tuple)):
        for v in value:
            out.extend(flatten_strings(v))
    elif value is not None:
        out.append(str(value))
    return out


def subagent_names(tool_input) -> set[str]:
    """Exact agent names a subagent/delegate call targets (looks in name-like fields only)."""
    names: set[str] = set()
    if isinstance(tool_input, dict):
        for key, value in tool_input.items():
            if key in SUBAGENT_NAME_KEYS and isinstance(value, str):
                names.add(value.strip())
            elif isinstance(value, (dict, list)):
                names |= subagent_names(value)
    elif isinstance(tool_input, list):
        for value in tool_input:
            names |= subagent_names(value)
    return names


def _tool_matches(rule: dict, tool: str) -> bool:
    tools = [t.lower() for t in rule.get("tools") or []]
    if not tools:
        return True
    for t in tools:
        if t.endswith("*") and tool.startswith(t[:-1]):
            return True
        if t == tool:
            return True
    return False


def _first_match(rule: dict, haystack: list[str]) -> str:
    for rx in rule.get("_compiled", []):
        for text in haystack:
            if rx.search(text):
                return rx.pattern
    return ""


def evaluate(policy: dict, agent: str, tool_name: str, tool_input) -> Decision:
    tool = normalize_tool(tool_name)
    haystack = flatten_strings(tool_input) + [tool_name or ""]

    for rule in policy.get("deny", []):
        if _tool_matches(rule, tool) and _first_match(rule, haystack):
            return Decision(
                "deny",
                rule.get("id", "deny"),
                rule.get("message") or f"blocked by BalkanID guardrail {rule.get('id')!r}",
            )

    if policy.get("require_agent_profile_for_aws_cli", True) and tool in SHELL_TOOLS:
        profile = f"balkanid-agent-{agent}"
        own_profile = re.compile(rf"""--profile(\s+|=)['"]?{re.escape(profile)}['"]?(\s|$)""")
        for text in haystack:
            for segment in SEGMENT_SPLIT_RE.split(text):
                if AWS_CLI_RE.search(segment) and not own_profile.search(segment):
                    return Decision(
                        "deny",
                        "agent-identity-required",
                        f"Every AWS CLI call from this agent must run as its own identity: add --profile {profile} "
                        "to each aws command. The developer's credentials are not available to agents.",
                    )

    if tool in SUBAGENT_TOOLS:
        allowed = set(policy.get("_allowed_subagents") or [])
        requested = subagent_names(tool_input)
        if not allowed or not requested or not requested <= allowed:
            return Decision(
                "deny",
                "subagent-not-registered",
                f"subagents must be BalkanID-registered children of {agent!r} named exactly in the call; "
                f"approved children: {sorted(allowed) or 'none'}",
            )

    for rule in policy.get("sensitive", []):
        if _tool_matches(rule, tool) and _first_match(rule, haystack):
            return Decision(
                "sensitive",
                rule.get("id", "sensitive"),
                rule.get("message") or f"sensitive operation {rule.get('id')!r} needs BalkanID approval",
                grant=rule.get("grant") or {},
                duration_seconds=int(rule.get("duration_seconds") or 900),
            )

    return Decision("allow")
