#!/usr/bin/env python3
"""Check local setup before registering or running a governed Kiro agent.

  python3 scripts/preflight.py --agent infra-helper
"""

from __future__ import annotations

import argparse
import shutil
import sys

import balkanid_api as api
import kiro_config as kc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--agent", required=True)
    args = parser.parse_args(argv)
    api.load_dotenv()

    errors: list[str] = []
    warnings: list[str] = []
    for name in ("BALKANID_PUBLIC_API_URL", "API_KEY_ID", "API_KEY_SECRET", "BALKANID_AGENT_OWNER_EMAIL"):
        if not api.env_optional(name):
            errors.append(f"missing {name}")
    if not api.env_optional("INTEGRATION_ID"):
        warnings.append("INTEGRATION_ID not set: service account gate, identity lookup and sensitive grants need it")
    if not shutil.which(api.env_optional("AWS_CLI") or "aws"):
        warnings.append("aws CLI not found: agent credentials cannot be issued")

    try:
        config = kc.load_agent(args.agent)
    except SystemExit as exc:
        errors.append(str(exc))
        config = None
    if config is not None:
        errors.extend(kc.lint_agent(args.agent, config))
        reg = kc.registration(args.agent)
        if not reg.get("request_id"):
            warnings.append("agent not registered yet: run scripts/register_agent.py")
        elif reg.get("config_sha256") != kc.fingerprint(config):
            warnings.append("agent config changed since its BalkanID approval: re-register")
        if reg and not reg.get("role_arn"):
            warnings.append("no role_arn recorded: run scripts/setup_agent_profile.py after terraform/agent-role")

    try:
        import guardrails

        guardrails.load_policy(kc.GUARDRAILS_FILE)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"guardrails.json invalid: {exc}")

    for msg in warnings:
        api.log_stderr(f"warning: {msg}")
    for msg in errors:
        api.log_stderr(f"error: {msg}")
    if errors:
        return 1
    api.log_stderr("preflight ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
