#!/usr/bin/env python3
"""AWS credential_process for a Kiro agent's own identity.

~/.aws/config (written by scripts/setup_agent_profile.py):

  [profile balkanid-agent-infra-helper]
  credential_process = python3 /path/to/repo/scripts/agent_credentials.py --agent infra-helper
  region = us-east-1

Every time the AWS CLI or an AWS MCP server needs credentials for that profile, this script:
  1. confirms the agent's current config is approved in BalkanID (fails closed otherwise),
  2. assumes the agent's dedicated role using the developer's base profile, with a short
     duration, a SourceIdentity that names the developer, and session tags for the agent,
  3. caches the result until shortly before expiry. The SessionEnd hook deletes the cache.

The developer's own credentials are only used to call sts:AssumeRole; the agent never sees them.
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import balkanid_api as api  # noqa: E402
import guardrails  # noqa: E402
import kiro_config as kc  # noqa: E402
from kiro_hook import hook_api_defaults, registration_check  # noqa: E402

REFRESH_MARGIN_SECONDS = 120


def _parse_expiration(value: str) -> float:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def cached(agent: str) -> dict | None:
    path = kc.state_dir() / "credentials" / f"{agent}.json"
    try:
        with open(path, encoding="utf-8") as fh:
            creds = json.load(fh)
        if _parse_expiration(creds["Expiration"]) - time.time() > REFRESH_MARGIN_SECONDS:
            return creds
    except (OSError, KeyError, ValueError):
        pass
    return None


def save(agent: str, creds: dict) -> None:
    folder = kc.state_dir() / "credentials"
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = folder / f"{agent}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(creds, fh)


def session_identity() -> str:
    raw = api.env_optional("BALKANID_DEVELOPER_ID") or getpass.getuser()
    return re.sub(r"[^\w+=,.@-]", "-", raw)[:64] or "developer"


def assume_role(agent: str, role_arn: str, owner: str) -> dict:
    aws = api.env_optional("AWS_CLI") or shutil.which("aws")
    if not aws:
        raise SystemExit("aws CLI not found (set AWS_CLI)")
    duration = int(api.env_optional("AGENT_CREDENTIAL_SECONDS", "900"))
    who = session_identity()
    env = dict(os.environ)
    # Never resolve the agent's own profile recursively, and never hand the agent profile's env down.
    for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        env.pop(key, None)
    cmd = [
        aws, "sts", "assume-role",
        "--role-arn", role_arn,
        "--role-session-name", f"kiro-{agent}-{who}"[:64],
        "--source-identity", who,
        "--duration-seconds", str(duration),
        "--tags", f"Key=balkanid-agent,Value={agent}", "Key=balkanid-platform,Value=kiro",
        "--output", "json",
    ]
    base_profile = api.env_optional("BALKANID_DEVELOPER_PROFILE")
    if base_profile:
        cmd += ["--profile", base_profile]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
    if proc.returncode != 0:
        raise SystemExit(f"sts assume-role failed for {role_arn}: {proc.stderr.strip()[:500]}")
    c = json.loads(proc.stdout)["Credentials"]
    return {
        "Version": 1,
        "AccessKeyId": c["AccessKeyId"],
        "SecretAccessKey": c["SecretAccessKey"],
        "SessionToken": c["SessionToken"],
        "Expiration": c["Expiration"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="credential_process for a BalkanID-governed Kiro agent")
    parser.add_argument("--agent", required=True)
    args = parser.parse_args(argv)

    api.load_dotenv()
    hook_api_defaults()

    policy = guardrails.load_policy(kc.GUARDRAILS_FILE)
    ok, why, reg = registration_check(args.agent, policy)
    if not ok:
        print(f"[BalkanID] {why}", file=sys.stderr)
        return 1
    role_arn = reg.get("role_arn")
    if not role_arn:
        print(f"[BalkanID] no role_arn recorded for {args.agent}; run scripts/setup_agent_profile.py", file=sys.stderr)
        return 1

    creds = cached(args.agent)
    if not creds:
        creds = assume_role(args.agent, role_arn, reg.get("owner", ""))
        save(args.agent, creds)
    print(json.dumps(creds))
    return 0


if __name__ == "__main__":
    sys.exit(main())
