#!/usr/bin/env python3
"""Connect an approved Kiro agent to its BalkanID-governed AWS identity.

Run after terraform/agent-role has created the role and BalkanID has synced it:

  python3 scripts/setup_agent_profile.py --agent infra-helper \
      --role-arn arn:aws:iam::123456789012:role/balkanid-kiro-agents/kiro-agent-infra-helper

It records the role ARN and the BalkanID service account id in .kiro/balkanid/registrations.json
(the hook needs the id to request time-bound grants for sensitive operations), and prints the
~/.aws/config profile block. Pass --write-aws-config to append the block yourself in one step.
"""

from __future__ import annotations

import argparse
import configparser
import os
import sys
from pathlib import Path

import balkanid_api as api
import kiro_config as kc
from service_account_gate import role_name_for


def profile_block(agent: str, region: str) -> str:
    script = (kc.ROOT / "scripts" / "agent_credentials.py").resolve()
    return (
        f"[profile {kc.agent_profile(agent)}]\n"
        f"credential_process = python3 {script} --agent {agent}\n"
        f"region = {region}\n"
    )


def write_aws_config(agent: str, block: str) -> str:
    path = Path(os.environ.get("AWS_CONFIG_FILE") or os.path.expanduser("~/.aws/config"))
    parser = configparser.RawConfigParser()
    if path.is_file():
        parser.read(path)
    section = f"profile {kc.agent_profile(agent)}"
    if parser.has_section(section):
        return f"{path} already has [{section}]; left unchanged"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n" + block)
    return f"appended [{section}] to {path}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Link a Kiro agent to its AWS identity")
    parser.add_argument("--agent", required=True)
    parser.add_argument("--role-arn", required=True)
    parser.add_argument("--skip-identity-lookup", action="store_true", help="do not resolve the BalkanID identity id")
    parser.add_argument("--write-aws-config", action="store_true")
    args = parser.parse_args(argv)

    api.load_dotenv()
    kc.load_agent(args.agent)
    integration_id = api.env_optional("INTEGRATION_ID")
    fields: dict = {"role_arn": args.role_arn, "integration_id": integration_id or None}

    if not args.skip_identity_lookup:
        if not integration_id:
            raise SystemExit("INTEGRATION_ID is required to resolve the agent's BalkanID service account")
        url, key_id, secret = api.api_client_from_env()
        role_name = args.role_arn.rsplit("/", 1)[-1] or role_name_for(args.agent)
        identity = api.find_identity_id(
            url, key_id, secret, integration_id, role_name,
            timeout_s=int(api.env_optional("IDENTITY_LOOKUP_TIMEOUT_SECONDS", "300")),
        )
        fields["service_account_identity_id"] = identity["id"]
        api.log_stderr(f"resolved BalkanID service account id for {role_name!r}")

    kc.update_registration(args.agent, **fields)
    block = profile_block(args.agent, api.env_optional("AWS_REGION", "us-east-1"))
    if args.write_aws_config:
        api.log_stderr(write_aws_config(args.agent, block))
    else:
        print(block)
        api.log_stderr("add the block above to ~/.aws/config, or re-run with --write-aws-config")
    return 0


if __name__ == "__main__":
    sys.exit(main())
