#!/usr/bin/env python3
"""Request BalkanID approval for the agent's own IAM role (CREATE_SERVICE_ACCOUNT).

This is the step that stops a Kiro agent from inheriting the developer's permissions: the
agent gets a dedicated role, scoped to the policy approved here, that developers can only
assume on the agent's behalf through scripts/agent_credentials.py. Terraform
(terraform/agent-role) creates the role after approval; this gate does not provision.

  python3 scripts/service_account_gate.py --agent infra-helper

Exit 0 only on approval.
"""

from __future__ import annotations

import argparse
import json
import sys

import balkanid_api as api
import kiro_config as kc

ROLE_PATH_PREFIX = "/balkanid-kiro-agents/"


def role_name_for(agent: str) -> str:
    return f"kiro-agent-{agent}"


def build_input(agent: str, owner: str, integration_id: str) -> dict:
    role_name = role_name_for(agent)
    scim_payload: dict = {
        "aws_service_role_name": role_name,
        "description": api.env_optional(
            "SERVICE_ACCOUNT_ROLE_DESCRIPTION",
            f"Dedicated identity for Kiro agent {agent}; assumed per session with short-lived credentials",
        ),
    }
    service_names = api.env_optional("SERVICE_ACCOUNT_AWS_SERVICE_NAMES")
    if service_names:
        scim_payload["aws_service_names"] = service_names
    policy_name = api.env_optional("SERVICE_ACCOUNT_POLICY_NAME")
    if policy_name:
        grant: dict = {"type": "policy", "source_name": policy_name}
        policy_id = api.env_optional("SERVICE_ACCOUNT_POLICY_ID")
        if policy_id:
            grant["source_id"] = policy_id
        scim_payload["grants"] = [grant]
        scim_payload["revokes"] = []

    inp: dict = {
        "requestType": "CREATE_SERVICE_ACCOUNT",
        "employeeEmail": owner,
        "reason": f"Dedicated scoped identity for Kiro agent {agent} instead of developer credentials",
        "payload": {
            "entity": {
                "provisioningOption": "app",
                "integrationId": integration_id,
                "sourceType": "aws service role",
                "identityType": "service account",
                "name": role_name,
                "scimPayload": scim_payload,
            }
        },
    }
    expiration = api.env_optional("SERVICE_ACCOUNT_EXPIRATION_DATE")
    if expiration:
        inp["expirationDate"] = expiration
    return inp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Approve a dedicated IAM role for a Kiro agent")
    parser.add_argument("--agent", required=True)
    args = parser.parse_args(argv)

    api.load_dotenv()
    kc.load_agent(args.agent)  # must exist
    owner = api.env("BALKANID_AGENT_OWNER_EMAIL")
    integration_id = api.env("INTEGRATION_ID")
    url, key_id, secret = api.api_client_from_env()
    poll_s, timeout_s = api.poll_settings()

    role_name = role_name_for(args.agent)
    api.log_stderr(f"requesting service account {role_name!r} for kiro/{args.agent}")
    request_id = api.create_request(url, key_id, secret, build_input(args.agent, owner, integration_id))
    api.log_stderr(f"request_id={request_id}; waiting for approval (fail closed on deny/timeout)")

    try:
        api.poll_request(
            url, key_id, secret, request_id,
            wait_provisioning=False, poll_s=poll_s, timeout_s=timeout_s, label="CREATE_SERVICE_ACCOUNT",
        )
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        print(json.dumps({"request_id": request_id, "status": "failed"}))
        return code or 1

    kc.update_registration(args.agent, service_account_request_id=request_id, role_name=role_name)
    out = {"request_id": request_id, "status": "approved", "role_name": role_name}
    account = api.env_optional("AWS_ACCOUNT_ID")
    if account:
        out["expected_role_arn"] = f"arn:aws:iam::{account}:role{ROLE_PATH_PREFIX}{role_name}"
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
