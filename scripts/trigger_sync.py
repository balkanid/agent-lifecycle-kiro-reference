#!/usr/bin/env python3
"""Trigger a BalkanID integration sync via Public API syncIntegration.

Run after terraform/agent-role creates the agent role so BalkanID discovers it.
Requires INTEGRATION_ID (or BALKANID_INTEGRATION_ID) and the same API key env as the gates.
"""

from __future__ import annotations

import json
import sys

from balkanid_api import (
    api_client_from_env,
    ci_mode,
    env_optional,
    gql,
    load_dotenv,
    log_stderr,
    redact_identifier,
)

SYNC = """
mutation SyncIntegration($input: SyncIntegrationInput!) {
  syncIntegration(input: $input) {
    success
    correlationId
  }
}
"""


def integration_id() -> str:
    for name in ("INTEGRATION_ID", "BALKANID_INTEGRATION_ID"):
        val = env_optional(name)
        if val:
            return val
    raise SystemExit("missing INTEGRATION_ID (or BALKANID_INTEGRATION_ID); required to trigger sync")


def main() -> int:
    load_dotenv()
    trigger = env_optional("TRIGGER_INTEGRATION_SYNC", "true").lower()
    if trigger in ("0", "false", "no", "off"):
        log_stderr("TRIGGER_INTEGRATION_SYNC disabled; skipping sync")
        return 0

    url, key_id, secret = api_client_from_env()
    iid = integration_id()

    if ci_mode():
        log_stderr("triggering integration sync")
    else:
        log_stderr(f"triggering sync integration_id={iid!r}")

    result = gql(url, key_id, secret, SYNC, {"input": {"integrationId": iid}})
    out = result.get("syncIntegration") or {}
    if not out.get("success"):
        if ci_mode():
            raise SystemExit("syncIntegration failed (details suppressed in CI logs)")
        raise SystemExit(f"syncIntegration failed: {out}")

    correlation_id = out.get("correlationId") or ""
    print(
        json.dumps(
            {
                "integration_id": redact_identifier(iid) if ci_mode() else iid,
                "correlation_id": correlation_id,
                "status": "accepted",
            }
        )
    )
    log_stderr(f"sync accepted correlation_id={correlation_id!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
