#!/usr/bin/env python3
"""Shared BalkanID Public API helpers for the Kiro agent guardrails reference.

Standard library only. Mirrors the helpers in balkanid/agent-lifecycle-terraform-reference.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

CREATE_REQUEST = """
mutation CreateRequest($input: CreateRequestInput!) {
  createRequest(input: $input) {
    id
    success
    eventIds
    stepUpRequired
  }
}
"""

GET_REQUEST = """
query RequestStatus($filter: RequestFilterInput, $first: Int) {
  requests(filter: $filter, first: $first) {
    edges {
      node {
        id
        status
        requestApprovalStatus
        requestProvisioningStatus
        requestType
        metadata
      }
    }
  }
}
"""

GET_IDENTITY = """
query IdentityByHandle($filter: IdentityFilterInput, $first: Int) {
  identities(filter: $filter, first: $first) {
    edges {
      node {
        id
        sourceId
        handle
        sourceType
        fullName
      }
    }
  }
}
"""

APPROVED = {
    "approved",
    "completed",
    "provisioned",
    "partially_approved",
    "partially approved",
}
DENIED = {
    "denied",
    "rejected",
    "cancelled",
    "canceled",
    "failed",
}
PROVISIONED = {
    "provisioned",
    "completed",
    "success",
    "succeeded",
}

USER_AGENT = (
    "balkanid-agent-lifecycle-kiro-reference/1.0 "
    "(+https://github.com/balkanid/agent-lifecycle-kiro-reference)"
)


def ci_mode() -> bool:
    return os.environ.get("GITHUB_ACTIONS", "").lower() == "true" or os.environ.get("CI", "").lower() in (
        "1",
        "true",
        "yes",
    )


def log_stderr(message: str) -> None:
    print(message, file=sys.stderr)


def redact_identifier(value: str, visible: int = 4) -> str:
    value = value.strip()
    if not value:
        return "(empty)"
    if len(value) <= visible:
        return "***"
    return f"***{value[-visible:]}"


def load_dotenv() -> None:
    if os.environ.get("BALKANID_SKIP_DOTENV", "").lower() in ("1", "true", "yes"):
        return
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, ".env")
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if key:
                os.environ[key] = value


def http_error_message(code: int, detail: str, url: str = "") -> str:
    lower = detail.lower()
    if code == 403 and "<html" in lower:
        return (
            f"HTTP 403: request blocked or denied{url and f' ({url})' or ''}. "
            "Verify BALKANID_PUBLIC_API_URL, API key id/secret, and Public API access."
        )
    if "<html" in lower:
        return f"HTTP {code}: non-JSON response from public API (check BALKANID_PUBLIC_API_URL)"
    if code == 404:
        return f"HTTP 404 from public API: {detail.strip()}"
    if len(detail) > 800:
        detail = detail[:800] + "..."
    return f"HTTP {code} from public API: {detail}"


def env(name: str, default: str | None = None) -> str:
    val = os.environ.get(name, default)
    if val is None or val.strip() == "":
        raise SystemExit(f"missing required env {name}")
    return val.strip()


def env_optional(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def api_client_from_env() -> tuple[str, str, str]:
    return env("BALKANID_PUBLIC_API_URL"), env("API_KEY_ID"), env("API_KEY_SECRET")


def poll_settings() -> tuple[int, int]:
    poll_s = int(env_optional("POLL_SECONDS", "5"))
    timeout_raw = os.environ.get("POLL_TIMEOUT_SECONDS")
    if timeout_raw and timeout_raw.strip():
        timeout_s = int(timeout_raw)
    else:
        wait_min = env_optional("APPROVAL_WAIT_MINUTES")
        timeout_s = int(wait_min) * 60 if wait_min else 900
    return poll_s, timeout_s


TRANSIENT_HTTP_CODES = frozenset({429, 502, 503, 504, 520})


def gql(url: str, key_id: str, secret: str, query: str, variables: dict) -> dict:
    body = json.dumps({"query": query, "variables": variables}).encode()
    max_attempts = max(1, int(env_optional("GQL_MAX_RETRIES", "5")))
    backoff_s = float(env_optional("GQL_RETRY_BACKOFF_SECONDS", "2"))

    payload: dict | None = None
    last_err: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
                "X-Api-Key-Id": key_id,
                "X-Api-Key-Secret": secret,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=float(env_optional("GQL_TIMEOUT_SECONDS", "120"))) as resp:
                payload = json.loads(resp.read().decode())
            last_err = None
            break
        except urllib.error.HTTPError as err:
            detail = err.read().decode() if err.fp else ""
            if err.code in TRANSIENT_HTTP_CODES and attempt < max_attempts:
                log_stderr(
                    f"transient HTTP {err.code} from public API (attempt {attempt}/{max_attempts}); retrying"
                )
                time.sleep(backoff_s * attempt)
                last_err = err
                continue
            raise SystemExit(http_error_message(err.code, detail, url)) from err
        except urllib.error.URLError as err:
            if attempt < max_attempts:
                log_stderr(f"public API unreachable (attempt {attempt}/{max_attempts}); retrying")
                time.sleep(backoff_s * attempt)
                last_err = err
                continue
            raise SystemExit(f"public API request failed: {err}") from err

    if payload is None:
        raise SystemExit(f"public API request failed after {max_attempts} attempts: {last_err}")

    if payload.get("errors"):
        if ci_mode():
            raise SystemExit("GraphQL request failed (error details suppressed in CI logs)")
        raise SystemExit(json.dumps(payload["errors"], indent=2))
    data = payload.get("data")
    if not data:
        raise SystemExit(f"empty GraphQL data: {payload}")
    return data


def approval_outcome(status: str | None, approval: str | None) -> str | None:
    for raw in (status, approval):
        if not raw:
            continue
        n = raw.strip().lower().replace("-", "_").replace(" ", "_")
        if n in DENIED or "denied" in n or "reject" in n:
            return "denied"
        if n in APPROVED or (("approv" in n or n.endswith("approved")) and "pending" not in n and "await" not in n):
            return "approved"
    return None


def provisioning_outcome(provisioning: str | None) -> str | None:
    if not provisioning:
        return None
    n = provisioning.strip().lower().replace("-", "_").replace(" ", "_")
    if n in DENIED or "fail" in n:
        return "failed"
    if n in PROVISIONED or "provisioned" in n:
        return "provisioned"
    return None


def get_request_node(url: str, key_id: str, secret: str, request_id: str) -> dict | None:
    listed = gql(url, key_id, secret, GET_REQUEST, {"filter": {"id": {"_eq": request_id}}, "first": 1})
    edges = (listed.get("requests") or {}).get("edges") or []
    if not edges:
        return None
    return (edges[0] or {}).get("node")


def create_request_raw(url: str, key_id: str, secret: str, inp: dict) -> dict:
    """Call createRequest and return the raw result (id, success, stepUpRequired)."""
    return gql(url, key_id, secret, CREATE_REQUEST, {"input": inp})["createRequest"]


def create_request(url: str, key_id: str, secret: str, inp: dict) -> str:
    created = create_request_raw(url, key_id, secret, inp)
    if created.get("stepUpRequired"):
        raise SystemExit("step-up MFA required on createRequest; complete MFA and retry")
    if not created.get("success") or not created.get("id"):
        if ci_mode():
            raise SystemExit("createRequest failed (details suppressed in CI logs)")
        raise SystemExit(f"createRequest failed: {created}")
    return created["id"]


def request_state(url: str, key_id: str, secret: str, request_id: str) -> str:
    """One-shot status check: 'approved', 'denied', 'pending' or 'missing'. Never waits."""
    node = get_request_node(url, key_id, secret, request_id)
    if not node:
        return "missing"
    outcome = approval_outcome(node.get("status"), node.get("requestApprovalStatus"))
    return outcome or "pending"


def poll_request(
    url: str,
    key_id: str,
    secret: str,
    request_id: str,
    *,
    wait_provisioning: bool,
    poll_s: int,
    timeout_s: int,
    label: str,
) -> dict:
    log_stderr(f"waiting on {label} request_id={request_id}")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        node = get_request_node(url, key_id, secret, request_id)
        if node:
            status = node.get("status")
            approval = node.get("requestApprovalStatus")
            provisioning = node.get("requestProvisioningStatus")
            req_type = node.get("requestType")
            log_stderr(
                f"{label}: status={status!r} approval={approval!r} "
                f"provisioning={provisioning!r} requestType={req_type!r}"
            )
            approval_state = approval_outcome(status, approval)
            if approval_state == "denied":
                log_stderr(f"{label} denied: request_id={request_id}")
                raise SystemExit(1)
            if approval_state == "approved":
                if not wait_provisioning:
                    return node
                prov_state = provisioning_outcome(provisioning)
                if prov_state == "failed":
                    log_stderr(f"{label} provisioning failed: request_id={request_id}")
                    raise SystemExit(1)
                if prov_state == "provisioned":
                    return node
        time.sleep(poll_s)
    raise SystemExit(f"timed out after {timeout_s}s waiting on {label} request_id={request_id}")


def find_identity_id(
    url: str,
    key_id: str,
    secret: str,
    integration_id: str,
    role_name: str,
    *,
    poll_s: int = 5,
    timeout_s: int = 300,
) -> dict:
    """Wait until the AWS service role identity appears in the graph."""
    log_stderr(f"resolving identity for role={role_name!r} integration={integration_id!r}")
    deadline = time.time() + timeout_s
    filt = {
        "handle": {"_eq": role_name},
        "integration": {"id": {"_eq": integration_id}},
        "sourceType": {"_eq": "aws service role"},
    }
    while time.time() < deadline:
        listed = gql(url, key_id, secret, GET_IDENTITY, {"filter": filt, "first": 1})
        edges = (listed.get("identities") or {}).get("edges") or []
        if edges:
            node = (edges[0] or {}).get("node") or {}
            if node.get("id"):
                return node
        time.sleep(poll_s)
    raise SystemExit(f"timed out resolving identity for role {role_name!r}")


def role_arn_from_identity(role_name: str, identity: dict, aws_account_id: str) -> str:
    source_id = (identity.get("sourceId") or "").strip()
    if source_id.startswith("arn:aws:iam::"):
        return source_id
    return f"arn:aws:iam::{aws_account_id}:role/{role_name}"
