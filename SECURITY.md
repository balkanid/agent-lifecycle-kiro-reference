# Security

## Reporting security issues

Per the [BalkanID Trust Center](https://trustcenter.balkan.id/), report security questions, incidents, or concerns to **[security@balkan.id](mailto:security@balkan.id)**.

For findings in this reference repository (sample code, docs, or workflows):

1. Email **security@balkan.id** with a description, reproduction steps, and impact.
2. Do **not** open a public GitHub issue for credential leaks, tenant-specific data, or exploitable vulnerabilities.
3. Do **not** test against BalkanID production systems or customer tenants without authorization.

For non-security bugs or documentation fixes, use GitHub Issues.

## Protecting credentials

| Location | Guidance |
|---|---|
| Git | Never commit `.env`, `*.tfvars` or Terraform state. `.kiro/balkanid/registrations.json` holds request ids and hashes only, and is meant to be committed. |
| Developer machine | Agent credentials are cached in `~/.cache/balkanid-kiro/credentials` with mode 0600 and deleted by the SessionEnd hook. They expire after `AGENT_CREDENTIAL_SECONDS` regardless. |
| Audit log | `~/.cache/balkanid-kiro/audit.jsonl` stores a SHA-256 of each tool input, never the input itself. |
| GitHub Actions | Store the BalkanID URL and API key as environment **secrets** on `agent-approval`. Fork pull requests do not receive them and fail closed. |
| AWS | Scope the Terraform principal to [`aws/kiro-agent-provisioner-iam-policy.json`](aws/kiro-agent-provisioner-iam-policy.json), which can only manage roles and policies under `/balkanid-kiro-agents/`. |

## What the hooks can and cannot guarantee

Kiro hooks run on the developer's machine. They stop a compromised or misdirected agent; they do not stop a developer who edits or removes them. The controls that hold regardless are server side: the agent's IAM role, its permissions boundary, short STS lifetimes, and BalkanID approvals. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#threat-model).
