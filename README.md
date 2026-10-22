# BalkanID guardrails for Kiro agents: reference

Reference implementation for governing [Kiro](https://kiro.dev) custom agents with **BalkanID**, so that an agent a developer creates does **not** inherit that developer's permissions.

Companion to [agent-lifecycle-terraform-reference](https://github.com/balkanid/agent-lifecycle-terraform-reference) (AWS Bedrock) and [agent-lifecycle-microsoft-copilot-reference](https://github.com/balkanid/agent-lifecycle-microsoft-copilot-reference). Same Public API, same fail-closed approval gate; here the provisioning plane is a Kiro agent config and a dedicated IAM role.

## The control gap

Kiro agents run with the developer's environment. Any AWS CLI call or AWS MCP server an agent uses picks up the developer's credentials, so a misprompted or compromised agent acts with developer-level privilege: no owner, no approval, no expiry, and nothing in CloudTrail to tell the agent apart from the person.

## What this demonstrates

| Control | How |
|---|---|
| **Govern the agent before it runs** | `register_agent.py` raises a BalkanID `AGENT_ACCESS` request for the exact agent config (SHA-256 fingerprint), naming a human owner. Tools stay blocked until it is approved, and again whenever the config changes. |
| **Its own identity, not the developer's** | Each agent gets a dedicated IAM role (`CREATE_SERVICE_ACCOUNT` approval, then Terraform) with a permissions boundary. A `credential_process` profile issues 15-minute credentials for that role only, tagged with the agent and stamped with the developer as SourceIdentity. |
| **Auto-deny guardrails** | A Kiro `PreToolUse` hook blocks credential theft, IAM and org changes, destructive commands, guardrail tampering, and any AWS CLI call not made as the agent. |
| **Step-up approval for sensitive access** | Secrets, production and customer data trigger a time-bound `SERVICE_ACCOUNT_ASSIGNMENT` grant on the agent's own identity. Mark those grants sensitive in BalkanID and approvers must complete step-up MFA. |
| **Subagents stay inside their parent** | Children are registered with `--parent`, share the parent's permissions boundary, and are the only agents the parent may spawn. |
| **Ephemeral by default** | Credentials expire in 15 minutes and are deleted on `SessionEnd`; grants expire with their approved duration. |
| **Review before merge** | The `Agent approval` workflow is a required PR check: a changed agent merges only with a live, matching approval. |

```
Developer writes .kiro/agents/infra-helper.json
  -> register_agent.py      AGENT_ACCESS (owner, purpose, config fingerprint)   -> approved
  -> service_account_gate   CREATE_SERVICE_ACCOUNT (agent role)                   -> approved
  -> terraform/agent-role   role + permissions boundary  -> trigger_sync.py
  -> setup_agent_profile    [profile balkanid-agent-infra-helper] credential_process
Kiro session
  SessionStart  -> approval still live? brief the agent on its identity
  PreToolUse    -> deny rules | own-identity rule | sensitive -> time-bound grant + step-up
  SessionEnd    -> delete cached credentials
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for components, control flows and the threat model.

## Repository layout

```
.kiro/
  agents/infra-helper.json        Example governed agent (hooks, permissions, AWS MCP on agent profile)
  balkanid/guardrails.json        Deny and sensitive rules evaluated on every tool call
  balkanid/registrations.json     Approved request ids and config fingerprints (commit this)
scripts/
  register_agent.py               AGENT_ACCESS gate; --lint-only and --verify for CI
  service_account_gate.py         CREATE_SERVICE_ACCOUNT gate for the agent role
  setup_agent_profile.py          Link role + BalkanID service account, write AWS profile
  agent_credentials.py            AWS credential_process: approval check + 15 min AssumeRole
  kiro_hook.py                    SessionStart / PreToolUse / SessionEnd hook
  guardrails.py                   Pure rule evaluation
  kiro_config.py                  Config loading, fingerprint, lint, registrations
  balkanid_api.py                 Shared Public API helpers (stdlib only)
  trigger_sync.py, preflight.py, verify_imports.py
terraform/
  agent-role/                     Agent IAM role, trust policy, permissions boundary
  grant-policies/                 Policies BalkanID attaches for approved grant windows
aws/kiro-agent-provisioner-iam-policy.json
.github/workflows/ci.yml, agent-approval.yml
tests/                            Unit tests against a mock BalkanID API
```

## Prerequisites

**BalkanID**

- Agents (Early Access) and agent access requests enabled on your tenant.
- An AWS integration for the account the agent works in (its id is `INTEGRATION_ID`).
- An employee API key that can call `createRequest`, `requests`, `identities` and `syncIntegration` ([Public API](https://docs.balkan.id/)).
- Request policies for `AGENT_ACCESS`, `CREATE_SERVICE_ACCOUNT` and `SERVICE_ACCOUNT_ASSIGNMENT` (auto-approve, route or deny).
- For step-up: [Step-Up MFA](https://docs.balkan.id/lifecycle-management/step-up-mfa-for-sensitive-requests) enabled, and a custom insight with **Is Sensitive** covering the grant policies.

**Local**

- Kiro (IDE or CLI) with custom agents and hooks.
- Python 3.11+ (standard library only), AWS CLI v2, Terraform 1.5+.
- A developer role that may call `sts:AssumeRole` on `arn:aws:iam::<account>:role/balkanid-kiro-agents/*`.

## Quick start

```bash
cp env.example .env              # BalkanID URL, API key, owner email, integration id, AWS account
python3 scripts/preflight.py --agent infra-helper
```

1. **Register the agent** (waits for approval; Ctrl+C is safe, the request stays open):

   ```bash
   python3 scripts/register_agent.py --agent infra-helper
   ```

2. **Approve its identity and create the role:**

   ```bash
   python3 scripts/service_account_gate.py --agent infra-helper
   cd terraform/grant-policies && terraform init && terraform apply      # once per account
   cd ../agent-role && terraform init && terraform apply \
     -var="aws_account_id=123456789012" -var="agent_name=infra-helper" \
     -var='developer_principal_arns=["arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Developer_abc123"]'
   cd ../.. && python3 scripts/trigger_sync.py
   ```

3. **Link the profile:**

   ```bash
   python3 scripts/setup_agent_profile.py --agent infra-helper \
     --role-arn "$(terraform -chdir=terraform/agent-role output -raw role_arn)" --write-aws-config
   ```

4. **Commit** `.kiro/agents/infra-helper.json` and `.kiro/balkanid/registrations.json`, open a PR, and let `Agent approval` verify it.

5. **Use the agent in Kiro.** Try these to see each control:

   | Ask the agent to | Result |
   |---|---|
   | `aws s3 ls` | Blocked: must use `--profile balkanid-agent-infra-helper` |
   | `aws s3 ls --profile balkanid-agent-infra-helper` | Allowed, as the agent role, for 15 minutes |
   | `cat ~/.aws/credentials` | Blocked: developer credentials |
   | `aws iam attach-role-policy ...` | Blocked: privilege escalation (and denied by the boundary) |
   | `aws secretsmanager get-secret-value ...` | Held: BalkanID request raised; approver completes step-up; retry succeeds inside the window |
   | Edit `.kiro/agents/infra-helper.json` | Blocked: guardrail tampering |

## Adding another agent

Copy `.kiro/agents/infra-helper.json`, rename it, and replace `infra-helper` in the three hook commands and the AWS profile name. `register_agent.py --lint-only` tells you anything missing. For a subagent, add `--parent <name>` when registering and `-var="parent_agent_name=<name>"` when applying `terraform/agent-role`.

## BalkanID Public API usage

| API | Used by |
|---|---|
| `createRequest` `AGENT_ACCESS` | `register_agent.py`: owner, purpose, intended role ARN, config fingerprint metadata |
| `createRequest` `CREATE_SERVICE_ACCOUNT` | `service_account_gate.py`: the agent's dedicated role |
| `createRequest` `SERVICE_ACCOUNT_ASSIGNMENT` | `kiro_hook.py`: time-bound grant for a sensitive operation |
| `requests` | Status polling and live re-checks (cached for `status_cache_seconds`) |
| `identities` | `setup_agent_profile.py`: resolve the agent role's BalkanID service account id |
| `syncIntegration` | `trigger_sync.py`: discover the new role |

## Testing

```bash
python3 -m unittest discover -s tests -v
```

The tests run every script against an in-process mock of the BalkanID API and a fake AWS CLI: registration, fail-closed paths, config drift, every rule family, the grant lifecycle (pending, approved, denied, step-up), API outage behaviour and credential issuance.

## Production considerations

This repository is a **reference**, not a hardened product. Before adopting it:

- Pin Kiro's hook trigger names and tool ids to the version you run and re-test; Kiro's agent schema is evolving.
- Treat `guardrails.json` patterns as a guardrail, not a sandbox. The IAM role and boundary are the enforcement.
- Use remote Terraform state and your own approval policies in BalkanID.
- Distribute the hooks through a managed template so new agents start governed.

## Out of scope

- Network-level egress control for agents.
- Kiro features beyond custom agents and hooks (for example, specs).
- Non-AWS clouds (the pattern is the same; the credential step differs).

## Security

See [SECURITY.md](SECURITY.md).
