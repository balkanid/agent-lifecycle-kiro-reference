# Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Every tool call says the agent "is not registered" | No entry in `.kiro/balkanid/registrations.json` for this agent | `python3 scripts/register_agent.py --agent <name>` |
| "changed since BalkanID approved it" | The agent JSON differs from the approved fingerprint (any edit, including whitespace inside values) | Re-register. Reformatting keys or spacing does not change the fingerprint; changing values does. |
| "approval ... is unknown" | BalkanID unreachable and the cached status is older than `BALKANID_MAX_STALE_SECONDS` | Check `BALKANID_PUBLIC_API_URL` and the API key; the hook fails closed by design |
| AWS CLI says the credential process failed | Agent not approved, no `role_arn` recorded, or the developer cannot assume the role | Run `scripts/preflight.py`; run `setup_agent_profile.py`; confirm your developer role is in `developer_principal_arns` and may call `sts:AssumeRole`, `sts:TagSession` and `sts:SetSourceIdentity` |
| `AccessDenied` on assume-role mentioning tags or SourceIdentity | Trust policy conditions not met | Use `agent_credentials.py` (it sets both); the role refuses sessions without them |
| Sensitive call blocked with "no BalkanID service account" | `service_account_identity_id` missing | Run `trigger_sync.py`, then `setup_agent_profile.py` without `--skip-identity-lookup` |
| Sensitive call stays "Waiting on BalkanID request" | Approver has not acted, or step-up not completed | Approve in BalkanID; the next retry checks live status |
| Grant approved but AWS still denies | BalkanID has not finished attaching the grant policy, or the policy is outside the permissions boundary | Wait for provisioning; make sure the grant's service is in `allowed_services` |
| Hooks do not run at all | Kiro version uses different trigger names, or the agent is not the active one | Check `/agent` in Kiro, compare trigger names with your Kiro version's hook docs |
| `Agent approval` check fails on a fork PR | Fork PRs do not receive secrets | A maintainer re-runs it from a branch in the main repository |
