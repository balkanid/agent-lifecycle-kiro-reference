output "role_arn" {
  value       = aws_iam_role.agent.arn
  description = "Pass to scripts/setup_agent_profile.py --role-arn."
}

output "role_name" {
  value = aws_iam_role.agent.name
}

output "permissions_boundary_arn" {
  value = aws_iam_role.agent.permissions_boundary
}
