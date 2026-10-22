variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "agent_name" {
  type        = string
  description = "Kiro agent name, matching .kiro/agents/<name>.json."

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,40}$", var.agent_name))
    error_message = "agent_name must be lowercase letters, digits and hyphens."
  }
}

variable "developer_principal_arns" {
  type        = list(string)
  description = "IAM role ARNs (for example the developers' IAM Identity Center permission set roles) allowed to assume the agent role on the agent's behalf."
}

variable "agent_policy_arns" {
  type        = list(string)
  default     = ["arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"]
  description = "Policies attached to the agent role at creation. ViewOnlyAccess lists and describes resources but cannot read data or secrets; data access comes later as time-bound BalkanID grants."
}

variable "allowed_services" {
  type        = list(string)
  default     = ["ec2", "s3", "lambda", "logs", "cloudwatch", "cloudformation", "ecs", "eks", "dynamodb", "rds", "sqs", "sns", "tag", "secretsmanager", "ssm", "kms"]
  description = "Upper bound of AWS services the agent can ever use, enforced by the permissions boundary. Sensitive grants from BalkanID must also fall inside it."
}

variable "max_session_seconds" {
  type        = number
  default     = 3600
  description = "Maximum STS session length for the agent role. agent_credentials.py requests 15 minutes by default."
}

variable "parent_agent_name" {
  type        = string
  default     = ""
  description = "For a subagent: the parent agent. The child reuses the parent's permissions boundary so it can never exceed its parent."
}
