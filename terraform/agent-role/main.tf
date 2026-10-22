locals {
  role_path = "/balkanid-kiro-agents/"
  role_name = "kiro-agent-${var.agent_name}"

  # Children share their parent's boundary, so a spawned subagent can never hold more than its parent.
  boundary_owner  = var.parent_agent_name != "" ? var.parent_agent_name : var.agent_name
  boundary_name   = "kiro-agent-boundary-${local.boundary_owner}"
  create_boundary = var.parent_agent_name == ""
}

data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "DevelopersAssumeOnAgentsBehalf"
    effect  = "Allow"
    actions = ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"]

    principals {
      type        = "AWS"
      identifiers = var.developer_principal_arns
    }

    # Every session must say which developer it is for and which agent it serves.
    condition {
      test     = "StringLike"
      variable = "sts:SourceIdentity"
      values   = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/balkanid-agent"
      values   = [var.agent_name]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/balkanid-platform"
      values   = ["kiro"]
    }
  }
}

data "aws_iam_policy_document" "boundary" {
  statement {
    sid       = "UpperBound"
    effect    = "Allow"
    actions   = [for s in var.allowed_services : "${s}:*"]
    resources = ["*"]
  }

  # Guardrails that hold even if a client-side hook is bypassed or a broad grant slips through.
  statement {
    sid    = "NeverIdentityOrOrg"
    effect = "Deny"
    actions = [
      "iam:*",
      "organizations:*",
      "sso:*",
      "sso-admin:*",
      "identitystore:*",
      "sts:AssumeRole",
      "sts:GetSessionToken",
      "sts:GetFederationToken",
      "account:*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "NeverDestroyData"
    effect = "Deny"
    actions = [
      "s3:DeleteBucket",
      "s3:PutBucketPolicy",
      "s3:PutBucketAcl",
      "rds:DeleteDBInstance",
      "rds:DeleteDBCluster",
      "dynamodb:DeleteTable",
      "ec2:TerminateInstances",
      "kms:ScheduleKeyDeletion",
      "kms:DisableKey",
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "boundary" {
  count       = local.create_boundary ? 1 : 0
  name        = local.boundary_name
  path        = local.role_path
  description = "Permissions boundary for Kiro agent ${var.agent_name} and any subagents it spawns (managed by BalkanID reference)."
  policy      = data.aws_iam_policy_document.boundary.json
}

data "aws_iam_policy" "parent_boundary" {
  count = local.create_boundary ? 0 : 1
  name  = local.boundary_name
}

resource "aws_iam_role" "agent" {
  name                 = local.role_name
  path                 = local.role_path
  description          = "Dedicated identity for Kiro agent ${var.agent_name}. Approved in BalkanID; assumed per session with short-lived credentials."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = var.max_session_seconds
  permissions_boundary = local.create_boundary ? aws_iam_policy.boundary[0].arn : data.aws_iam_policy.parent_boundary[0].arn

  tags = {
    "balkanid-agent"    = var.agent_name
    "balkanid-platform" = "kiro"
    "balkanid-parent"   = var.parent_agent_name
  }
}

resource "aws_iam_role_policy_attachment" "agent" {
  for_each   = toset(var.agent_policy_arns)
  role       = aws_iam_role.agent.name
  policy_arn = each.value
}
