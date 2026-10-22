# Account-wide policies that BalkanID attaches to an agent's role for the length of an approved,
# time-bound grant. Names must match the "grant" entries in .kiro/balkanid/guardrails.json.
# Create once per account. Each stays inside the agent permissions boundary.

data "aws_iam_policy_document" "secrets_read" {
  statement {
    sid       = "ReadApprovedSecrets"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = var.secret_arns
  }
  statement {
    sid       = "DecryptViaSecretsAndSsmOnly"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["secretsmanager.*.amazonaws.com", "ssm.*.amazonaws.com"]
    }
  }
  statement {
    sid       = "ReadSecureParameters"
    actions   = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "production_read_only" {
  statement {
    sid       = "ReadProductionResources"
    actions   = ["ec2:Describe*", "rds:Describe*", "ecs:Describe*", "ecs:List*", "lambda:Get*", "lambda:List*", "logs:Get*", "logs:FilterLogEvents", "cloudwatch:Get*"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "customer_data_read" {
  count = length(var.customer_data_bucket_arns) > 0 ? 1 : 0
  statement {
    sid       = "ReadCustomerDataBuckets"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = concat(var.customer_data_bucket_arns, [for b in var.customer_data_bucket_arns : "${b}/*"])
  }
}

resource "aws_iam_policy" "secrets_read" {
  name        = "BalkanIDAgentSecretsRead"
  path        = "/balkanid-kiro-agents/"
  description = "Time-bound BalkanID grant: read approved secrets."
  policy      = data.aws_iam_policy_document.secrets_read.json
}

resource "aws_iam_policy" "production_read_only" {
  name        = "BalkanIDAgentProductionReadOnly"
  path        = "/balkanid-kiro-agents/"
  description = "Time-bound BalkanID grant: read-only access to production resources."
  policy      = data.aws_iam_policy_document.production_read_only.json
}

resource "aws_iam_policy" "customer_data_read" {
  count       = length(var.customer_data_bucket_arns) > 0 ? 1 : 0
  name        = "BalkanIDAgentCustomerDataRead"
  path        = "/balkanid-kiro-agents/"
  description = "Time-bound BalkanID grant: read customer data buckets."
  policy      = data.aws_iam_policy_document.customer_data_read[0].json
}
