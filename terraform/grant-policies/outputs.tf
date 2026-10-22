output "grant_policy_arns" {
  value = compact([
    aws_iam_policy.secrets_read.arn,
    aws_iam_policy.production_read_only.arn,
    try(aws_iam_policy.customer_data_read[0].arn, ""),
  ])
}
