variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "secret_arns" {
  type        = list(string)
  default     = ["*"]
  description = "Secrets an approved agent may read during a BalkanID secrets-read grant. Narrow this."
}

variable "customer_data_bucket_arns" {
  type        = list(string)
  default     = []
  description = "S3 buckets holding customer data, readable only during a BalkanID customer-data grant."
}
