data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = var.region

  buckets = {
    logs       = "sas-logs-${local.account_id}"
    accesslogs = "sas-accesslogs-${local.account_id}"
    data       = "sas-data-${local.account_id}"
    evidence   = "sas-evidence-${local.account_id}"
    web        = "sas-web-${local.account_id}"
  }

  admin_arn = "arn:aws:iam::${local.account_id}:user/${var.admin_user_name}"

  # Log retention for every log group in the boundary (AU-11 organization-defined value).
  log_retention_days = 365

  lambda_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}
