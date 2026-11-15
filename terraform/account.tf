# Account-wide guardrails. Each block notes the Security Hub check and NIST control it satisfies.

# IA-5(1): organization-defined password parameters (also enforced as IAM.7 custom parameters).
resource "aws_iam_account_password_policy" "this" {
  #checkov:skip=CKV_AWS_9:No forced expiry per NIST SP 800-63B; change on evidence of compromise. SSP IA-5(1)
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 24
  # No forced expiry, per NIST SP 800-63B. Change on evidence of compromise.
}

# S3.1 / AC-3: no bucket in the account can be made public.
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# EC2.7 / SC-28: any future EBS volume is encrypted.
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

# SSM.7 / AC-3: SSM documents cannot be shared publicly.
resource "aws_ssm_service_setting" "doc_public_sharing" {
  setting_id    = "/ssm/documents/console/public-sharing-permission"
  setting_value = "Disable"
}

# SSM.6 / AU-2: SSM Automation output goes to CloudWatch Logs.
resource "aws_cloudwatch_log_group" "ssm_automation" {
  #checkov:skip=CKV_AWS_158:Log groups use CloudWatch default encryption; CMK encryption planned. POA&M-03
  name              = "/sas/ssm-automation"
  retention_in_days = local.log_retention_days
}

resource "aws_ssm_service_setting" "automation_log_destination" {
  setting_id    = "/ssm/automation/customer-script-log-destination"
  setting_value = "CloudWatch"
}

resource "aws_ssm_service_setting" "automation_log_group" {
  setting_id    = "/ssm/automation/customer-script-log-group-name"
  setting_value = aws_cloudwatch_log_group.ssm_automation.name
}

# Account.1 / IR-6: security contact on file.
resource "aws_account_alternate_contact" "security" {
  alternate_contact_type = "SECURITY"
  name                   = var.security_contact.name
  title                  = var.security_contact.title
  email_address          = var.security_contact.email
  phone_number           = var.security_contact.phone
}

# Cost guardrail. Credits excluded so the budget shows real usage.
resource "aws_budgets_budget" "monthly" {
  name         = var.discovered.budget_name
  budget_type  = "COST"
  limit_amount = format("%.1f", var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_types {
    include_credit = false
    include_refund = false
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 40
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
  }
}
