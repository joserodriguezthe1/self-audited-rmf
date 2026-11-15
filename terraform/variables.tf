# Values you set: terraform.tfvars (gitignored). See terraform.tfvars.example.
# Values read from the live account: discovered.auto.tfvars.json, written by scripts/discover.py.

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "admin_user_name" {
  description = "IAM user that administers the system (key administrator in the KMS key policy)."
  type        = string
}

variable "alert_email" {
  description = "Email for budget alerts."
  type        = string
}

variable "security_contact" {
  description = "Account security contact (Account.1 / IR-6)."
  type = object({
    name  = string
    title = string
    email = string
    phone = string
  })
}

variable "chat_model_id" {
  description = "Bedrock inference profile ID for the compliance chat."
  type        = string
  default     = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
}

variable "monthly_budget_usd" {
  type    = number
  default = 25
}

# ---------------- discovered from the live account ----------------

variable "discovered" {
  description = "As-built identifiers and settings, written by scripts/discover.py. Not hand-edited."
  type = object({
    config_recorder_name          = string
    config_delivery_channel_name  = string
    cloudtrail_cwl_role_name      = string
    cloudtrail_cwl_role_path      = string
    cloudtrail_cwl_policy_name    = string
    cloudtrail_cwl_policy_path    = string
    records_api_runtime           = string
    records_api_memory            = number
    records_api_access_log_format = string
    records_api_permission_sid    = string
    cloudfront_origin_id          = string
    cloudfront_oac_name           = string
    cloudfront_web_acl_id         = string
    budget_name                   = string
    records_route_integrations    = map(string)
    automation_rule_orders        = map(number)
  })
}

variable "risk_owner" {
  description = "Name recorded on risk acceptance notes in Security Hub."
  type        = string
}
