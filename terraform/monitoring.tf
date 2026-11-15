# Continuous monitoring (CA-7): AWS Config records every resource; Security Hub CSPM runs the
# NIST SP 800-53 Rev 5 standard on top of it.

resource "aws_config_configuration_recorder" "this" {
  name     = var.discovered.config_recorder_name
  role_arn = "arn:aws:iam::${local.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

resource "aws_config_delivery_channel" "this" {
  name           = var.discovered.config_delivery_channel_name
  s3_bucket_name = module.logs_bucket.id
  s3_key_prefix  = "config" # objects encrypted by the bucket default (SSE-KMS, sas-key)
  depends_on     = [aws_config_configuration_recorder.this]
}

resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.this]
}

resource "aws_securityhub_account" "this" {
  enable_default_standards  = false
  control_finding_generator = "SECURITY_CONTROL"
  auto_enable_controls      = true
}

resource "aws_securityhub_standards_subscription" "nist_800_53" {
  standards_arn = "arn:aws:securityhub:${local.region}::standards/nist-800-53/v/5.0.0"
  depends_on    = [aws_securityhub_account.this]
}

# ---- Risk acceptances (RA-7). Each rule suppresses matching findings and attaches the
# justification as a note. The evidence pipeline reports these controls as risk-accepted
# and the chat quotes the note. Register: docs/risk-register.md ----

locals {
  risk_acceptances = {
    "sas-accept-account-2" = {
      control = "Account.2", resource = null
      note    = "Single-account system by design. Joining AWS Organizations ends Free Tier credits. Compensating: budget alerts, CloudTrail, Config. Review 2027-05-14."
    }
    "sas-accept-macie-1" = {
      control = "Macie.1", resource = null
      note    = "System stores only synthetic test records, no PII or CUI. Re-evaluate before any real data is introduced."
    }
    "sas-accept-s3-7" = {
      control = "S3.7", resource = null
      note    = "Single-region system by design. Versioning and AWS Backup provide recovery. Cross-region replication not required for this system."
    }
    "sas-accept-s3-20" = {
      control = "S3.20", resource = null
      note    = "MFA delete requires root credentials on the CLI, and routine root use is prohibited. Versioning and Object Lock compensate."
    }
    "sas-accept-lambda-3" = {
      control = "Lambda.3", resource = null
      note    = "Functions call only AWS APIs over TLS and reach no private network resources. A VPC would add NAT cost with no security gain."
    }
    "sas-accept-s3-15-data" = {
      control = "S3.15", resource = "arn:aws:s3:::${local.buckets.data}"
      note    = "Object Lock applied where integrity is required: log and evidence buckets (AU-9). Data bucket relies on versioning and AWS Backup."
    }
    "sas-accept-s3-15-accesslogs" = {
      control = "S3.15", resource = "arn:aws:s3:::${local.buckets.accesslogs}"
      note    = "Object Lock applied where integrity is required: log and evidence buckets (AU-9). Access-log bucket relies on versioning."
    }
    "sas-accept-s3-17-accesslogs" = {
      control = "S3.17", resource = "arn:aws:s3:::${local.buckets.accesslogs}"
      note    = "S3 server access log delivery requires SSE-S3 on the destination bucket. Documented exception."
    }
    "sas-accept-s3-9-accesslogs" = {
      control = "S3.9", resource = "arn:aws:s3:::${local.buckets.accesslogs}"
      note    = "Logging the access-log bucket to itself would create a delivery loop. Bucket activity is captured by CloudTrail."
    }
    "sas-accept-s3-15-web" = {
      control = "S3.15", resource = "arn:aws:s3:::${local.buckets.web}"
      note    = "Static site assets only, rebuilt from Git on every deploy. Versioning covers recovery."
    }
  }
}

resource "aws_securityhub_automation_rule" "risk_acceptance" {
  for_each    = local.risk_acceptances
  rule_name   = each.key
  rule_order  = lookup(var.discovered.automation_rule_orders, each.key, 50)
  rule_status = "ENABLED"
  description = "SAS risk acceptance: ${each.value.control}"

  criteria {
    compliance_security_control_id {
      comparison = "EQUALS"
      value      = each.value.control
    }
    dynamic "resource_id" {
      for_each = each.value.resource == null ? [] : [each.value.resource]
      content {
        comparison = "PREFIX"
        value      = resource_id.value
      }
    }
  }

  actions {
    type = "FINDING_FIELDS_UPDATE"
    finding_fields_update {
      workflow {
        status = "SUPPRESSED"
      }
      note {
        text       = each.value.note
        updated_by = var.risk_owner
      }
    }
  }

  depends_on = [aws_securityhub_account.this]
}
