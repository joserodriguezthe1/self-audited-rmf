# One S3 bucket with the SAS baseline: public access blocked, versioned, encrypted,
# TLS-only, access-logged, lifecycle-managed, EventBridge notifications, optional Object Lock.
# Controls: AC-3, AU-9, AU-11, SC-8, SC-28, CM-6.

variable "name" { type = string }

variable "kms_key_arn" {
  description = "Customer managed key. Null means SSE-S3 (only for the access-log bucket)."
  type        = string
  default     = null
}

variable "extra_policy_statements" {
  description = "Statements added before the DenyInsecureTransport statement."
  type        = any
  default     = []
}

variable "access_log_bucket" {
  description = "Target bucket for S3 server access logs. Null disables (access-log bucket itself)."
  type        = string
  default     = null
}

variable "expire_current_days" {
  description = "Expire current object versions after N days. Null keeps them."
  type        = number
  default     = null
}

variable "log_simple_prefix" {
  description = "Set the simple-prefix log key format (what the S3 console writes)."
  type        = bool
  default     = false
}

variable "noncurrent_days" {
  type    = number
  default = 90
}

variable "object_lock_days" {
  description = "Default Object Lock retention in GOVERNANCE mode. Null means no Object Lock."
  type        = number
  default     = null
}

resource "aws_s3_bucket" "this" {
  #checkov:skip=CKV_AWS_144:Single-region system by design; versioning and AWS Backup provide recovery. Risk accepted (S3.7)
  bucket              = var.name
  object_lock_enabled = var.object_lock_days != null
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(var.extra_policy_statements, [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }])
  })
  depends_on = [aws_s3_bucket_public_access_block.this]
}

resource "aws_s3_bucket_logging" "this" {
  count         = var.access_log_bucket == null ? 0 : 1
  bucket        = aws_s3_bucket.this.id
  target_bucket = var.access_log_bucket
  target_prefix = "${trimsuffix(replace(var.name, "/-[0-9]{12}$/", ""), "-")}/"

  dynamic "target_object_key_format" {
    for_each = var.log_simple_prefix ? [1] : []
    content {
      simple_prefix {}
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    id     = "sas-lifecycle"
    status = "Enabled"
    filter {
      prefix = ""
    }
    dynamic "expiration" {
      for_each = var.expire_current_days == null ? [] : [var.expire_current_days]
      content {
        days = expiration.value
      }
    }
    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_notification" "this" {
  bucket      = aws_s3_bucket.this.id
  eventbridge = true
}

resource "aws_s3_bucket_object_lock_configuration" "this" {
  count  = var.object_lock_days == null ? 0 : 1
  bucket = aws_s3_bucket.this.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.object_lock_days
    }
  }
}

output "id" { value = aws_s3_bucket.this.id }
output "arn" { value = aws_s3_bucket.this.arn }
output "regional_domain_name" { value = aws_s3_bucket.this.bucket_regional_domain_name }
