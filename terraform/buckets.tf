# Five buckets, one baseline (modules/hardened_bucket). Differences are deliberate and listed here.

# Receives S3 server access logs. SSE-S3 is required for log delivery (accepted: S3.17).
module "accesslogs_bucket" {
  source              = "./modules/hardened_bucket"
  name                = local.buckets.accesslogs
  kms_key_arn         = null
  access_log_bucket   = null # logging to itself would loop (accepted: S3.9)
  expire_current_days = 400  # over the 365-day AU-11 retention
  extra_policy_statements = [{
    Sid       = "S3ServerAccessLogsPolicy"
    Effect    = "Allow"
    Principal = { Service = "logging.s3.amazonaws.com" }
    Action    = "s3:PutObject"
    Resource  = "arn:aws:s3:::${local.buckets.accesslogs}/*"
    Condition = {
      ArnLike = { "aws:SourceArn" = [
        for k in ["data", "logs", "evidence", "web"] : "arn:aws:s3:::${local.buckets[k]}"
      ] }
      StringEquals = { "aws:SourceAccount" = local.account_id }
    }
  }]
}

# CloudTrail and Config delivery. Object Lock protects audit records (AU-9).
module "logs_bucket" {
  source              = "./modules/hardened_bucket"
  name                = local.buckets.logs
  kms_key_arn         = aws_kms_key.sas.arn
  access_log_bucket   = module.accesslogs_bucket.id
  expire_current_days = 400
  object_lock_days    = 365
  extra_policy_statements = [
    {
      Sid       = "CloudTrailAclCheck"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "s3:GetBucketAcl"
      Resource  = "arn:aws:s3:::${local.buckets.logs}"
      Condition = { StringEquals = { "aws:SourceArn" = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/sas-trail" } }
    },
    {
      Sid       = "CloudTrailWrite"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "arn:aws:s3:::${local.buckets.logs}/AWSLogs/${local.account_id}/*"
      Condition = { StringEquals = {
        "s3:x-amz-acl"  = "bucket-owner-full-control"
        "aws:SourceArn" = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/sas-trail"
      } }
    },
    {
      Sid       = "ConfigAclCheck"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "s3:GetBucketAcl"
      Resource  = "arn:aws:s3:::${local.buckets.logs}"
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    },
    {
      Sid       = "ConfigExistenceCheck"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "s3:ListBucket"
      Resource  = "arn:aws:s3:::${local.buckets.logs}"
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    },
    {
      Sid       = "ConfigDelivery"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "arn:aws:s3:::${local.buckets.logs}/config/AWSLogs/${local.account_id}/Config/*"
      Condition = { StringEquals = {
        "s3:x-amz-acl"      = "bucket-owner-full-control"
        "aws:SourceAccount" = local.account_id
      } }
    },
  ]
}

# Workload data (accepted: S3.15, relies on versioning and AWS Backup).
module "data_bucket" {
  source            = "./modules/hardened_bucket"
  name              = local.buckets.data
  kms_key_arn       = aws_kms_key.sas.arn
  access_log_bucket = module.accesslogs_bucket.id
  log_simple_prefix = true # logging was first enabled in the console
}

# Machine-readable evidence: raw findings, OSCAL results, POA&M, attestations, Terraform state.
module "evidence_bucket" {
  source            = "./modules/hardened_bucket"
  name              = local.buckets.evidence
  kms_key_arn       = aws_kms_key.sas.arn
  access_log_bucket = module.accesslogs_bucket.id
  noncurrent_days   = 400
  object_lock_days  = 365
}

# Static web chat page, readable only by the CloudFront distribution (accepted: S3.15).
module "web_bucket" {
  source            = "./modules/hardened_bucket"
  name              = local.buckets.web
  kms_key_arn       = aws_kms_key.sas.arn
  access_log_bucket = module.accesslogs_bucket.id
  extra_policy_statements = [{
    Sid       = "AllowCloudFrontOAC"
    Effect    = "Allow"
    Principal = { Service = "cloudfront.amazonaws.com" }
    Action    = "s3:GetObject"
    Resource  = "arn:aws:s3:::${local.buckets.web}/*"
    Condition = { StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.web.arn } }
  }]
}
