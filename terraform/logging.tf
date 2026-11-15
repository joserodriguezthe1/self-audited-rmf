# Audit logging: CloudTrail to the locked log bucket and to CloudWatch Logs (AU-2, AU-3, AU-6, AU-9, AU-12).

resource "aws_cloudwatch_log_group" "cloudtrail" {
  #checkov:skip=CKV_AWS_158:Log groups use CloudWatch default encryption; CMK encryption planned. POA&M-03
  name              = "/sas/cloudtrail"
  retention_in_days = local.log_retention_days
}

resource "aws_iam_role" "cloudtrail_cwl" {
  name        = var.discovered.cloudtrail_cwl_role_name
  path        = var.discovered.cloudtrail_cwl_role_path
  description = "Role for config CloudWatchLogs for trail sas-trail"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = {
        "aws:SourceAccount" = local.account_id
        "aws:SourceArn"     = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/sas-trail"
      } }
    }]
  })
}

resource "aws_iam_policy" "cloudtrail_cwl" {
  name        = var.discovered.cloudtrail_cwl_policy_name
  path        = var.discovered.cloudtrail_cwl_policy_path
  description = "Policy for config CloudWatchLogs for trail sas-trail, created by CloudTrail console"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AWSCloudTrailCreateLogStream2014110"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream"]
        Resource = ["arn:aws:logs:${local.region}:${local.account_id}:log-group:/sas/cloudtrail:log-stream:${local.account_id}_CloudTrail_${local.region}*"]
      },
      {
        Sid      = "AWSCloudTrailPutLogEvents20141101"
        Effect   = "Allow"
        Action   = ["logs:PutLogEvents"]
        Resource = ["arn:aws:logs:${local.region}:${local.account_id}:log-group:/sas/cloudtrail:log-stream:${local.account_id}_CloudTrail_${local.region}*"]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudtrail_cwl" {
  role       = aws_iam_role.cloudtrail_cwl.name
  policy_arn = aws_iam_policy.cloudtrail_cwl.arn
}

resource "aws_cloudtrail" "sas" {
  #checkov:skip=CKV_AWS_252:Trail alerts handled through CloudWatch Logs; SNS delivery notifications not required
  name                          = "sas-trail"
  s3_bucket_name                = module.logs_bucket.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true
  kms_key_id                    = aws_kms_key.sas.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cwl.arn

  advanced_event_selector {
    name = "Management events selector"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }
}
