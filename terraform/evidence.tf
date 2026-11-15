# Evidence plane: daily pipeline turns Security Hub findings into hashed raw evidence,
# OSCAL assessment results, an OSCAL POA&M, and one status row per control.

resource "aws_dynamodb_table" "control_status" {
  name                        = "control_status"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "control_id"
  deletion_protection_enabled = true

  attribute {
    name = "control_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.sas.arn
  }

  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_cloudwatch_log_group" "pipeline" {
  #checkov:skip=CKV_AWS_158:Log groups use CloudWatch default encryption; CMK encryption planned. POA&M-03
  name              = "/aws/lambda/sas-evidence-pipeline"
  retention_in_days = local.log_retention_days
}

resource "aws_iam_policy" "pipeline" {
  #checkov:skip=CKV_AWS_355:securityhub:GetFindings and X-Ray writes do not support resource-level permissions
  name = "sas-evidence-pipeline-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "ReadSecurityHubFindings", Effect = "Allow", Action = "securityhub:GetFindings", Resource = "*" },
      { Sid = "EvidenceObjects", Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${module.evidence_bucket.arn}/*" },
      { Sid = "EvidenceList", Effect = "Allow", Action = "s3:ListBucket", Resource = module.evidence_bucket.arn },
      { Sid = "UseSasKey", Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.sas.arn },
      { Sid = "WriteStatus", Effect = "Allow", Action = ["dynamodb:PutItem", "dynamodb:BatchWriteItem"], Resource = aws_dynamodb_table.control_status.arn },
      { Sid = "WriteOwnLogs", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.pipeline.arn}:*" },
      { Sid = "XRay", Effect = "Allow", Action = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"], Resource = "*" },
    ]
  })
}

resource "aws_iam_role" "pipeline" {
  name               = "sas-evidence-pipeline-role"
  assume_role_policy = local.lambda_trust
}

resource "aws_iam_role_policy_attachment" "pipeline" {
  role       = aws_iam_role.pipeline.name
  policy_arn = aws_iam_policy.pipeline.arn
}

data "archive_file" "pipeline" {
  type        = "zip"
  output_path = "${path.module}/.build/sas-evidence-pipeline.zip"

  source {
    content  = file("${path.module}/../src/evidence_pipeline/lambda_function.py")
    filename = "lambda_function.py"
  }
  source {
    content  = file("${path.module}/../src/evidence_pipeline/control-map.json")
    filename = "control-map.json"
  }
  source {
    content  = file("${path.module}/../oscal/catalog/moderate_controls.json")
    filename = "moderate_controls.json"
  }
}

resource "aws_lambda_function" "pipeline" {
  #checkov:skip=CKV_AWS_117:No VPC by design; functions reach only AWS APIs over TLS. Risk accepted (Lambda.3), docs/risk-register.md
  #checkov:skip=CKV_AWS_116:Failures surface in CloudWatch Logs and the next daily run; no async consumer needs a DLQ. POA&M-07
  #checkov:skip=CKV_AWS_272:Code signing not yet configured. POA&M-06
  #checkov:skip=CKV_AWS_115:New-account concurrency quota is too low to reserve per function; API throttling limits load (SC-5)
  #checkov:skip=CKV_AWS_173:Environment variables hold resource names only, no secrets; encrypted at rest with the AWS managed key
  function_name    = "sas-evidence-pipeline"
  role             = aws_iam_role.pipeline.arn
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "lambda_function.lambda_handler"
  filename         = data.archive_file.pipeline.output_path
  source_code_hash = data.archive_file.pipeline.output_base64sha256
  timeout          = 300
  memory_size      = 512

  environment {
    variables = {
      EVIDENCE_BUCKET = module.evidence_bucket.id
      STATUS_TABLE    = aws_dynamodb_table.control_status.name
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.pipeline]
}

# ---- daily run, 7:30 Eastern ----

resource "aws_iam_policy" "scheduler" {
  name = "sas-scheduler-policy"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "lambda:InvokeFunction", Resource = aws_lambda_function.pipeline.arn }]
  })
}

resource "aws_iam_role" "scheduler" {
  name = "sas-scheduler-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "scheduler" {
  role       = aws_iam_role.scheduler.name
  policy_arn = aws_iam_policy.scheduler.arn
}

resource "aws_scheduler_schedule" "evidence_daily" {
  #checkov:skip=CKV_AWS_297:Schedule payload holds no data; AWS owned key is sufficient
  name                         = "sas-evidence-daily"
  group_name                   = "default"
  schedule_expression          = "cron(30 7 * * ? *)"
  schedule_expression_timezone = "America/New_York"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.pipeline.arn
    role_arn = aws_iam_role.scheduler.arn
  }
}

# ---- backups (CP-9): both DynamoDB tables, daily, 35 days ----

resource "aws_backup_vault" "sas" {
  name        = "sas-backup-vault"
  kms_key_arn = aws_kms_key.sas.arn
}

resource "aws_iam_role" "backup" {
  name = "sas-backup-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  for_each = toset([
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores",
  ])
  role       = aws_iam_role.backup.name
  policy_arn = each.value
}

resource "aws_backup_plan" "daily" {
  name = "sas-daily"

  rule {
    rule_name         = "daily-35d"
    target_vault_name = aws_backup_vault.sas.name
    schedule          = "cron(0 6 * * ? *)"
    start_window      = 60
    completion_window = 10080

    lifecycle {
      delete_after = 35
    }
  }
}

resource "aws_backup_selection" "tables" {
  for_each = {
    "sas-records-table"        = aws_dynamodb_table.records.arn
    "sas-control-status-table" = aws_dynamodb_table.control_status.arn
  }
  name         = each.key
  plan_id      = aws_backup_plan.daily.id
  iam_role_arn = aws_iam_role.backup.arn
  resources    = [each.value]
}
