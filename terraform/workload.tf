# The workload inside the boundary: a records API (API Gateway, IAM auth) over Lambda and DynamoDB.

resource "aws_dynamodb_table" "records" {
  name                        = "records"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "record_id"
  deletion_protection_enabled = true

  attribute {
    name = "record_id"
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

resource "aws_cloudwatch_log_group" "records_api_lambda" {
  #checkov:skip=CKV_AWS_158:Log groups use CloudWatch default encryption; CMK encryption planned. POA&M-03
  name              = "/aws/lambda/records-api"
  retention_in_days = local.log_retention_days
}

resource "aws_iam_policy" "records_api" {
  name = "sas-records-api-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "RecordsTable"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"]
        Resource = aws_dynamodb_table.records.arn
      },
      {
        Sid      = "DataBucketObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${module.data_bucket.arn}/*"
      },
      {
        Sid      = "UseSasKey"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.sas.arn
      },
      {
        Sid      = "WriteOwnLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.records_api_lambda.arn}:*"
      },
    ]
  })
}

resource "aws_iam_role" "records_api" {
  name               = "sas-records-api-role"
  description        = "Allows Lambda functions to call AWS services on your behalf."
  assume_role_policy = local.lambda_trust
}

resource "aws_iam_role_policy_attachment" "records_api" {
  role       = aws_iam_role.records_api.name
  policy_arn = aws_iam_policy.records_api.arn
}

resource "aws_iam_role_policy_attachment" "records_api_xray" {
  role       = aws_iam_role.records_api.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

data "archive_file" "records_api" {
  type        = "zip"
  source_file = "${path.module}/../src/records_api/lambda_function.py"
  output_path = "${path.module}/.build/records-api.zip"
}

resource "aws_lambda_function" "records_api" {
  #checkov:skip=CKV_AWS_117:No VPC by design; functions reach only AWS APIs over TLS. Risk accepted (Lambda.3), docs/risk-register.md
  #checkov:skip=CKV_AWS_116:Failures surface in CloudWatch Logs and the next daily run; no async consumer needs a DLQ. POA&M-07
  #checkov:skip=CKV_AWS_272:Code signing not yet configured. POA&M-06
  #checkov:skip=CKV_AWS_115:New-account concurrency quota is too low to reserve per function; API throttling limits load (SC-5)
  #checkov:skip=CKV_AWS_173:Environment variables hold resource names only, no secrets; encrypted at rest with the AWS managed key
  function_name    = "records-api"
  role             = aws_iam_role.records_api.arn
  runtime          = var.discovered.records_api_runtime
  architectures    = ["arm64"]
  handler          = "lambda_function.lambda_handler"
  filename         = data.archive_file.records_api.output_path
  source_code_hash = data.archive_file.records_api.output_base64sha256
  timeout          = 10
  memory_size      = var.discovered.records_api_memory

  environment {
    variables = { TABLE_NAME = aws_dynamodb_table.records.name }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.records_api_lambda]
}

# ---- API Gateway: both routes require SigV4 (IAM) auth ----

resource "aws_cloudwatch_log_group" "records_api_access" {
  #checkov:skip=CKV_AWS_158:Log groups use CloudWatch default encryption; CMK encryption planned. POA&M-03
  name              = "/sas/apigw/records-api"
  retention_in_days = local.log_retention_days
}

resource "aws_apigatewayv2_api" "records" {
  name          = "sas-records-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "records" {
  for_each               = toset(keys(var.discovered.records_route_integrations))
  api_id                 = aws_apigatewayv2_api.records.id
  integration_type       = "AWS_PROXY"
  integration_method     = "POST"
  integration_uri        = aws_lambda_function.records_api.arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "records" {
  for_each           = toset(["GET /records", "POST /records"])
  api_id             = aws_apigatewayv2_api.records.id
  route_key          = each.key
  target             = "integrations/${aws_apigatewayv2_integration.records[each.key].id}"
  authorization_type = "AWS_IAM"
}

resource "aws_apigatewayv2_stage" "records" {
  api_id      = aws_apigatewayv2_api.records.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.records_api_access.arn
    format          = var.discovered.records_api_access_log_format
  }

  default_route_settings {
    throttling_rate_limit  = 10
    throttling_burst_limit = 20
  }
}

resource "aws_lambda_permission" "records_api" {
  statement_id  = var.discovered.records_api_permission_sid
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.records_api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.records.execution_arn}/*/*/records"
}
