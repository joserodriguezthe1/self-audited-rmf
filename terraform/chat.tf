# Compliance chat: Bedrock tool use over the status table and evidence bucket. Read-only.
# Reached two ways: Lambda invoke from the CLI (IAM), and POST /chat behind a Cognito JWT.

resource "aws_cloudwatch_log_group" "chat" {
  #checkov:skip=CKV_AWS_158:Log groups use CloudWatch default encryption; CMK encryption planned. POA&M-03
  name              = "/aws/lambda/sas-chat"
  retention_in_days = local.log_retention_days
}

resource "aws_iam_policy" "chat" {
  name = "sas-chat-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "ReadStatus", Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:Scan"], Resource = aws_dynamodb_table.control_status.arn },
      { Sid = "ReadEvidence", Effect = "Allow", Action = "s3:GetObject", Resource = "${module.evidence_bucket.arn}/*" },
      { Sid = "ListEvidence", Effect = "Allow", Action = "s3:ListBucket", Resource = module.evidence_bucket.arn },
      { Sid = "DecryptWithSasKey", Effect = "Allow", Action = "kms:Decrypt", Resource = aws_kms_key.sas.arn },
      {
        Sid    = "InvokeClaudeOnly"
        Effect = "Allow"
        Action = "bedrock:InvokeModel"
        Resource = [
          "arn:aws:bedrock:*::foundation-model/anthropic.*",
          "arn:aws:bedrock:${local.region}:${local.account_id}:inference-profile/us.anthropic.*",
        ]
      },
      { Sid = "WriteOwnLogs", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.chat.arn}:*" },
      { Sid = "XRay", Effect = "Allow", Action = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"], Resource = "*" },
    ]
  })
}

resource "aws_iam_role" "chat" {
  name               = "sas-chat-role"
  assume_role_policy = local.lambda_trust
}

resource "aws_iam_role_policy_attachment" "chat" {
  role       = aws_iam_role.chat.name
  policy_arn = aws_iam_policy.chat.arn
}

data "archive_file" "chat" {
  type        = "zip"
  output_path = "${path.module}/.build/sas-chat.zip"

  source {
    content  = file("${path.module}/../src/chat/lambda_function.py")
    filename = "lambda_function.py"
  }
  source {
    content  = file("${path.module}/../oscal/catalog/moderate_controls.json")
    filename = "moderate_controls.json"
  }
}

resource "aws_lambda_function" "chat" {
  #checkov:skip=CKV_AWS_117:No VPC by design; functions reach only AWS APIs over TLS. Risk accepted (Lambda.3), docs/risk-register.md
  #checkov:skip=CKV_AWS_116:Failures surface in CloudWatch Logs and the next daily run; no async consumer needs a DLQ. POA&M-07
  #checkov:skip=CKV_AWS_272:Code signing not yet configured. POA&M-06
  #checkov:skip=CKV_AWS_115:New-account concurrency quota is too low to reserve per function; API throttling limits load (SC-5)
  #checkov:skip=CKV_AWS_173:Environment variables hold resource names only, no secrets; encrypted at rest with the AWS managed key
  function_name    = "sas-chat"
  role             = aws_iam_role.chat.arn
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "lambda_function.lambda_handler"
  filename         = data.archive_file.chat.output_path
  source_code_hash = data.archive_file.chat.output_base64sha256
  timeout          = 120
  memory_size      = 512

  environment {
    variables = {
      MODEL_ID        = var.chat_model_id
      STATUS_TABLE    = aws_dynamodb_table.control_status.name
      EVIDENCE_BUCKET = module.evidence_bucket.id
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.chat]
}

# ---- Cognito: admin-created users only, 14-character passwords, TOTP MFA required (IA-2(1), IA-5) ----

resource "aws_cognito_user_pool" "users" {
  name                     = "sas-users"
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]
  mfa_configuration        = "ON"

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  password_policy {
    minimum_length                   = 14
    require_uppercase                = true
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 3
  }

  software_token_mfa_configuration {
    enabled = true
  }
}

resource "aws_cognito_user_pool_domain" "users" {
  domain                = "sas-${local.account_id}"
  user_pool_id          = aws_cognito_user_pool.users.id
  managed_login_version = 1
}

resource "aws_cognito_user_pool_client" "web" {
  name                                 = "sas-web"
  user_pool_id                         = aws_cognito_user_pool.users.id
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email"]
  allowed_oauth_flows_user_pool_client = true
  supported_identity_providers         = ["COGNITO"]
  callback_urls                        = ["https://${aws_cloudfront_distribution.web.domain_name}/"]
  logout_urls                          = ["https://${aws_cloudfront_distribution.web.domain_name}/"]
  explicit_auth_flows                  = ["ALLOW_REFRESH_TOKEN_AUTH"]
  prevent_user_existence_errors        = "ENABLED"
  id_token_validity                    = 60
  access_token_validity                = 60
  refresh_token_validity               = 1

  token_validity_units {
    id_token      = "minutes"
    access_token  = "minutes"
    refresh_token = "days"
  }
}

# ---- API: POST /chat requires a valid Cognito ID token ----

resource "aws_cloudwatch_log_group" "chat_api_access" {
  #checkov:skip=CKV_AWS_158:Log groups use CloudWatch default encryption; CMK encryption planned. POA&M-03
  name              = "/sas/apigw/sas-chat-api"
  retention_in_days = local.log_retention_days
}

resource "aws_apigatewayv2_api" "chat" {
  name          = "sas-chat-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["https://${aws_cloudfront_distribution.web.domain_name}"]
    allow_methods = ["POST", "OPTIONS"]
    allow_headers = ["authorization", "content-type"]
    max_age       = 300
  }
}

resource "aws_apigatewayv2_integration" "chat" {
  api_id                 = aws_apigatewayv2_api.chat.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.chat.arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 30000
}

resource "aws_apigatewayv2_authorizer" "cognito" {
  api_id           = aws_apigatewayv2_api.chat.id
  name             = "cognito-jwt"
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]

  jwt_configuration {
    audience = [aws_cognito_user_pool_client.web.id]
    issuer   = "https://cognito-idp.${local.region}.amazonaws.com/${aws_cognito_user_pool.users.id}"
  }
}

resource "aws_apigatewayv2_route" "chat" {
  api_id             = aws_apigatewayv2_api.chat.id
  route_key          = "POST /chat"
  target             = "integrations/${aws_apigatewayv2_integration.chat.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_stage" "chat" {
  api_id      = aws_apigatewayv2_api.chat.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.chat_api_access.arn
    # Literal string so the field order matches the deployed stage exactly.
    format = "{\"requestId\":\"$context.requestId\",\"ip\":\"$context.identity.sourceIp\",\"user\":\"$context.authorizer.claims.email\",\"route\":\"$context.routeKey\",\"status\":\"$context.status\",\"latency\":\"$context.integrationLatency\",\"time\":\"$context.requestTime\"}"
  }

  default_route_settings {
    throttling_rate_limit  = 5
    throttling_burst_limit = 10
  }
}

resource "aws_lambda_permission" "chat_api" {
  statement_id  = "apigw-sas-chat-api"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.chat.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.chat.execution_arn}/*/*/chat"
}
