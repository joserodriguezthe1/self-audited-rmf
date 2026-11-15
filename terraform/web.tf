# Web chat page: private S3 bucket behind CloudFront with origin access control, HTTPS only.

resource "aws_cloudfront_origin_access_control" "web" {
  name                              = var.discovered.cloudfront_oac_name
  description                       = "Created by CloudFront"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "web" {
  #checkov:skip=CKV2_AWS_47:Web ACL is the one created with the CloudFront plan; its rule set is not yet reviewed. POA&M-04
  #checkov:skip=CKV_AWS_86:CloudFront access logging planned. POA&M-05
  #checkov:skip=CKV2_AWS_32:Security response headers policy planned. POA&M-05
  #checkov:skip=CKV_AWS_174:Default *.cloudfront.net certificate; minimum TLS version is only settable with a custom certificate
  #checkov:skip=CKV2_AWS_42:No custom domain; default CloudFront certificate is used
  #checkov:skip=CKV_AWS_310:Single static origin; failover adds no value for this page
  #checkov:skip=CKV_AWS_374:No geographic restriction requirement for this system
  enabled             = true
  default_root_object = "index.html"
  is_ipv6_enabled     = true
  http_version        = "http2"
  web_acl_id          = var.discovered.cloudfront_web_acl_id # web ACL created with the CloudFront plan
  tags                = { Name = "sas-web" }

  origin {
    origin_id                = var.discovered.cloudfront_origin_id
    domain_name              = module.web_bucket.regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.web.id
  }

  default_cache_behavior {
    target_origin_id       = var.discovered.cloudfront_origin_id
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true
    cache_policy_id        = "658327ea-f89d-4fab-a63d-7e88639e58f6" # AWS managed CachingOptimized
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

resource "aws_s3_object" "index" {
  bucket        = module.web_bucket.id
  key           = "index.html"
  source        = "${path.module}/../web/index.html"
  source_hash   = filemd5("${path.module}/../web/index.html")
  content_type  = "text/html; charset=utf-8"
  cache_control = "no-cache"
}

resource "aws_s3_object" "config" {
  bucket = module.web_bucket.id
  key    = "config.js"
  content = templatefile("${path.module}/../web/config.js.tftpl", {
    cognito_domain = "https://${aws_cognito_user_pool_domain.users.domain}.auth.${local.region}.amazoncognito.com"
    client_id      = aws_cognito_user_pool_client.web.id
    redirect_uri   = "https://${aws_cloudfront_distribution.web.domain_name}/"
    api_url        = aws_apigatewayv2_api.chat.api_endpoint
  })
  content_type  = "application/javascript"
  cache_control = "no-cache"
}

output "web_url" {
  value = "https://${aws_cloudfront_distribution.web.domain_name}/"
}

output "chat_api_url" {
  value = aws_apigatewayv2_api.chat.api_endpoint
}

output "records_api_url" {
  value = aws_apigatewayv2_api.records.api_endpoint
}
