# SAS policy as code: the SSP's organization-defined parameters, checked against the
# Terraform source before anything deploys. Run with:
#   conftest test terraform/ --combine --all-namespaces --policy policy/terraform
# Every message starts with the NIST control ID so CI output maps straight to the SSP.
package sas.terraform

import rego.v1

# ---------- helpers ----------

# All blocks of one resource type across every .tf file (conftest --combine input).
resources(t) := [{"name": n, "body": b, "path": f.path} |
	some f in input
	some n, blocks in f.contents.resource[t]
	some b in blocks
]

modules := [{"name": n, "body": b, "path": f.path} |
	some f in input
	some n, blocks in f.contents.module
	some b in blocks
]

locals_merged := object.union_n([l | some f in input; some l in f.contents.locals])

min_log_retention := 365

retention_ok(v) if {
	is_number(v)
	v >= min_log_retention
}

retention_ok(v) if {
	v == "${local.log_retention_days}"
	locals_merged.log_retention_days >= min_log_retention
}

# ---------- AU-11: audit record retention ----------

deny contains msg if {
	some r in resources("aws_cloudwatch_log_group")
	not retention_ok(r.body.retention_in_days)
	msg := sprintf("AU-11: log group %q must retain logs at least %d days (%s)", [r.name, min_log_retention, r.path])
}

# ---------- AU-12 / Lambda.7: tracing on every function ----------

deny contains msg if {
	some r in resources("aws_lambda_function")
	not tracing_active(r.body)
	msg := sprintf("AU-12: Lambda %q must have active X-Ray tracing (%s)", [r.name, r.path])
}

tracing_active(b) if {
	some t in b.tracing_config
	t.mode == "Active"
}

# ---------- SC-28 / CP-9: DynamoDB encrypted with the CMK, PITR, deletion protection ----------

deny contains msg if {
	some r in resources("aws_dynamodb_table")
	not cmk_encrypted(r.body)
	msg := sprintf("SC-28: DynamoDB table %q must be encrypted with a customer managed key", [r.name])
}

cmk_encrypted(b) if {
	some e in b.server_side_encryption
	e.enabled == true
	e.kms_key_arn
}

deny contains msg if {
	some r in resources("aws_dynamodb_table")
	not pitr_on(r.body)
	msg := sprintf("CP-9: DynamoDB table %q must have point-in-time recovery", [r.name])
}

pitr_on(b) if {
	some p in b.point_in_time_recovery
	p.enabled == true
}

deny contains msg if {
	some r in resources("aws_dynamodb_table")
	not r.body.deletion_protection_enabled == true
	msg := sprintf("CP-9: DynamoDB table %q must have deletion protection", [r.name])
}

# ---------- AC-3: no unauthenticated API routes ----------

deny contains msg if {
	some r in resources("aws_apigatewayv2_route")
	not r.body.authorization_type in {"AWS_IAM", "JWT", "CUSTOM"}
	msg := sprintf("AC-3: API route %q must require IAM, JWT, or custom authorization", [r.name])
}

# ---------- AU-2 / AU-12: API access logging ----------

deny contains msg if {
	some r in resources("aws_apigatewayv2_stage")
	count(object.get(r.body, "access_log_settings", [])) == 0
	msg := sprintf("AU-2: API stage %q must write access logs", [r.name])
}

# ---------- SC-5: API throttling ----------

deny contains msg if {
	some r in resources("aws_apigatewayv2_stage")
	not throttled(r.body)
	msg := sprintf("SC-5: API stage %q must set rate and burst throttling", [r.name])
}

throttled(b) if {
	some s in b.default_route_settings
	s.throttling_rate_limit > 0
	s.throttling_burst_limit > 0
}

# ---------- IA-5(1): account password parameters ----------

deny contains msg if {
	some r in resources("aws_iam_account_password_policy")
	r.body.minimum_password_length < 14
	msg := "IA-5(1): IAM password minimum length must be at least 14"
}

deny contains msg if {
	some r in resources("aws_iam_account_password_policy")
	object.get(r.body, "password_reuse_prevention", 0) < 24
	msg := "IA-5(1): IAM password reuse prevention must be at least 24"
}

deny contains msg if {
	some r in resources("aws_iam_account_password_policy")
	some k in ["require_uppercase_characters", "require_lowercase_characters", "require_numbers", "require_symbols"]
	not r.body[k] == true
	msg := sprintf("IA-5(1): IAM password policy must set %s", [k])
}

# ---------- IA-2(1) / IA-5(1): Cognito ----------

deny contains msg if {
	some r in resources("aws_cognito_user_pool")
	not r.body.mfa_configuration == "ON"
	msg := sprintf("IA-2(1): Cognito pool %q must require MFA", [r.name])
}

deny contains msg if {
	some r in resources("aws_cognito_user_pool")
	some p in r.body.password_policy
	p.minimum_length < 14
	msg := sprintf("IA-5(1): Cognito pool %q passwords must be at least 14 characters", [r.name])
}

# ---------- AU-9: CloudTrail integrity ----------

deny contains msg if {
	some r in resources("aws_cloudtrail")
	some k in ["enable_log_file_validation", "is_multi_region_trail"]
	not r.body[k] == true
	msg := sprintf("AU-9: trail %q must set %s", [r.name, k])
}

deny contains msg if {
	some r in resources("aws_cloudtrail")
	not r.body.kms_key_id
	msg := sprintf("AU-9: trail %q must encrypt log files with KMS", [r.name])
}

# ---------- SC-12: key rotation ----------

deny contains msg if {
	some r in resources("aws_kms_key")
	not r.body.enable_key_rotation == true
	msg := sprintf("SC-12: KMS key %q must rotate automatically", [r.name])
}

# ---------- SC-8: TLS only ----------

deny contains msg if {
	some r in resources("aws_s3_bucket_policy")
	not contains(r.body.policy, "aws:SecureTransport")
	msg := sprintf("SC-8: bucket policy %q must deny non-TLS requests (%s)", [r.name, r.path])
}

deny contains msg if {
	some r in resources("aws_cloudfront_distribution")
	some c in r.body.default_cache_behavior
	not c.viewer_protocol_policy in {"redirect-to-https", "https-only"}
	msg := sprintf("SC-8: CloudFront %q must force HTTPS", [r.name])
}

# ---------- SC-28: buckets use the CMK; SSE-S3 only for the documented access-log exception ----------

deny contains msg if {
	some m in modules
	m.body.source == "./modules/hardened_bucket"
	m.body.kms_key_arn == null
	not contains(m.body.name, "accesslogs")
	msg := sprintf("SC-28: bucket module %q must use the customer managed key (only the access-log bucket is exempt)", [m.name])
}

# ---------- CM-8: every resource carries the boundary tag ----------

deny contains msg if {
	some f in input
	some p in f.contents.provider.aws
	not boundary_tagged(p)
	msg := "CM-8: the aws provider must set default_tags Boundary = sas"
}

boundary_tagged(p) if {
	some d in p.default_tags
	d.tags.Boundary == "sas"
}
