package sas.terraform_test

import rego.v1

import data.sas.terraform

# Build conftest --combine style input from one file's parsed HCL.
file(contents) := [{"path": "test.tf", "contents": contents}]

good_tf := {
	"locals": [{"log_retention_days": 365}],
	"provider": {"aws": [{"default_tags": [{"tags": {"Boundary": "sas"}}]}]},
	"resource": {
		"aws_cloudwatch_log_group": {"lg": [{"retention_in_days": "${local.log_retention_days}"}]},
		"aws_lambda_function": {"fn": [{"tracing_config": [{"mode": "Active"}]}]},
		"aws_dynamodb_table": {"t": [{
			"server_side_encryption": [{"enabled": true, "kms_key_arn": "${aws_kms_key.sas.arn}"}],
			"point_in_time_recovery": [{"enabled": true}],
			"deletion_protection_enabled": true,
		}]},
		"aws_apigatewayv2_route": {"r": [{"authorization_type": "JWT"}]},
		"aws_apigatewayv2_stage": {"s": [{
			"access_log_settings": [{"format": "x"}],
			"default_route_settings": [{"throttling_rate_limit": 5, "throttling_burst_limit": 10}],
		}]},
		"aws_iam_account_password_policy": {"p": [{
			"minimum_password_length": 14, "password_reuse_prevention": 24,
			"require_uppercase_characters": true, "require_lowercase_characters": true,
			"require_numbers": true, "require_symbols": true,
		}]},
		"aws_cognito_user_pool": {"u": [{"mfa_configuration": "ON", "password_policy": [{"minimum_length": 14}]}]},
		"aws_cloudtrail": {"t": [{"enable_log_file_validation": true, "is_multi_region_trail": true, "kms_key_id": "k"}]},
		"aws_kms_key": {"k": [{"enable_key_rotation": true}]},
		"aws_s3_bucket_policy": {"b": [{"policy": "{\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}"}]},
		"aws_cloudfront_distribution": {"d": [{"default_cache_behavior": [{"viewer_protocol_policy": "redirect-to-https"}]}]},
	},
	"module": {
		"data_bucket": [{"source": "./modules/hardened_bucket", "name": "sas-data-1", "kms_key_arn": "k"}],
		"accesslogs_bucket": [{"source": "./modules/hardened_bucket", "name": "sas-accesslogs-1", "kms_key_arn": null}],
	},
}

test_compliant_config_passes if {
	count(terraform.deny) == 0 with input as file(good_tf)
}

# Each case breaks one setting and expects exactly the matching control in the message.
break(path, value) := json.patch(good_tf, [{"op": "replace", "path": path, "value": value}])

expect(tf, control) if {
	msgs := terraform.deny with input as file(tf)
	some m in msgs
	startswith(m, control)
}

test_au_11_short_retention if expect(break("/resource/aws_cloudwatch_log_group/lg/0/retention_in_days", 30), "AU-11")

test_au_11_local_too_low if expect(break("/locals/0/log_retention_days", 90), "AU-11")

test_au_12_no_tracing if expect(break("/resource/aws_lambda_function/fn/0/tracing_config/0/mode", "PassThrough"), "AU-12")

test_sc_28_dynamodb_default_key if expect(break("/resource/aws_dynamodb_table/t/0/server_side_encryption/0/enabled", false), "SC-28")

test_cp_9_no_pitr if expect(break("/resource/aws_dynamodb_table/t/0/point_in_time_recovery/0/enabled", false), "CP-9")

test_ac_3_open_route if expect(break("/resource/aws_apigatewayv2_route/r/0/authorization_type", "NONE"), "AC-3")

test_au_2_no_access_logs if expect(break("/resource/aws_apigatewayv2_stage/s/0/access_log_settings", []), "AU-2")

test_sc_5_no_throttle if expect(break("/resource/aws_apigatewayv2_stage/s/0/default_route_settings/0/throttling_rate_limit", 0), "SC-5")

test_ia_5_short_password if expect(break("/resource/aws_iam_account_password_policy/p/0/minimum_password_length", 8), "IA-5(1)")

test_ia_5_no_symbols if expect(break("/resource/aws_iam_account_password_policy/p/0/require_symbols", false), "IA-5(1)")

test_ia_2_cognito_mfa_optional if expect(break("/resource/aws_cognito_user_pool/u/0/mfa_configuration", "OPTIONAL"), "IA-2(1)")

test_au_9_no_validation if expect(break("/resource/aws_cloudtrail/t/0/enable_log_file_validation", false), "AU-9")

test_sc_12_no_rotation if expect(break("/resource/aws_kms_key/k/0/enable_key_rotation", false), "SC-12")

test_sc_8_bucket_allows_http if expect(break("/resource/aws_s3_bucket_policy/b/0/policy", "{}"), "SC-8")

test_sc_8_cloudfront_allows_http if expect(break("/resource/aws_cloudfront_distribution/d/0/default_cache_behavior/0/viewer_protocol_policy", "allow-all"), "SC-8")

test_sc_28_bucket_without_cmk if expect(break("/module/data_bucket/0/kms_key_arn", null), "SC-28")

test_cm_8_missing_boundary_tag if expect(break("/provider/aws/0/default_tags/0/tags/Boundary", "other"), "CM-8")
