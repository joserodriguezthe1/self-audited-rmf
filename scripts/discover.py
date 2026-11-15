#!/usr/bin/env python3
"""Read the live SAS account and write the files Terraform needs to adopt it.

Writes (all gitignored, all account-specific):
  terraform/discovered.auto.tfvars.json   as-built names and settings
  terraform/imports.tf                     one import block per live resource
  terraform/backend.hcl                    S3 backend settings (state in the evidence bucket)

Run from the repo root in CloudShell:  python3 scripts/discover.py
Read-only: it only calls Describe/Get/List APIs.
"""
import json
import os
import sys

import boto3
from botocore.exceptions import ClientError

REGION = os.environ.get("AWS_REGION", "us-east-1")
s = boto3.session.Session(region_name=REGION)
ACCT = s.client("sts").get_caller_identity()["Account"]
TF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "terraform")

imports, warnings = [], []


def imp(to, id_):
    imports.append((to, id_))


def warn(msg):
    warnings.append(msg)
    print(f"WARN  {msg}")


def try_(fn, what, default=None):
    try:
        return fn()
    except (ClientError, KeyError, IndexError, StopIteration, TypeError) as e:
        warn(f"{what}: {e}")
        return default


# ---------------- KMS ----------------
kms = s.client("kms")
key_id = try_(lambda: kms.describe_key(KeyId="alias/sas-key")["KeyMetadata"]["KeyId"], "kms alias/sas-key")
key_arn = f"arn:aws:kms:{REGION}:{ACCT}:key/{key_id}"
if key_id:
    imp("aws_kms_key.sas", key_id)
    imp("aws_kms_alias.sas", "alias/sas-key")

# ---------------- buckets ----------------
s3 = s.client("s3")
buckets = {k: f"sas-{k}-{ACCT}" for k in ["logs", "accesslogs", "data", "evidence", "web"]}
for k, b in buckets.items():
    m = f"module.{k}_bucket"
    if not try_(lambda: s3.head_bucket(Bucket=b) or True, f"bucket {b}"):
        continue
    for r in ["aws_s3_bucket", "aws_s3_bucket_public_access_block", "aws_s3_bucket_versioning",
              "aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_policy",
              "aws_s3_bucket_lifecycle_configuration", "aws_s3_bucket_notification"]:
        imp(f"{m}.{r}.this", b)
    if k != "accesslogs":
        imp(f"{m}.aws_s3_bucket_logging.this[0]", b)
    if k in ("logs", "evidence"):
        imp(f"{m}.aws_s3_bucket_object_lock_configuration.this[0]", b)
imp("aws_s3_object.index", f"s3://{buckets['web']}/index.html")
imp("aws_s3_object.config", f"s3://{buckets['web']}/config.js")

# ---------------- log groups ----------------
for addr, name in {
    "cloudtrail": "/sas/cloudtrail", "ssm_automation": "/sas/ssm-automation",
    "records_api_lambda": "/aws/lambda/records-api", "records_api_access": "/sas/apigw/records-api",
    "pipeline": "/aws/lambda/sas-evidence-pipeline", "chat": "/aws/lambda/sas-chat",
    "chat_api_access": "/sas/apigw/sas-chat-api",
}.items():
    imp(f"aws_cloudwatch_log_group.{addr}", name)

# ---------------- CloudTrail and its CloudWatch Logs role ----------------
ct = s.client("cloudtrail")
iam = s.client("iam")
trail = try_(lambda: ct.describe_trails(trailNameList=["sas-trail"])["trailList"][0], "trail sas-trail", {})
imp("aws_cloudtrail.sas", f"arn:aws:cloudtrail:{REGION}:{ACCT}:trail/sas-trail")
cwl_role_arn = trail.get("CloudWatchLogsRoleArn", "")
cwl_role_name = cwl_role_arn.split("/")[-1] if cwl_role_arn else "CloudTrailRoleForCloudWatchLogs_sas"
cwl_role = try_(lambda: iam.get_role(RoleName=cwl_role_name)["Role"], "cloudtrail cwl role", {})
cwl_pol = try_(lambda: iam.list_attached_role_policies(RoleName=cwl_role_name)["AttachedPolicies"][0],
               "cloudtrail cwl policy", {})
cwl_pol_arn = cwl_pol.get("PolicyArn", "")
cwl_pol_meta = try_(lambda: iam.get_policy(PolicyArn=cwl_pol_arn)["Policy"], "cloudtrail cwl policy meta", {}) if cwl_pol_arn else {}
imp("aws_iam_role.cloudtrail_cwl", cwl_role_name)
if cwl_pol_arn:
    imp("aws_iam_policy.cloudtrail_cwl", cwl_pol_arn)
    imp("aws_iam_role_policy_attachment.cloudtrail_cwl", f"{cwl_role_name}/{cwl_pol_arn}")

# ---------------- IAM roles and policies ----------------
pol = lambda n: f"arn:aws:iam::{ACCT}:policy/{n}"
for addr, role, policy in [
    ("records_api", "sas-records-api-role", "sas-records-api-policy"),
    ("pipeline", "sas-evidence-pipeline-role", "sas-evidence-pipeline-policy"),
    ("scheduler", "sas-scheduler-role", "sas-scheduler-policy"),
    ("chat", "sas-chat-role", "sas-chat-policy"),
]:
    imp(f"aws_iam_role.{addr}", role)
    imp(f"aws_iam_policy.{addr}", pol(policy))
    imp(f"aws_iam_role_policy_attachment.{addr}", f"{role}/{pol(policy)}")
imp("aws_iam_role_policy_attachment.records_api_xray",
    "sas-records-api-role/arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess")
imp("aws_iam_role.backup", "sas-backup-role")
for p in ["AWSBackupServiceRolePolicyForBackup", "AWSBackupServiceRolePolicyForRestores"]:
    arn = f"arn:aws:iam::aws:policy/service-role/{p}"
    imp(f'aws_iam_role_policy_attachment.backup["{arn}"]', f"sas-backup-role/{arn}")

# ---------------- account settings ----------------
imp("aws_iam_account_password_policy.this", "iam-account-password-policy")
imp("aws_s3_account_public_access_block.this", ACCT)
imp("aws_ebs_encryption_by_default.this", "default")
for addr, sid in [("doc_public_sharing", "documents/console/public-sharing-permission"),
                  ("automation_log_destination", "automation/customer-script-log-destination"),
                  ("automation_log_group", "automation/customer-script-log-group-name")]:
    imp(f"aws_ssm_service_setting.{addr}", f"arn:aws:ssm:{REGION}:{ACCT}:servicesetting/ssm/{sid}")
imp("aws_account_alternate_contact.security", "SECURITY")
budgets = try_(lambda: [b["BudgetName"] for b in s.client("budgets").describe_budgets(AccountId=ACCT).get("Budgets", [])], "budgets", [])
budget_name = next((b for b in budgets if "sas" in b.lower()), budgets[0] if len(budgets) == 1 else "")
if budget_name:
    imp("aws_budgets_budget.monthly", f"{ACCT}:{budget_name}")
    print(f"OK    budget {budget_name!r}")
else:
    warn(f"no budget to import (found: {budgets}); Terraform will create sas-monthly")
    budget_name = "sas-monthly"

# ---------------- DynamoDB, Lambda ----------------
for addr, t in [("records", "records"), ("control_status", "control_status")]:
    imp(f"aws_dynamodb_table.{addr}", t)
lam = s.client("lambda")
for addr, fn in [("records_api", "records-api"), ("pipeline", "sas-evidence-pipeline"), ("chat", "sas-chat")]:
    imp(f"aws_lambda_function.{addr}", fn)
rec_cfg = try_(lambda: lam.get_function_configuration(FunctionName="records-api"), "records-api config", {})


def apigw_sid(fn):
    p = try_(lambda: json.loads(lam.get_policy(FunctionName=fn)["Policy"]), f"{fn} resource policy", {})
    for st in p.get("Statement", []):
        if st.get("Principal", {}).get("Service") == "apigateway.amazonaws.com":
            return st["Sid"]
    return None


rec_sid = apigw_sid("records-api")
if rec_sid:
    imp("aws_lambda_permission.records_api", f"records-api/{rec_sid}")
imp("aws_lambda_permission.chat_api", "sas-chat/apigw-sas-chat-api")

# ---------------- API Gateway ----------------
gw = s.client("apigatewayv2")
apis = {a["Name"]: a["ApiId"] for a in gw.get_apis()["Items"]}
rec_log_format = ""
route_integrations = {}
for name, key in [("sas-records-api", "records"), ("sas-chat-api", "chat")]:
    api = apis.get(name)
    if not api:
        warn(f"api {name} not found")
        continue
    imp(f"aws_apigatewayv2_api.{key}", api)
    routes = gw.get_routes(ApiId=api)["Items"]
    for r in routes:
        integ = r.get("Target", "").split("/")[-1]
        if key == "records":
            imp(f'aws_apigatewayv2_route.records["{r["RouteKey"]}"]', f"{api}/{r['RouteId']}")
            imp(f'aws_apigatewayv2_integration.records["{r["RouteKey"]}"]', f"{api}/{integ}")
            route_integrations[r["RouteKey"]] = integ
        else:
            imp("aws_apigatewayv2_route.chat", f"{api}/{r['RouteId']}")
            imp("aws_apigatewayv2_integration.chat", f"{api}/{integ}")
    imp(f"aws_apigatewayv2_stage.{key}", f"{api}/$default")
    if key == "chat":
        auths = gw.get_authorizers(ApiId=api)["Items"]
        if auths:
            imp("aws_apigatewayv2_authorizer.cognito", f"{api}/{auths[0]['AuthorizerId']}")
    else:
        st = try_(lambda: gw.get_stage(ApiId=api, StageName="$default"), "records stage", {})
        rec_log_format = st.get("AccessLogSettings", {}).get("Format", "")

# ---------------- Config, Security Hub ----------------
cfg = s.client("config")
rec_name = try_(lambda: cfg.describe_configuration_recorders()["ConfigurationRecorders"][0]["name"], "config recorder", "default")
ch_name = try_(lambda: cfg.describe_delivery_channels()["DeliveryChannels"][0]["name"], "config channel", "default")
imp("aws_config_configuration_recorder.this", rec_name)
imp("aws_config_delivery_channel.this", ch_name)
imp("aws_config_configuration_recorder_status.this", rec_name)

sh = s.client("securityhub")
imp("aws_securityhub_account.this", ACCT)
imp("aws_securityhub_standards_subscription.nist_800_53",
    f"arn:aws:securityhub:{REGION}:{ACCT}:subscription/nist-800-53/v/5.0.0")
orders = {}
rules = try_(lambda: sh.list_automation_rules(MaxResults=100)["AutomationRulesMetadata"], "automation rules", [])
for r in rules:
    if r["RuleName"].startswith("sas-accept-"):
        orders[r["RuleName"]] = r["RuleOrder"]
        imp(f'aws_securityhub_automation_rule.risk_acceptance["{r["RuleName"]}"]', r["RuleArn"])

# ---------------- scheduler, backup ----------------
imp("aws_scheduler_schedule.evidence_daily", "default/sas-evidence-daily")
bk = s.client("backup")
imp("aws_backup_vault.sas", "sas-backup-vault")
plan_id = try_(lambda: next(p["BackupPlanId"] for p in bk.list_backup_plans()["BackupPlansList"]
                            if p["BackupPlanName"] == "sas-daily"), "backup plan sas-daily")
if plan_id:
    imp("aws_backup_plan.daily", plan_id)
    for sel in bk.list_backup_selections(BackupPlanId=plan_id)["BackupSelectionsList"]:
        imp(f'aws_backup_selection.tables["{sel["SelectionName"]}"]', f"{plan_id}|{sel['SelectionId']}")

# ---------------- Cognito ----------------
cog = s.client("cognito-idp")
pools = sorted([p for p in cog.list_user_pools(MaxResults=60)["UserPools"] if p["Name"] == "sas-users"],
               key=lambda p: p["CreationDate"])
if len(pools) > 1:
    warn(f"{len(pools)} user pools named sas-users; using the newest. Delete the others.")
if pools:
    pool_id = pools[-1]["Id"]
    imp("aws_cognito_user_pool.users", pool_id)
    imp("aws_cognito_user_pool_domain.users", f"sas-{ACCT}")
    client = try_(lambda: next(c["ClientId"] for c in cog.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60)["UserPoolClients"]
                               if c["ClientName"] == "sas-web"), "cognito client sas-web")
    if client:
        imp("aws_cognito_user_pool_client.web", f"{pool_id}/{client}")

# ---------------- CloudFront ----------------
cf = s.client("cloudfront")
origin_id, oac_name, web_acl = "", "", ""
web_origin = f"{buckets['web']}.s3"
for d in cf.list_distributions().get("DistributionList", {}).get("Items", []):
    origins = d["Origins"]["Items"]
    o = next((o for o in origins if o["DomainName"].startswith(web_origin)), None)
    if o:
        imp("aws_cloudfront_distribution.web", d["Id"])
        origin_id = o["Id"]
        web_acl = d.get("WebACLId", "")
        oac_id = o.get("OriginAccessControlId")
        if oac_id:
            imp("aws_cloudfront_origin_access_control.web", oac_id)
            oac_name = cf.get_origin_access_control(Id=oac_id)["OriginAccessControl"]["OriginAccessControlConfig"]["Name"]
        print(f"OK    distribution {d['Id']} {d['DomainName']}")
        break
else:
    warn("no CloudFront distribution with the sas-web bucket as origin")

# ---------------- write files ----------------
discovered = {"discovered": {
    "config_recorder_name": rec_name,
    "config_delivery_channel_name": ch_name,
    "cloudtrail_cwl_role_name": cwl_role_name,
    "cloudtrail_cwl_role_path": cwl_role.get("Path", "/"),
    "cloudtrail_cwl_policy_name": cwl_pol_meta.get("PolicyName", ""),
    "cloudtrail_cwl_policy_path": cwl_pol_meta.get("Path", "/"),
    "records_api_runtime": rec_cfg.get("Runtime", "python3.12"),
    "records_api_memory": rec_cfg.get("MemorySize", 128),
    "records_api_access_log_format": rec_log_format,
    "records_api_permission_sid": rec_sid or "sas-records-api-invoke",
    "cloudfront_origin_id": origin_id,
    "cloudfront_oac_name": oac_name,
    "cloudfront_web_acl_id": web_acl,
    "budget_name": budget_name,
    "records_route_integrations": route_integrations,
    "automation_rule_orders": orders,
}}
with open(os.path.join(TF, "discovered.auto.tfvars.json"), "w") as f:
    json.dump(discovered, f, indent=2)

with open(os.path.join(TF, "imports.tf"), "w") as f:
    f.write("# Generated by scripts/discover.py. Account-specific; gitignored.\n"
            "# After the first successful apply these blocks do nothing and can be deleted.\n\n")
    for to, id_ in imports:
        f.write(f'import {{\n  to = {to}\n  id = "{id_}"\n}}\n\n')

with open(os.path.join(TF, "backend.hcl"), "w") as f:
    f.write(f'bucket       = "{buckets["evidence"]}"\n'
            f'key          = "terraform/sas.tfstate"\n'
            f'region       = "{REGION}"\n'
            f'encrypt      = true\n'
            f'kms_key_id   = "{key_arn}"\n'
            f'use_lockfile = true\n')

print(f"\nwrote {len(imports)} import blocks, discovered.auto.tfvars.json and backend.hcl")
if warnings:
    print(f"{len(warnings)} warning(s) above. Review before terraform plan.")
    sys.exit(1)
