#!/usr/bin/env bash
# Tear down the Self-Audited System and leave the AWS account clean.
# Run from the repo root in CloudShell:   bash scripts/teardown.sh
# Read docs/teardown.md first. This deletes all evidence, logs, and backups.
#
# Safe to re-run: every step checks before it acts, and the script stops at the
# first failure instead of carrying on with a half-finished teardown.
#
# Before you start: cancel the CloudFront pricing plan in the console
# (CloudFront > Distributions > your distribution > Pricing plan). AWS will not
# delete a distribution that is still subscribed to a plan.
set -euo pipefail
set +H

export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-east-1}
ACCT=$(aws sts get-caller-identity --query Account --output text)
KEEP_GUARDRAILS=${KEEP_GUARDRAILS:-1}   # 1 = keep free account-wide security settings
export AWS_PAGER=""
export TF_DATA_DIR=${TF_DATA_DIR:-/tmp/tfdata}
cd "$(dirname "$0")/../terraform"

echo "Account $ACCT. This permanently deletes the SAS system, its evidence, logs and backups."
read -r -p "Type the account ID to continue: " CONFIRM
[ "$CONFIRM" = "$ACCT" ] || { echo "Cancelled."; exit 1; }

step() { echo; echo "==== $*"; }

# Empties the named buckets, every version and delete marker. Only passes
# BypassGovernanceRetention to buckets that actually have Object Lock on.
empty_buckets() {
python3 - "$ACCT" "$@" <<'EOF'
import sys, boto3
from botocore.exceptions import ClientError
acct, kinds = sys.argv[1], sys.argv[2:]
s3 = boto3.client("s3")
for k in kinds:
    b = f"sas-{k}-{acct}"
    try:
        s3.head_bucket(Bucket=b)
    except ClientError:
        print(f"{b}: not found, skipping"); continue
    try:
        locked = s3.get_object_lock_configuration(Bucket=b)["ObjectLockConfiguration"].get("ObjectLockEnabled") == "Enabled"
    except ClientError:
        locked = False
    extra = {"BypassGovernanceRetention": True} if locked else {}
    n = 0
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=b):
        objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        for i in range(0, len(objs), 1000):
            r = s3.delete_objects(Bucket=b, Delete={"Objects": objs[i:i+1000], "Quiet": True}, **extra)
            if r.get("Errors"):
                sys.exit(f"{b}: {r['Errors'][0]}")
            n += len(objs[i:i+1000])
    print(f"{b}: deleted {n} object versions" + (" (Object Lock bypassed)" if locked else ""))
EOF
}

step "1/9 Move Terraform state out of the evidence bucket (it is about to be emptied)"
if grep -q '^  backend "s3" {}' versions.tf; then
  terraform init -input=false -backend-config=backend.hcl >/dev/null
  terraform state pull > ../sas-final.tfstate
  [ -s ../sas-final.tfstate ] || { echo "State pull came back empty. Stopping."; exit 1; }
  sed -i 's/^  backend "s3" {}/  # backend "s3" {}  (disabled for teardown)/' versions.tf
  terraform init -migrate-state -force-copy -input=false >/dev/null
  echo "state is now local ($(terraform state list | wc -l) resources); backup at ../sas-final.tfstate"
else
  terraform init -input=false >/dev/null
  echo "backend already local ($(terraform state list | wc -l) resources)"
fi

step "2/9 Stop new writes: CloudTrail logging, Config recorder"
aws cloudtrail stop-logging --name sas-trail 2>/dev/null && echo "trail stopped" || echo "trail already gone"
REC=$(aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[0].name' --output text)
if [ "$REC" != "None" ]; then
  aws configservice stop-configuration-recorder --configuration-recorder-name "$REC" && echo "recorder stopped"
fi

step "3/9 Remove DynamoDB deletion protection"
for t in records control_status; do
  aws dynamodb update-table --table-name $t --no-deletion-protection-enabled \
    --query 'TableDescription.TableName' --output text 2>/dev/null || echo "$t already gone"
done

step "4/9 Delete backup recovery points"
python3 - <<'EOF'
import boto3
b = boto3.client("backup"); v = "sas-backup-vault"; n = 0
try:
    for page in b.get_paginator("list_recovery_points_by_backup_vault").paginate(BackupVaultName=v):
        for rp in page["RecoveryPoints"]:
            b.delete_recovery_point(BackupVaultName=v, RecoveryPointArn=rp["RecoveryPointArn"]); n += 1
    print(f"deleted {n} recovery points")
except b.exceptions.ResourceNotFoundException:
    print("vault already gone")
EOF

step "5/9 Empty all five buckets"
empty_buckets logs accesslogs data evidence web

if [ "$KEEP_GUARDRAILS" = "1" ]; then
  step "6/9 Keep free account-wide guardrails (password policy, S3 public block, EBS encryption, SSM, contact)"
  for r in aws_iam_account_password_policy.this aws_s3_account_public_access_block.this \
           aws_ebs_encryption_by_default.this aws_ssm_service_setting.doc_public_sharing \
           aws_ssm_service_setting.automation_log_destination aws_ssm_service_setting.automation_log_group \
           aws_cloudwatch_log_group.ssm_automation aws_account_alternate_contact.security; do
    if terraform state list | grep -qx "$r"; then terraform state rm "$r" >/dev/null && echo "kept $r"; fi
  done
else
  step "6/9 Guardrails will be removed too (KEEP_GUARDRAILS=0)"
fi

step "7/9 terraform destroy (CloudFront takes a few minutes to disable and delete)"
terraform plan -destroy -out=destroy.tfplan -input=false -no-color | tail -1
# With KEEP_GUARDRAILS=1, no guardrail should appear in the plan. Stop if one does.
[ "$KEEP_GUARDRAILS" = "1" ] && OUTSIDE=$(terraform show -json destroy.tfplan | python3 -c '
import json, sys
p = json.load(sys.stdin)
for rc in p.get("resource_changes", []):
    if "delete" in rc["change"]["actions"] and rc["address"].startswith(("aws_iam_account", "aws_s3_account", "aws_ebs_", "aws_account_", "aws_ssm_service_setting", "aws_cloudwatch_log_group.ssm_automation")):
        print(rc["address"])') || OUTSIDE=""
[ -z "${OUTSIDE:-}" ] || { echo "Plan would delete guardrails: $OUTSIDE. Stopping."; exit 1; }

# The access logs bucket keeps filling until CloudFront and the other buckets
# are gone, so empty it right before each attempt and retry once.
for attempt in 1 2; do
  empty_buckets accesslogs
  if terraform apply -input=false -no-color destroy.tfplan 2>&1 | tee /tmp/destroy-run.txt | grep -E "Apply complete|Error"; then :; fi
  [ "$(terraform state list | grep -vc '^data\.')" = "0" ] && break
  echo "Resources left after attempt $attempt:"; terraform state list | grep -v '^data\.'
  if grep -q "pricing plan" /tmp/destroy-run.txt; then
    echo "Cancel the CloudFront pricing plan in the console, then re-run this script."; exit 1
  fi
  terraform plan -destroy -out=destroy.tfplan -input=false -no-color | tail -1
done
[ "$(terraform state list | grep -vc '^data\.')" = "0" ] || { echo "Destroy did not finish. See /tmp/destroy-run.txt"; exit 1; }

step "8/9 Clean up what Terraform does not manage"
WACL=$(aws wafv2 list-web-acls --scope CLOUDFRONT --region us-east-1 \
  --query "WebACLs[?starts_with(Name,'CreatedByCloudFront')].[Name,Id,LockToken] | [0]" --output text)
if [ -n "$WACL" ] && [ "$WACL" != "None" ]; then
  read -r WN WID WLT <<< "$WACL"
  aws wafv2 delete-web-acl --scope CLOUDFRONT --region us-east-1 --name "$WN" --id "$WID" --lock-token "$WLT" \
    && echo "deleted web ACL $WN"
fi
aws inspector2 disable --resource-types EC2 ECR LAMBDA LAMBDA_CODE --query 'accounts[0].status' --output text 2>/dev/null \
  && echo "Inspector disabled" || true
# Terraform schedules the key with a 30-day window. Shorten it to 7, and only
# for a key that Terraform has already put into PendingDeletion.
KEY=$(aws kms list-keys --query 'Keys[].KeyId' --output text | tr '\t' '\n' | while read -r k; do
  d=$(aws kms describe-key --key-id "$k" --query 'KeyMetadata.[Description,KeyState]' --output text)
  case "$d" in *"Self-Audited System"*PendingDeletion*) echo "$k";; esac; done | head -1)
if [ -n "$KEY" ]; then
  aws kms cancel-key-deletion --key-id "$KEY" >/dev/null
  aws kms schedule-key-deletion --key-id "$KEY" --pending-window-in-days 7 --query DeletionDate --output text
  echo "KMS key deletion moved to the 7-day minimum"
fi

step "9/9 Verify the account is clean"
echo "-- buckets";       aws s3api list-buckets --query "Buckets[?starts_with(Name,'sas')].Name" --output text
echo "-- tables";        aws dynamodb list-tables --query "TableNames" --output text | tr '\t' '\n' | grep -E '^(records|control_status)$' || true
echo "-- functions";     aws lambda list-functions --query "Functions[].FunctionName" --output text | tr '\t' '\n' | grep -E 'records-api|sas-' || true
echo "-- distributions"; aws cloudfront list-distributions --query "DistributionList.Items[].Id" --output text
echo "-- trails";        aws cloudtrail describe-trails --query "trailList[].Name" --output text
echo "-- config";        aws configservice describe-configuration-recorders --query "ConfigurationRecorders[].name" --output text
echo "-- security hub";  aws securityhub describe-hub --query HubArn --output text 2>/dev/null || echo "not subscribed"
echo "-- cognito";       aws cognito-idp list-user-pools --max-results 20 --query "UserPools[?starts_with(Name,'sas')].Name" --output text
echo "-- apis";          aws apigatewayv2 get-apis --query "Items[?starts_with(Name,'sas')].Name" --output text
echo "-- vaults";        aws backup list-backup-vaults --query "BackupVaultList[?starts_with(BackupVaultName,'sas')].BackupVaultName" --output text
echo "-- log groups";    aws logs describe-log-groups --query "logGroups[].logGroupName" --output text
echo "-- waf";           aws wafv2 list-web-acls --scope CLOUDFRONT --region us-east-1 --query "WebACLs[].Name" --output text
echo
echo "Done. Blank lines above mean clean (distributions may print None)."
echo "State backup: ../sas-final.tfstate. Check Billing tomorrow and after the KMS key is deleted."
