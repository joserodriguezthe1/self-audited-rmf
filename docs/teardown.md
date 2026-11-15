# Teardown runbook

How to take the system down and leave the AWS account with no ongoing charges. This is the procedure used on 2026-11-15, including the problems hit along the way, so the next run goes cleanly.

Teardown deletes every piece of evidence, every log and every backup. Download anything you want to keep first, such as the latest OSCAL assessment results and POA&M from the evidence bucket.

## Before you start

1. **Cancel the CloudFront pricing plan.** In the console, open CloudFront, select the distribution, and cancel its pricing plan. AWS refuses to delete a distribution that is still subscribed to a plan (`PreconditionFailed: You can't delete this distribution while it's subscribed to a pricing plan`).
2. **Save what you want to publish.** For example, `oscal/ar/latest.json` and `oscal/poam/latest.json` from the evidence bucket. Replace the account ID with a placeholder before you commit them.
3. Open CloudShell in us-east-1 with the repo and `terraform/backend.hcl` in place.

## Run

```bash
bash scripts/teardown.sh
```

It asks for the account ID as confirmation, then runs nine steps. It stops at the first failure and is safe to re-run.

| Step | What it does | Why |
| --- | --- | --- |
| 1 | Pulls state to `sas-final.tfstate` and moves the backend to local | State lives in the evidence bucket, which step 5 empties |
| 2 | Stops CloudTrail logging and the Config recorder | Otherwise they keep writing into buckets being emptied |
| 3 | Turns off DynamoDB deletion protection | Destroy fails on protected tables |
| 4 | Deletes backup recovery points | A vault with recovery points cannot be deleted |
| 5 | Empties all five buckets, every version | Versioned buckets cannot be deleted with objects in them. Object Lock is bypassed only on locked buckets |
| 6 | Removes the free account-wide guardrails from state | Keeps the password policy, S3 public access block, EBS default encryption, SSM settings and security contact in place. Set `KEEP_GUARDRAILS=0` to delete them too |
| 7 | Plans the destroy, stops if a guardrail would be deleted, empties the access logs bucket, applies, and retries once | The access logs bucket refills until CloudFront and the other buckets are gone |
| 8 | Deletes the WAF web ACL CloudFront created, disables Inspector, shortens the KMS deletion window to 7 days | Terraform does not manage these |
| 9 | Lists anything left | Blank output means clean |

## Problems hit on the first run

| Problem | Cause | Fix now in the script |
| --- | --- | --- |
| `state pull` failed | CloudShell's `/tmp` had been cleared, so Terraform had no modules or backend config | Runs `terraform init` with `backend.hcl` before pulling, and stops if the pull is empty |
| Emptying crashed on a bucket | `BypassGovernanceRetention` was sent to a bucket without Object Lock | Checks each bucket's Object Lock setting first |
| Destroy did nothing, but later steps ran | The script did not stop on errors | `set -euo pipefail` and an explicit check that state is empty |
| The KMS key was scheduled for deletion while Terraform still managed it | Step 8 ran even though step 7 had failed | Only touches a key already in `PendingDeletion`, and step 8 runs only after state is empty |
| CloudFront deletion failed with `PreconditionFailed` | The distribution was on the Free pricing plan | Cancel the plan before starting; the script names the fix if it sees this error |
| Access logs bucket failed with `BucketNotEmpty` | New log objects arrived after step 5 | Empties it again right before each destroy attempt |

The KMS key was recovered with `aws kms cancel-key-deletion` and `aws kms enable-key` before the destroy was re-run.

## After

- The KMS key is deleted 7 days later. It costs a few cents until then.
- Check Billing the next day and again after the key is gone.
- Kept on purpose (free): the account guardrails from step 6 and any zero-spend budget created outside Terraform.
- `sas-final.tfstate` contains resource IDs and the account ID. Keep it out of git; `.gitignore` already covers `*.tfstate`.
