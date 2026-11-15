# Risk acceptance register (RA-7)

Each acceptance is a Security Hub automation rule (`terraform/monitoring.tf`, `local.risk_acceptances`). The rule suppresses matching findings and writes the justification below into the finding's note. The evidence pipeline reports affected controls as `risk-accepted`, and the chat quotes the note when asked.

Recorded by the system owner on 2026-11-14. Review all items by 2027-05-14 or when the system changes.

| Rule | Check | Scope | Justification |
| --- | --- | --- | --- |
| sas-accept-account-2 | Account.2 | Account | Single-account system by design. Joining AWS Organizations ends Free Tier credits. Compensating: budget alerts, CloudTrail, Config. |
| sas-accept-macie-1 | Macie.1 | Account | System stores only synthetic test records, no PII or CUI. Re-evaluate before any real data is introduced. |
| sas-accept-s3-7 | S3.7 | All buckets | Single-region system by design. Versioning and AWS Backup provide recovery. |
| sas-accept-s3-20 | S3.20 | All buckets | MFA delete requires root credentials on the CLI, and routine root use is prohibited. Versioning and Object Lock compensate. |
| sas-accept-lambda-3 | Lambda.3 | All functions | Functions call only AWS APIs over TLS and reach no private network resources. A VPC would add NAT cost with no security gain. |
| sas-accept-s3-15-data | S3.15 | sas-data | Object Lock is applied where integrity is required (log and evidence buckets, AU-9). Data bucket relies on versioning and AWS Backup. |
| sas-accept-s3-15-accesslogs | S3.15 | sas-accesslogs | Same as above. Access-log bucket relies on versioning. |
| sas-accept-s3-15-web | S3.15 | sas-web | Static site assets only, rebuilt from Git on every deploy. Versioning covers recovery. |
| sas-accept-s3-17-accesslogs | S3.17 | sas-accesslogs | S3 server access log delivery requires SSE-S3 on the destination bucket. |
| sas-accept-s3-9-accesslogs | S3.9 | sas-accesslogs | Logging the access-log bucket to itself would create a delivery loop. Bucket activity is captured by CloudTrail. |

## Other accepted items

| Item | Justification |
| --- | --- |
| Security contact phone | The account security contact uses the owner's real email; the phone number is intentionally withheld. Email is the contact path. Found during Terraform adoption on 2026-11-15, when the contact was found to still hold placeholder values; the email was corrected through Terraform. |

## Pre-deployment exceptions (Checkov)

Checkov skips are written inline in the Terraform next to the resource, each with its reason, so every exception is visible in code review. Run `grep -rn "checkov:skip" terraform/` to list them. Skips that are planned work point to an item in [poam.md](poam.md).
