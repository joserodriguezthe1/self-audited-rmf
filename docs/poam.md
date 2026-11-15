# Plan of action and milestones (CA-5)

Automated findings get POA&M items without anyone writing them: every daily run writes `oscal/poam/latest.json` to the evidence bucket, opens an item for each not-satisfied control, and closes it when the control passes. The items below are tracked by hand because no automated check raises them, or because they need a decision first.

| ID | Weakness | Control | Milestone | Target |
| --- | --- | --- | --- | --- |
| POA&M-01 | Root user MFA is not a hardware key (Security Hub IAM.6) | IA-2(1) | Buy and register a FIDO2 key | 2026-12-15 |
| POA&M-02 | GuardDuty threat detection is off (GuardDuty.1) | SI-4 | Enable during the 30-day trial window before the demo, then decide on cost | 2026-12-15 |
| POA&M-03 | CloudWatch log groups use default encryption, not the system CMK | AU-9, SC-28 | Add CloudWatch Logs to the key policy and set `kms_key_id` on every log group | 2026-12-31 |
| POA&M-04 | The CloudFront distribution has a web ACL (created with the CloudFront plan) whose rules have not been reviewed | SC-7, SI-4 | Review the rule set, confirm it blocks known-bad inputs, and record it in the SSP | 2027-01-31 |
| POA&M-05 | No CloudFront access logs or security response headers policy | AU-2, SC-8 | Attach the managed SecurityHeadersPolicy and enable standard logging | 2026-12-31 |
| POA&M-06 | Lambda code signing not configured | CM-14, SI-7 | Add an AWS Signer profile and code signing config | 2027-01-31 |
| POA&M-07 | No dead-letter handling for the evidence pipeline | SI-11 | Add an SQS DLQ or an on-failure destination with an alarm | 2027-01-31 |
| POA&M-08 | Chat API requests time out at 30 seconds on long questions | SC-5 (availability) | Stream responses or move long questions to an async pattern | 2027-01-31 |
| POA&M-09 | 190 Moderate controls have no automated check | CA-2 | Write custom checks or manual assessment procedures, family by family | 2027-03-31 |
| POA&M-10 | Policy and procedure (xx-1) controls lack attestations | xx-1 | Write each policy, record a dated attestation in the evidence bucket | 2027-02-28 |
| POA&M-11 | Audit logs are not reviewed by a person on a schedule | AU-6 | Weekly review of CloudTrail and chat logs, recorded as an attestation | 2027-01-15 |
| POA&M-12 | S3 event notifications are not configured on the five buckets (Security Hub S3.11) | AU-12, SI-4 | Send object-level events (delete, lifecycle expiration, replication failure) to EventBridge and alert on deletes in the evidence bucket | 2027-01-31 |
