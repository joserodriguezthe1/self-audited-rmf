# Continuous monitoring test record (CA-2, CA-7)

## Test 1: drift detection on the data bucket (2026-11-14)

**Objective.** Show that a security-relevant configuration change is detected, recorded as evidence, and reported by the chat without anyone looking for it, then that the fix is confirmed the same way.

**Method.** Removed S3 Block Public Access from `sas-data` (the account-level block stayed on, so no data was exposed). Waited for Security Hub check S3.8, ran the evidence pipeline, asked the chat about AC-3. Then restored the setting and repeated.

| Time (UTC) | Event | AC-3 checks | Evidence file (sha256) |
| --- | --- | --- | --- |
| 20:02:59 | Baseline run | 71 passed, 8 failed | `c7291a82...` |
| 20:03:47 | Block Public Access removed | | |
| 20:10:01 | Security Hub reports S3.8 FAILED | | |
| 20:10:06 | Pipeline records it; chat lists S3.8 first under AC-3 | 70 passed, 9 failed | `5e49ae97...` |
| ~20:10:30 | Block Public Access restored | | |
| 20:14:23 | Security Hub reports S3.8 PASSED | | |
| 20:14:27 | Pipeline records recovery; S3.8 gone from AC-3 | 71 passed, 8 failed | `2114edbc...` |

**Result.** Change to detection: about 6 minutes. Fix to confirmed recovery: about 4 minutes. Each state is a separate, hash-verified evidence file under Object Lock.

## Test 2: evidence integrity

The chat's `get_evidence` tool re-hashes the S3 object on every request and compares it to the hash recorded at collection. Observed on 2026-11-14: recorded and recomputed SHA-256 matched (`f2c02491...`), reported as verified.

## Test 3: risk acceptance is reflected in the assessment

Ten Security Hub automation rules were created with justifications. On the next run, risk-accepted controls rose from 0 to 8 and not-satisfied fell from 59 to 51. Asked which controls are risk-accepted, the chat listed them and quoted the justification text.

## Test 4: configuration drift caught by the assessment

The SSP sets IA-5(1) at 14 characters with symbols and numbers. Security Hub IAM.7 failed on 2026-11-14 because the live policy did not require symbols or numbers. Corrected the same day; IAM.7 now runs with custom parameters matching the SSP.

## Test 5: Terraform adoption found an evidence gap (2026-11-15)

Importing the account into Terraform showed the security contact still held placeholder values. Security Hub Account.1 had passed because it checks only that a contact exists. The email was corrected through Terraform. Lesson recorded: an automated pass confirms presence, not accuracy.
