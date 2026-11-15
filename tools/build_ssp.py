"""Build the OSCAL 1.1.3 System Security Plan and Assessment Plan for SAS.

Every Moderate control gets an implemented-requirement. Controls this system implements
directly carry a specific statement below; the rest are stated by how they are covered
(inherited from AWS, policy attestation, or automated check / manual assessment), matching
src/evidence_pipeline/control-map.json so the SSP and the daily assessment never disagree.

Usage: python tools/build_ssp.py      (writes oscal/ssp/sas-ssp.json and oscal/ap/sas-ap.json)
"""
import json
import os
import uuid

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
NS = uuid.UUID("6f1c2d4e-8a3b-4c5d-9e7f-0a1b2c3d4e5f")
U = lambda name: str(uuid.uuid5(NS, name))  # stable UUIDs so diffs stay readable
DATE = "2026-11-15T00:00:00+00:00"
PROFILE = ("https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/"
           "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json")

catalog = json.load(open(os.path.join(ROOT, "oscal/catalog/moderate_controls.json")))
cmap = json.load(open(os.path.join(ROOT, "src/evidence_pipeline/control-map.json")))

C_THIS, C_AWS, C_SH = U("component-this-system"), U("component-aws"), U("component-securityhub")

# Specific implementation statements, written from the build record. (state, statement)
SPECIFIC = {
    "ac-2": ("implemented", "IAM principals are limited to one administrator user (MFA, rights through the admins group only) and five service roles, each defined in Terraform. Web users exist only in the sas-users Cognito pool, where only an administrator can create accounts. Unused access keys are removed; IAM.3 and IAM.8 monitor this daily."),
    "ac-3": ("implemented", "Every API route requires authorization: the records API uses IAM (SigV4) and the chat API uses a Cognito JWT authorizer. S3 Block Public Access is on at the account level and on every bucket. The web bucket is readable only by one CloudFront distribution through origin access control."),
    "ac-6": ("implemented", "Each Lambda function has its own role whose policy names exact resources (one table, one bucket, one key, its own log group). The chat role is read-only and may invoke only Anthropic models on Bedrock. Enforced in review by Checkov and in operation by Security Hub IAM checks."),
    "ac-6.9": ("implemented", "All privileged API activity is recorded by the multi-region CloudTrail trail sas-trail."),
    "au-2": ("implemented", "Logged events: all AWS management API calls (CloudTrail, read and write), API Gateway access logs for both APIs, S3 server access logs for every data bucket, Lambda execution logs, and every chat question with the asking user, the tools used, and the answer."),
    "au-3": ("implemented", "Records include time, source, identity, action, and outcome: CloudTrail events natively; API access logs record request ID, source IP, authenticated user, route, status, and latency; chat logs record user, channel, question, tool calls, and answer."),
    "au-6": ("partial", "Audit records are centralized in CloudWatch Logs and the sas-logs bucket and analyzed daily through Security Hub findings and the evidence pipeline. Routine human review of raw logs is not yet scheduled (POA&M)."),
    "au-9": ("implemented", "CloudTrail log file validation is on and digest files are delivered. The log bucket uses S3 Object Lock in governance mode with 365-day retention, versioning, SSE-KMS with the system key, and a TLS-only bucket policy."),
    "au-11": ("implemented", "Organization-defined retention: 365 days for every CloudWatch log group; log buckets keep objects 400 days under Object Lock. Enforced before deployment by the AU-11 Rego rule."),
    "au-12": ("implemented", "CloudTrail, API Gateway access logging, S3 server access logging, and X-Ray tracing are enabled on every component and defined in Terraform."),
    "ca-2": ("implemented", "A daily automated assessment (sas-evidence-pipeline) evaluates every Moderate control and writes OSCAL assessment results to the evidence bucket. Break-and-fix tests are recorded in docs/test-record.md."),
    "ca-5": ("implemented", "The pipeline writes an OSCAL POA&M on every run: one item per not-satisfied control, first-seen date retained, scheduled completion 30 days out, closed automatically when the control is satisfied. Manually tracked items are in docs/poam.md."),
    "ca-7": ("implemented", "AWS Config records all resources continuously; Security Hub CSPM runs the NIST SP 800-53 Rev 5 standard; the evidence pipeline runs daily at 07:30 America/New_York. Measured: a public-access change was detected in about 6 minutes and recovery confirmed in about 4."),
    "cm-2": ("implemented", "The baseline configuration is the Terraform in this repository. All live resources were imported, so terraform plan reports drift from the baseline."),
    "cm-3": ("implemented", "Changes go through Git and CI (fmt, validate, Checkov, Rego, Bandit, OSCAL validation) before apply. Terraform state versions are retained under Object Lock in the evidence bucket as a change record."),
    "cm-6": ("implemented", "Configuration settings are enforced in Terraform and checked by Checkov and the SAS Rego rules before deployment, and by Security Hub after deployment."),
    "cm-8": ("implemented", "Every resource carries the tags Project=self-audited-rmf and Boundary=sas through provider default tags (enforced by the CM-8 Rego rule). AWS Config records the inventory of all resource types."),
    "cp-9": ("implemented", "Both DynamoDB tables have point-in-time recovery and deletion protection, and are backed up daily by AWS Backup (plan sas-daily, 35-day retention, vault encrypted with the system key). All buckets are versioned."),
    "ia-2": ("implemented", "Administrators authenticate as the IAM user with MFA. Web users authenticate through Cognito. Service access uses IAM roles only; no long-lived access keys exist."),
    "ia-2.1": ("partial", "MFA is required for the administrator and for every Cognito user (TOTP). The root user has MFA but not a hardware key (POA&M-01)."),
    "ia-5": ("implemented", "Authenticators are managed by IAM and Cognito; temporary Cognito passwords expire after 3 days; no access keys are issued."),
    "ia-5.1": ("implemented", "Organization-defined parameters: minimum 14 characters with upper, lower, number, and symbol; 24 passwords remembered; no forced expiry (NIST SP 800-63B). Enforced in IAM and Cognito, tested by Security Hub IAM.7 with custom parameters, and checked in Terraform by the IA-5(1) Rego rules."),
    "ra-5": ("implemented", "Amazon Inspector scans Lambda functions; Security Hub CSPM evaluates configuration continuously; Checkov and Bandit scan code in CI."),
    "ra-7": ("implemented", "Risk responses are recorded as Security Hub automation rules that suppress the finding and attach the justification. Ten acceptances are on record (docs/risk-register.md); the assessment reports these controls as risk-accepted."),
    "sc-5": ("implemented", "API Gateway throttling: records API 10 requests/second (burst 20); chat API 5 (burst 10). Enforced by the SC-5 Rego rule."),
    "sc-7": ("implemented", "The boundary is one AWS account in us-east-1 with no VPC, no compute instances, and no public buckets. Entry points are two API Gateway endpoints (authorized) and one CloudFront distribution serving a static page."),
    "sc-8": ("implemented", "All S3 bucket policies deny requests without TLS. CloudFront redirects HTTP to HTTPS. API Gateway and AWS APIs are TLS-only."),
    "sc-12": ("implemented", "One customer managed KMS key (alias sas-key) with automatic annual rotation. Its key policy grants use only to the administrator and to named services scoped by source ARN or account."),
    "sc-13": ("implemented", "Encryption uses AWS KMS (FIPS 140-validated HSMs) and TLS provided by AWS services."),
    "sc-28": ("implemented", "Data at rest is encrypted with the system CMK: all buckets except the access-log bucket (SSE-S3, required for log delivery, risk accepted), both DynamoDB tables, CloudTrail logs, Config delivery, and the backup vault."),
    "sc-28.1": ("implemented", "See SC-28. Cryptographic protection uses AES-256 through AWS KMS."),
    "si-4": ("partial", "Security Hub CSPM, AWS Config, and Amazon Inspector monitor the system. GuardDuty threat detection is planned (POA&M-02)."),
    "si-7": ("implemented", "Evidence files are stored with a SHA-256 hash and re-hashed on every chat request. CloudTrail log file validation detects log tampering. Object Lock prevents alteration of logs and evidence for 365 days."),
    "si-7.1": ("implemented", "Integrity checks run on every evidence read (chat get_evidence) and daily through CloudTrail digest delivery."),
}


def source_for(cid):
    if cid in cmap["controls"]:
        return cmap["controls"][cid].get("source")
    if cid.split(".")[0].endswith("-1"):
        return "attestation"
    if cid.split("-")[0] in cmap["family_defaults"]:
        return cmap["family_defaults"][cid.split("-")[0]]["source"]
    return "auto"


def requirement(cid):
    src = source_for(cid)
    if cid in SPECIFIC:
        state, text = SPECIFIC[cid]
        comps = [(C_THIS, text, state), (C_SH, "Assessed daily by Security Hub CSPM where checks map to this control.", "implemented")]
    elif src == "inherited":
        comps = [(C_AWS, "Inherited from AWS (data center physical, environmental, and media controls) under the AWS FedRAMP authorization.", "implemented")]
    elif src == "attestation":
        comps = [(C_THIS, "Policy and procedures to be documented, approved, and recorded as a dated attestation (attestations/<control>.json in the evidence bucket). Until then the assessment reports this control not-satisfied.", "planned")]
    else:
        comps = [(C_THIS, "Covered where Security Hub CSPM checks map to this control; otherwise requires manual assessment. Current state is in the latest OSCAL assessment results.", "partial")]
    return {
        "uuid": U(f"req-{cid}"),
        "control-id": cid,
        "props": [{"name": "control-origination", "value": "inherited" if src == "inherited" else "sp-system"}],
        "by-components": [{
            "uuid": U(f"bc-{cid}-{c}"),
            "component-uuid": c,
            "description": d,
            "implementation-status": {"state": s},
        } for c, d, s in comps],
    }


party = U("party-system-owner")
role_owner = "system-owner"
metadata = lambda title: {
    "title": title, "last-modified": DATE, "version": "1.0.0", "oscal-version": "1.1.3",
    "roles": [{"id": role_owner, "title": "System Owner"}],
    "parties": [{"uuid": party, "type": "person", "name": "Jose Rodriguez"}],
    "responsible-parties": [{"role-id": role_owner, "party-uuids": [party]}],
}

ssp = {"system-security-plan": {
    "uuid": U("ssp"),
    "metadata": metadata("Self-Audited System (SAS) System Security Plan"),
    "import-profile": {"href": PROFILE},
    "system-characteristics": {
        "system-ids": [{"identifier-type": "https://ietf.org/rfc/rfc4122", "id": U("system")}],
        "system-name": "Self-Audited System",
        "system-name-short": "SAS",
        "description": "A serverless AWS system that assesses itself daily against the NIST SP 800-53 Rev 5 Moderate baseline, records the results as OSCAL with hash-verified evidence, and answers control questions through an AI chat that can only cite that evidence.",
        "security-sensitivity-level": "moderate",
        "system-information": {"information-types": [{
            "uuid": U("info-type-records"),
            "title": "Internal records (synthetic test data)",
            "description": "Records created through the records API. Synthetic data only; no PII, PHI, or CUI.",
            "confidentiality-impact": {"base": "moderate"},
            "integrity-impact": {"base": "moderate"},
            "availability-impact": {"base": "low"},
        }]},
        "security-impact-level": {
            "security-objective-confidentiality": "moderate",
            "security-objective-integrity": "moderate",
            "security-objective-availability": "low",
        },
        "status": {"state": "operational"},
        "authorization-boundary": {"description": "One AWS account in us-east-1. Inside: the records API (API Gateway, Lambda, DynamoDB, S3), the logging and encryption foundation (CloudTrail, CloudWatch Logs, KMS), the evidence plane (Config, Security Hub CSPM, the evidence pipeline, evidence bucket, status table, AWS Backup), and the chat plane (chat Lambda, Bedrock, Cognito, chat API, CloudFront and the web bucket). Outside: AWS itself (leveraged provider), administrator workstations, and GitHub."},
    },
    "system-implementation": {
        "users": [
            {"uuid": U("user-admin"), "title": "Administrator", "role-ids": [role_owner],
             "props": [{"name": "type", "value": "internal"}, {"name": "privilege-level", "value": "privileged"}]},
            {"uuid": U("user-web"), "title": "Chat user",
             "props": [{"name": "type", "value": "internal"}, {"name": "privilege-level", "value": "non-privileged"}]},
        ],
        "components": [
            {"uuid": C_THIS, "type": "this-system", "title": "Self-Audited System",
             "description": "All resources defined in this repository's Terraform.", "status": {"state": "operational"}},
            {"uuid": C_AWS, "type": "service", "title": "Amazon Web Services (leveraged)",
             "description": "Cloud service provider. Physical, environmental, and media protections are inherited.",
             "status": {"state": "operational"}},
            {"uuid": C_SH, "type": "service", "title": "AWS Security Hub CSPM (NIST SP 800-53 Rev 5 standard)",
             "description": "Automated control checks. Findings are the primary automated assessment input.",
             "status": {"state": "operational"}},
        ],
    },
    "control-implementation": {
        "description": "Implementation of the NIST SP 800-53 Rev 5 Moderate baseline. Status is assessed daily; see oscal/samples and the evidence bucket for current results.",
        "implemented-requirements": [requirement(c) for c in sorted(catalog)],
    },
}}

ap = {"assessment-plan": {
    "uuid": U("ap"),
    "metadata": metadata("SAS Automated Assessment Plan"),
    "import-ssp": {"href": "../ssp/sas-ssp.json"},
    "local-definitions": {"activities": [
        {"uuid": U("act-securityhub"), "title": "Automated configuration testing",
         "description": "Security Hub CSPM NIST SP 800-53 Rev 5 checks, collected daily by sas-evidence-pipeline.",
         "props": [{"name": "method", "value": "TEST"}]},
        {"uuid": U("act-attestation"), "title": "Policy attestation review",
         "description": "Examine attestation records for xx-1 controls; reviews older than 365 days fail.",
         "props": [{"name": "method", "value": "EXAMINE"}]},
        {"uuid": U("act-precommit"), "title": "Pre-deployment policy checks",
         "description": "Checkov and SAS Rego rules evaluate Terraform in CI before any change deploys.",
         "props": [{"name": "method", "value": "TEST"}]},
    ]},
    "reviewed-controls": {"control-selections": [{"include-all": {}}]},
}}

os.makedirs(os.path.join(ROOT, "oscal/ssp"), exist_ok=True)
os.makedirs(os.path.join(ROOT, "oscal/ap"), exist_ok=True)
json.dump(ssp, open(os.path.join(ROOT, "oscal/ssp/sas-ssp.json"), "w"), indent=2)
json.dump(ap, open(os.path.join(ROOT, "oscal/ap/sas-ap.json"), "w"), indent=2)
states = {}
for r in ssp["system-security-plan"]["control-implementation"]["implemented-requirements"]:
    for bc in r["by-components"]:
        if bc["component-uuid"] != C_SH:
            states[bc["implementation-status"]["state"]] = states.get(bc["implementation-status"]["state"], 0) + 1
print(f"SSP: {len(catalog)} requirements, {len(SPECIFIC)} with specific statements, states {states}")
