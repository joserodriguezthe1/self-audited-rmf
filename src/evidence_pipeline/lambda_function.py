"""SAS evidence pipeline.

Runs daily (EventBridge Scheduler) or on demand. One run:
  1. Pulls every active Security Hub CSPM finding mapped to NIST SP 800-53 Rev 5.
  2. Stores the raw findings unchanged in the evidence bucket with their SHA-256.
  3. Decides a state for every Moderate control (control-map.json + findings + attestations).
  4. Writes an OSCAL 1.1.3 assessment-results file and an OSCAL POA&M.
  5. Writes one row per control to the control_status DynamoDB table for the chat.

Environment variables:
  EVIDENCE_BUCKET  sas-evidence-<account-id>
  STATUS_TABLE     control_status
  SYSTEM_NAME      Self-Audited System (SAS)        (optional)
  POAM_DAYS        days to remediate an automated finding (optional, default 30)
"""
import datetime as dt
import hashlib
import json
import os
import re
import uuid

import boto3

s3 = boto3.client("s3")
sh = boto3.client("securityhub")
ddb = boto3.resource("dynamodb")

BUCKET = os.environ.get("EVIDENCE_BUCKET", "")
TABLE = os.environ.get("STATUS_TABLE", "control_status")
SYSTEM_NAME = os.environ.get("SYSTEM_NAME", "Self-Audited System (SAS)")
POAM_DAYS = int(os.environ.get("POAM_DAYS", "30"))
OSCAL_VERSION = "1.1.3"
NS = "https://github.com/joserodriguezthe1/self-audited-rmf/ns"
UUID_NS = uuid.UUID("6f1c2d4e-8a3b-4c5d-9e7f-0a1b2c3d4e5f")
HERE = os.path.dirname(os.path.abspath(__file__))


def find_file(name):
    """Packaged Lambda: next to this file. Repo checkout (tests): oscal/catalog/."""
    for d in (HERE, os.path.join(HERE, "..", "..", "oscal", "catalog")):
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    raise FileNotFoundError(name)

REQ_RE = re.compile(r"^NIST\.800-53\.r5 ([A-Z]{2})-(\d+)(?:\((\d+)\))?$")


# ---------- helpers ----------

def now_iso():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def to_oscal_id(req: str):
    """'NIST.800-53.r5 SC-28(1)' -> 'sc-28.1'; returns None for anything else."""
    m = REQ_RE.match(req.strip())
    if not m:
        return None
    fam, num, enh = m.groups()
    return f"{fam.lower()}-{num}" + (f".{enh}" if enh else "")


def display_id(cid: str) -> str:
    """'sc-28.1' -> 'SC-28(1)'"""
    base, _, enh = cid.partition(".")
    return base.upper() + (f"({enh})" if enh else "")


def load_json(name):
    with open(find_file(name), encoding="utf-8") as f:
        return json.load(f)


def put_json(key, obj):
    body = json.dumps(obj, indent=2, sort_keys=False, default=str).encode()
    digest = sha256(body)
    s3.put_object(Bucket=BUCKET, Key=key, Body=body, ContentType="application/json",
                  Metadata={"sha256": digest}, ChecksumAlgorithm="SHA256")
    return digest


def get_json(key):
    try:
        obj = s3.get_object(Bucket=BUCKET, Key=key)
        return json.loads(obj["Body"].read())
    except s3.exceptions.NoSuchKey:
        return None


# ---------- 1. collect ----------

def collect_findings():
    filters = {
        "ProductName": [{"Value": "Security Hub", "Comparison": "EQUALS"}],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    }
    out = []
    for page in sh.get_paginator("get_findings").paginate(
            Filters=filters, PaginationConfig={"PageSize": 100}):
        for f in page["Findings"]:
            reqs = f.get("Compliance", {}).get("RelatedRequirements", [])
            if any(r.startswith("NIST.800-53.r5 ") for r in reqs):
                out.append(f)
    return out


# ---------- 2. decide control states ----------

def index_checks(findings):
    """control id -> list of check dicts"""
    by_control = {}
    for f in findings:
        comp = f.get("Compliance", {})
        check = {
            "check_id": comp.get("SecurityControlId") or f.get("GeneratorId", ""),
            "title": f.get("Title", ""),
            "status": comp.get("Status", "NOT_AVAILABLE"),
            "workflow": f.get("Workflow", {}).get("Status", "NEW"),
            "resource": (f.get("Resources") or [{}])[0].get("Id", ""),
            "finding_id": f.get("Id", ""),
            "updated": f.get("UpdatedAt", ""),
            "note": (f.get("Note") or {}).get("Text", ""),
        }
        for req in comp.get("RelatedRequirements", []):
            cid = to_oscal_id(req)
            if cid:
                by_control.setdefault(cid, []).append(check)
    return by_control


def attestation_state(cid, today):
    """Attestations live at attestations/<control-id>.json:
    {"artifact": "docs/policies/ac-policy.md", "sha256": "...", "reviewed": "2026-11-13", "reviewer": "Jose"}"""
    key = f"attestations/{cid}.json"
    att = get_json(key)
    if not att:
        return "not-satisfied", None, "No attestation on file."
    try:
        reviewed = dt.date.fromisoformat(att["reviewed"])
    except (KeyError, ValueError):
        return "not-satisfied", key, "Attestation has no valid review date."
    age = (today - reviewed).days
    if age > 365:
        return "not-satisfied", key, f"Attestation last reviewed {age} days ago (limit 365)."
    return "satisfied", key, f"Attestation reviewed {att['reviewed']} by {att.get('reviewer', 'unknown')}."


def decide(cid, cmap_entry, checks, today):
    source = cmap_entry.get("source", "auto")
    if source == "inherited":
        return {"state": "inherited", "source": "inherited",
                "reason": f"Inherited from {cmap_entry.get('provider', 'AWS')}. See SSP."}
    if source == "attestation":
        state, key, reason = attestation_state(cid, today)
        return {"state": state, "source": "attestation", "reason": reason, "attestation_key": key}
    if source == "not-applicable":
        return {"state": "not-applicable", "source": "not-applicable",
                "reason": cmap_entry.get("reason", "Not applicable. See SSP.")}

    if not checks:
        return {"state": "not-assessed", "source": "manual",
                "reason": "No automated check covers this control. Needs manual assessment."}

    failed = [c for c in checks if c["status"] == "FAILED" and c["workflow"] != "SUPPRESSED"]
    accepted = [c for c in checks if c["status"] == "FAILED" and c["workflow"] == "SUPPRESSED"]
    passed = [c for c in checks if c["status"] == "PASSED"]
    if failed:
        state = "not-satisfied"
    elif accepted:
        state = "risk-accepted"
    elif passed:
        state = "satisfied"
    else:
        state = "not-assessed"
    return {
        "state": state, "source": "securityhub",
        "checks_total": len(checks), "checks_failed": len(failed),
        "checks_accepted": len(accepted), "checks_passed": len(passed),
        "failing": [f"{c['check_id']} on {c['resource']}" for c in failed][:20],
        "accepted": [f"{c['check_id']} on {c['resource']}: {c['note'] or 'suppressed'}" for c in accepted][:20],
        "reason": f"{len(passed)} passed, {len(failed)} failed, {len(accepted)} risk-accepted "
                  f"of {len(checks)} Security Hub checks.",
    }


# ---------- 3. OSCAL ----------

def build_assessment_results(run_id, started, ended, catalog, decisions, checks_by_control,
                             raw_key, raw_digest):
    observations, findings = [], []
    evidence = [{
        "href": f"s3://{BUCKET}/{raw_key}",
        "description": f"Raw Security Hub CSPM findings (ASFF), sha256 {raw_digest}",
        "props": [{"name": "evidence-sha256", "ns": NS, "value": raw_digest}],
    }]

    for cid in sorted(decisions):
        d = decisions[cid]
        if d["state"] in ("inherited", "not-applicable", "not-assessed"):
            continue
        obs_uuids = []
        if d["source"] == "securityhub":
            for c in checks_by_control.get(cid, []):
                ou = str(uuid.uuid4())
                obs_uuids.append(ou)
                observations.append({
                    "uuid": ou,
                    "title": f"{c['check_id']} {c['status']}",
                    "description": f"{c['title']} on {c['resource']}: {c['status']}"
                                   + (" (risk accepted)" if c["workflow"] == "SUPPRESSED" else ""),
                    "methods": ["TEST"],
                    "types": ["finding"],
                    "collected": c["updated"] or ended,
                    "relevant-evidence": evidence,
                })
        else:  # attestation
            ou = str(uuid.uuid4())
            obs_uuids.append(ou)
            obs = {
                "uuid": ou,
                "title": f"{display_id(cid)} attestation",
                "description": d["reason"],
                "methods": ["EXAMINE"],
                "types": ["control-objective"],
                "collected": ended,
            }
            if d.get("attestation_key"):
                obs["relevant-evidence"] = [{"href": f"s3://{BUCKET}/{d['attestation_key']}",
                                             "description": "Attestation record"}]
            observations.append(obs)

        oscal_state = "satisfied" if d["state"] == "satisfied" else "not-satisfied"
        fu = str(uuid.uuid4())
        d["finding_uuid"] = fu
        finding = {
            "uuid": fu,
            "title": f"{display_id(cid)} {catalog.get(cid, {}).get('title', '')}".strip(),
            "description": d["reason"],
            "target": {
                "type": "objective-id",
                "target-id": f"{cid}_obj",
                "status": {"state": oscal_state},
            },
            "related-observations": [{"observation-uuid": u} for u in obs_uuids],
        }
        if d["state"] == "risk-accepted":
            finding["props"] = [{"name": "risk-accepted", "ns": NS, "value": "true"}]
        findings.append(finding)

    result = {
        "uuid": str(uuid.uuid4()),
        "title": f"Automated assessment {run_id}",
        "description": "Daily automated assessment against the NIST SP 800-53 Rev 5 Moderate baseline "
                       "using AWS Security Hub CSPM, attestations, and the SAS control map.",
        "start": started,
        "end": ended,
        "reviewed-controls": {"control-selections": [{"include-all": {}}]},
    }
    if observations:
        result["observations"] = observations
    if findings:
        result["findings"] = findings
    return {"assessment-results": {
        "uuid": str(uuid.uuid4()),
        "metadata": {
            "title": f"{SYSTEM_NAME} automated assessment results {run_id}",
            "last-modified": ended,
            "version": run_id,
            "oscal-version": OSCAL_VERSION,
        },
        "import-ap": {"href": "../ap/sas-ap.json"},
        "results": [result],
    }}


def build_poam(run_id, ended, catalog, decisions, previous):
    """One POA&M item per not-satisfied control. Keeps first-seen dates across runs,
    and moves items that are now satisfied to closed with the closing date."""
    prev_items = {}
    if previous:
        for it in previous.get("plan-of-action-and-milestones", {}).get("poam-items", []):
            cid = next((p["value"] for p in it.get("props", []) if p["name"] == "control-id"), None)
            if cid:
                prev_items[cid] = it
    today = ended[:10]
    items = []
    for cid in sorted(set(decisions) | set(prev_items)):
        d = decisions.get(cid, {})
        prev = prev_items.get(cid)
        prev_props = {p["name"]: p["value"] for p in (prev or {}).get("props", [])}
        is_open = d.get("state") == "not-satisfied"
        if not is_open and not prev:
            continue
        first_seen = prev_props.get("first-seen", today)
        due = (dt.date.fromisoformat(first_seen) + dt.timedelta(days=POAM_DAYS)).isoformat()
        status = "open" if is_open else "closed"
        props = [
            {"name": "control-id", "ns": NS, "value": cid},
            {"name": "status", "ns": NS, "value": status},
            {"name": "first-seen", "ns": NS, "value": first_seen},
            {"name": "scheduled-completion", "ns": NS, "value": due},
        ]
        if status == "closed":
            props.append({"name": "closed-on", "ns": NS,
                          "value": prev_props.get("closed-on", today) if prev_props.get("status") == "closed" else today})
        if d.get("finding_uuid"):
            props.append({"name": "latest-finding-uuid", "ns": NS, "value": d["finding_uuid"]})
        items.append({
            "uuid": str(uuid.uuid5(UUID_NS, f"poam-{cid}")),
            "title": f"{display_id(cid)} {catalog.get(cid, {}).get('title', '')}".strip(),
            "description": d.get("reason") or (prev or {}).get("description", ""),
            "props": props,
            "remarks": "; ".join(d.get("failing", [])) or None,
        })
    for it in items:
        if it["remarks"] is None:
            del it["remarks"]
    return {"plan-of-action-and-milestones": {
        "uuid": str(uuid.uuid4()),
        "metadata": {
            "title": f"{SYSTEM_NAME} plan of action and milestones",
            "last-modified": ended,
            "version": run_id,
            "oscal-version": OSCAL_VERSION,
        },
        "system-id": {"identifier-type": "https://ietf.org/rfc/rfc4122",
                      "id": str(uuid.uuid5(UUID_NS, SYSTEM_NAME))},
        "poam-items": items or [{
            "uuid": str(uuid.uuid5(UUID_NS, "poam-none")),
            "title": "No open items",
            "description": "No not-satisfied controls in this run.",
        }],
    }}


# ---------- 4. status table ----------

def write_status(decisions, catalog, run_id, ended, ar_key, ar_digest, raw_key, raw_digest):
    table = ddb.Table(TABLE)
    with table.batch_writer(overwrite_by_pkeys=["control_id"]) as batch:
        for cid, d in decisions.items():
            item = {
                "control_id": cid,
                "display_id": display_id(cid),
                "title": catalog.get(cid, {}).get("title", ""),
                "family": catalog.get(cid, {}).get("family", ""),
                "state": d["state"],
                "source": d["source"],
                "reason": d["reason"],
                "last_assessed": ended,
                "run_id": run_id,
                "ar_key": ar_key,
                "ar_sha256": ar_digest,
            }
            if d["source"] == "securityhub":
                item.update({
                    "evidence_key": raw_key, "evidence_sha256": raw_digest,
                    "checks_total": d["checks_total"], "checks_failed": d["checks_failed"],
                    "checks_accepted": d["checks_accepted"], "checks_passed": d["checks_passed"],
                    "failing": d["failing"], "accepted": d["accepted"],
                })
            if d.get("attestation_key"):
                item["evidence_key"] = d["attestation_key"]
            if d.get("finding_uuid"):
                item["finding_uuid"] = d["finding_uuid"]
            batch.put_item(Item={k: v for k, v in item.items() if v not in (None, [], "")})


# ---------- handler ----------

def run(findings, today=None):
    """Pure part of the pipeline (no AWS calls except attestation reads). Used by tests."""
    catalog = load_json("moderate_controls.json")
    cmap = load_json("control-map.json")
    defaults = cmap.get("family_defaults", {})
    overrides = cmap.get("controls", {})
    today = today or dt.date.today()
    checks = index_checks(findings)
    decisions = {}
    for cid in catalog:
        entry = overrides.get(cid) or defaults.get(cid.split("-")[0]) or {}
        if not overrides.get(cid) and cid.split(".")[0].endswith("-1") and "policy_controls" in cmap:
            entry = cmap["policy_controls"]
        decisions[cid] = decide(cid, entry, checks.get(cid, []), today)
    return catalog, checks, decisions


def lambda_handler(event, context):
    started = now_iso()
    run_id = started.replace(":", "").replace("+0000", "Z")
    findings = collect_findings()

    raw_key = f"raw/securityhub/{run_id}.json"
    raw_body = json.dumps(findings, default=str, sort_keys=True).encode()
    raw_digest = sha256(raw_body)
    s3.put_object(Bucket=BUCKET, Key=raw_key, Body=raw_body, ContentType="application/json",
                  Metadata={"sha256": raw_digest}, ChecksumAlgorithm="SHA256")

    catalog, checks, decisions = run(findings)
    ended = now_iso()

    ar = build_assessment_results(run_id, started, ended, catalog, decisions, checks, raw_key, raw_digest)
    ar_key = f"oscal/ar/{run_id}.json"
    ar_digest = put_json(ar_key, ar)
    put_json("oscal/ar/latest.json", ar)

    poam = build_poam(run_id, ended, catalog, decisions, get_json("oscal/poam/latest.json"))
    put_json(f"oscal/poam/{run_id}.json", poam)
    put_json("oscal/poam/latest.json", poam)

    write_status(decisions, catalog, run_id, ended, ar_key, ar_digest, raw_key, raw_digest)

    counts = {}
    for d in decisions.values():
        counts[d["state"]] = counts.get(d["state"], 0) + 1
    summary = {"run_id": run_id, "findings": len(findings), "controls": len(decisions),
               "states": counts, "ar_key": ar_key, "ar_sha256": ar_digest,
               "raw_key": raw_key, "raw_sha256": raw_digest}
    print(json.dumps({"event": "sas-evidence-run", **summary}))
    return summary
