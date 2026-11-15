"""SAS compliance chat.

Bedrock Converse with tool use. The model can only see what these read-only tools return:
control status rows, hashed evidence, the NIST catalog text, and the OSCAL POA&M.

Input event (Lambda invoke from the CLI):
  {"question": "Is SC-28 satisfied?", "history": [ ...text-only turns from the last reply... ]}
Input event (API Gateway HTTP API, later): same JSON in event["body"].

Environment variables:
  MODEL_ID         Bedrock inference profile ID (us. prefixed)
  STATUS_TABLE     control_status
  EVIDENCE_BUCKET  sas-evidence-<account-id>
"""
import hashlib
import json
import os
import re

import boto3

br = boto3.client("bedrock-runtime")
s3 = boto3.client("s3")
table = boto3.resource("dynamodb").Table(os.environ.get("STATUS_TABLE", "control_status"))

MODEL_ID = os.environ.get("MODEL_ID", "")
BUCKET = os.environ.get("EVIDENCE_BUCKET", "")
HERE = os.path.dirname(os.path.abspath(__file__))


def find_file(name):
    """Packaged Lambda: next to this file. Repo checkout (tests): oscal/catalog/."""
    for d in (HERE, os.path.join(HERE, "..", "..", "oscal", "catalog")):
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    raise FileNotFoundError(name)
CATALOG = json.load(open(find_file("moderate_controls.json"), encoding="utf-8"))
MAX_TOOL_ROUNDS = 8

SYSTEM = [{"text": (
    "You are the compliance assistant for the Self-Audited System (SAS), assessed against the "
    "NIST SP 800-53 Rev 5 Moderate baseline. Answer only from tool results; never from memory. "
    "For every control you report, give its state, source, and last assessed time. When the source "
    "is securityhub or attestation, also give the OSCAL finding UUID and the evidence key with its "
    "sha256, and say whether the hash was verified if you checked it. "
    "States: satisfied, not-satisfied, risk-accepted (a failed check with a documented acceptance), "
    "inherited (provided by AWS, see SSP), not-applicable, not-assessed (needs manual assessment). "
    "Never call a control satisfied or compliant unless a tool result says satisfied. "
    "Never say the whole system is compliant; give counts by state instead, exactly as the tool "
    "returns them, one line per state, with no grouping, estimating, or percentages you did not compute. "
    "A failing check can be stale if it was fixed after the last assessment run; say when the run was. "
    "Use the control's NIST wording only from explain_control. Be brief and plain."
)}]


def norm(cid: str) -> str:
    """'AC-2(1)', 'ac-2.1', 'AC 2 (1)' -> 'ac-2.1'"""
    m = re.match(r"^\s*([A-Za-z]{2})[\s-]*(\d+)\s*(?:[\(.]\s*(\d+)\s*\)?)?\s*$", cid or "")
    if not m:
        return (cid or "").strip().lower()
    fam, num, enh = m.groups()
    return f"{fam.lower()}-{int(num)}" + (f".{int(enh)}" if enh else "")


def clean(item):
    """DynamoDB Decimals -> int for JSON."""
    return json.loads(json.dumps(item, default=lambda d: int(d) if d == int(d) else float(d)))


# ---------------- tools ----------------

def get_control_status(control_id):
    cid = norm(control_id)
    item = table.get_item(Key={"control_id": cid}).get("Item")
    if not item:
        in_baseline = cid in CATALOG
        return {"control_id": cid, "state": "not-assessed" if in_baseline else "unknown",
                "note": "No status row. " + ("Control is in the Moderate baseline but has not been assessed yet."
                                             if in_baseline else "Control is not in the Moderate baseline.")}
    return clean(item)


def scan_all():
    items, kwargs = [], {}
    while True:
        page = table.scan(**kwargs)
        items.extend(page["Items"])
        if "LastEvaluatedKey" not in page:
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    return items


def list_controls(family=None, state=None):
    fam = (family or "").strip().lower()
    out = [{"control_id": i["control_id"], "display_id": i.get("display_id"), "title": i.get("title"),
            "state": i.get("state"), "source": i.get("source")}
           for i in scan_all()
           if (not fam or i["control_id"].split("-")[0] == fam) and (not state or i.get("state") == state)]
    out.sort(key=lambda x: x["control_id"])
    limit = 150
    result = {"count": len(out), "controls": out[:limit]}
    if len(out) > limit:
        result["note"] = f"Showing the first {limit} of {len(out)}. Filter by family or state for the rest."
    return result


def get_summary():
    items = scan_all()
    counts = {}
    for i in items:
        counts[i.get("state", "unknown")] = counts.get(i.get("state", "unknown"), 0) + 1
    latest = max((i.get("last_assessed", "") for i in items), default=None)
    run_id = next((i.get("run_id") for i in items if i.get("last_assessed") == latest), None)
    return {"controls_in_table": len(items), "baseline_size": len(CATALOG), "by_state": counts,
            "every_state_listed": True, "last_assessed": latest, "run_id": run_id}


def get_evidence(control_id):
    status = get_control_status(control_id)
    key = status.get("evidence_key")
    if not key:
        return {"control_id": status.get("control_id"), "state": status.get("state"),
                "evidence": "none", "note": "No machine evidence for this control (inherited, manual, or not assessed)."}
    obj = s3.get_object(Bucket=BUCKET, Key=key)
    body = obj["Body"].read()
    actual = hashlib.sha256(body).hexdigest()
    recorded = status.get("evidence_sha256") or obj.get("Metadata", {}).get("sha256")
    result = {
        "control_id": status["control_id"], "state": status.get("state"),
        "evidence_key": f"s3://{BUCKET}/{key}",
        "recorded_sha256": recorded, "actual_sha256": actual,
        "hash_verified": bool(recorded) and recorded == actual,
        "object_version": obj.get("VersionId"),
        "finding_uuid": status.get("finding_uuid"),
        "failing_checks": status.get("failing", []),
        "accepted_checks": status.get("accepted", []),
        "ar_key": status.get("ar_key"), "ar_sha256": status.get("ar_sha256"),
    }
    if status.get("source") == "attestation":
        result["attestation"] = json.loads(body)
    return result


def explain_control(control_id):
    cid = norm(control_id)
    c = CATALOG.get(cid)
    if not c:
        return {"control_id": cid, "note": "Not in the NIST SP 800-53 Rev 5 Moderate baseline."}
    return {"control_id": cid, **c}


def get_poam_item(control_id):
    cid = norm(control_id)
    try:
        poam = json.loads(s3.get_object(Bucket=BUCKET, Key="oscal/poam/latest.json")["Body"].read())
    except s3.exceptions.NoSuchKey:
        return {"note": "No POA&M generated yet."}
    for it in poam["plan-of-action-and-milestones"].get("poam-items", []):
        props = {p["name"]: p["value"] for p in it.get("props", [])}
        if props.get("control-id") == cid:
            return {"uuid": it["uuid"], "title": it["title"], "description": it.get("description"),
                    "remarks": it.get("remarks"), **props}
    return {"control_id": cid, "note": "No POA&M item for this control."}


TOOL_FUNCS = {
    "get_control_status": get_control_status,
    "list_controls": list_controls,
    "get_summary": get_summary,
    "get_evidence": get_evidence,
    "explain_control": explain_control,
    "get_poam_item": get_poam_item,
}

CID = {"type": "string", "description": "NIST control id, e.g. ac-2, AC-2(1), sc-28.1"}
TOOLS = {"tools": [
    {"toolSpec": {"name": "get_control_status",
                  "description": "Current assessed state of one control, with source, reason, finding UUID and evidence key.",
                  "inputSchema": {"json": {"type": "object", "properties": {"control_id": CID},
                                           "required": ["control_id"]}}}},
    {"toolSpec": {"name": "list_controls",
                  "description": "List controls, optionally filtered by two-letter family (ac, au, sc...) and/or state.",
                  "inputSchema": {"json": {"type": "object", "properties": {
                      "family": {"type": "string"},
                      "state": {"type": "string", "enum": ["satisfied", "not-satisfied", "risk-accepted",
                                                          "inherited", "not-applicable", "not-assessed"]}}}}}},
    {"toolSpec": {"name": "get_summary",
                  "description": "Counts of controls by state and the time of the latest assessment run.",
                  "inputSchema": {"json": {"type": "object", "properties": {}}}}},
    {"toolSpec": {"name": "get_evidence",
                  "description": "Fetch the evidence file for a control, re-hash it, and report whether it matches the recorded sha256.",
                  "inputSchema": {"json": {"type": "object", "properties": {"control_id": CID},
                                           "required": ["control_id"]}}}},
    {"toolSpec": {"name": "explain_control",
                  "description": "Official NIST SP 800-53 Rev 5 title and statement for a control.",
                  "inputSchema": {"json": {"type": "object", "properties": {"control_id": CID},
                                           "required": ["control_id"]}}}},
    {"toolSpec": {"name": "get_poam_item",
                  "description": "The POA&M item for a control: status, first seen, scheduled completion, failing checks.",
                  "inputSchema": {"json": {"type": "object", "properties": {"control_id": CID},
                                           "required": ["control_id"]}}}},
]}


# ---------------- converse loop ----------------

def answer(question, history):
    messages = [m for m in (history or []) if m.get("role") in ("user", "assistant")][-10:]
    messages.append({"role": "user", "content": [{"text": question}]})
    calls = []
    for _ in range(MAX_TOOL_ROUNDS):
        resp = br.converse(modelId=MODEL_ID, system=SYSTEM, messages=messages, toolConfig=TOOLS,
                           inferenceConfig={"maxTokens": 1200, "temperature": 0})
        msg = resp["output"]["message"]
        messages.append(msg)
        if resp["stopReason"] != "tool_use":
            text = "".join(b.get("text", "") for b in msg["content"]).strip()
            return text, calls
        results = []
        for block in msg["content"]:
            if "toolUse" not in block:
                continue
            tu = block["toolUse"]
            try:
                out = TOOL_FUNCS[tu["name"]](**(tu.get("input") or {}))
                status = "success"
            except Exception as e:  # report tool errors to the model, never invent data
                out, status = {"error": f"{type(e).__name__}: {e}"}, "error"
            calls.append({"tool": tu["name"], "input": tu.get("input"), "status": status})
            results.append({"toolResult": {"toolUseId": tu["toolUseId"], "content": [{"json": out}],
                                           "status": status}})
        messages.append({"role": "user", "content": results})
    return "I couldn't finish within the tool-call limit. Try a narrower question.", calls


def lambda_handler(event, context):
    body = event
    if isinstance(event.get("body"), str):  # API Gateway
        body = json.loads(event["body"] or "{}")
    question = (body.get("question") or "").strip()[:2000]
    if not question:
        return {"statusCode": 400, "body": json.dumps({"error": "question required"})}
    history = body.get("history") or []
    text, calls = answer(question, history)
    new_history = history + [{"role": "user", "content": [{"text": question}]},
                             {"role": "assistant", "content": [{"text": text}]}]
    claims = (event.get("requestContext", {}).get("authorizer", {}).get("jwt", {}).get("claims", {}))
    user = claims.get("email") or claims.get("cognito:username") or claims.get("sub") or "iam-invoke"
    channel = "web" if "body" in event else "cli"
    print(json.dumps({"event": "sas-chat", "user": user, "channel": channel, "question": question,
                      "tool_calls": calls, "answer": text}))
    result = {"answer": text, "tool_calls": calls, "history": new_history[-10:]}
    if "body" in event:
        return {"statusCode": 200, "headers": {"content-type": "application/json"}, "body": json.dumps(result)}
    return result
