import json, sys, datetime as dt, os
os.environ["AWS_DEFAULT_REGION"]="us-east-1"; os.environ["EVIDENCE_BUCKET"]="sas-evidence-test"
sys.path.insert(0, "src/evidence_pipeline")
import lambda_function as lf
lf.get_json = lambda key: None  # no S3 in tests

def f(ctrl, status, reqs, res="arn:aws:s3:::sas-data", wf="NEW"):
    return {"Id": f"id-{ctrl}-{res}", "Title": f"{ctrl} check", "UpdatedAt": "2026-11-13T20:00:00Z",
            "Resources": [{"Id": res}], "Workflow": {"Status": wf},
            "Compliance": {"SecurityControlId": ctrl, "Status": status,
                           "RelatedRequirements": [f"NIST.800-53.r5 {r}" for r in reqs]}}
findings = [
    f("S3.17","FAILED",["SC-28","SC-28(1)","SC-13"],"arn:aws:s3:::sas-accesslogs", wf="SUPPRESSED"),
    f("S3.17","PASSED",["SC-28","SC-28(1)","SC-13"],"arn:aws:s3:::sas-data"),
    f("IAM.6","FAILED",["IA-2(1)","IA-2(2)","AC-6(10)"],"AWS::::Account:1"),
    f("KMS.4","PASSED",["SC-12","SC-12(2)"],"arn:aws:kms:key/1"),
    f("CloudTrail.4","PASSED",["AU-9","SI-7(1)"],"arn:trail"),
    f("X.1","FAILED",["XX-99"],"weird"),  # unmapped requirement, must be ignored
]
catalog, checks, decisions = lf.run(findings, today=dt.date(2026,11,13))
for c in ["sc-28","sc-28.1","ia-2.1","sc-12","au-9","pe-3","pe-1","ac-1","ac-2","ma-2"]:
    print(c, decisions[c]["state"], decisions[c]["source"], "|", decisions[c]["reason"])
assert decisions["sc-28"]["state"]=="risk-accepted"
assert decisions["ia-2.1"]["state"]=="not-satisfied"
assert decisions["sc-12"]["state"]=="satisfied"
assert decisions["pe-3"]["state"]=="inherited"
assert decisions["pe-1"]["state"]=="not-satisfied" and decisions["pe-1"]["source"]=="attestation"
assert decisions["ac-2"]["state"]=="not-assessed"
assert lf.to_oscal_id("NIST.800-53.r5 SC-28(1)")=="sc-28.1" and lf.display_id("sc-28.1")=="SC-28(1)"

ar = lf.build_assessment_results("2026-11-13T200000Z","2026-11-13T20:00:00+00:00","2026-11-13T20:01:00+00:00",
     catalog, decisions, checks, "raw/securityhub/x.json", "ab"*32)
poam = lf.build_poam("r1","2026-11-13T20:01:00+00:00", catalog, decisions, None)
# second run: ia-2.1 fixed -> item closes, first-seen preserved
decisions2 = json.loads(json.dumps(decisions)); decisions2["ia-2.1"]={"state":"satisfied","source":"securityhub","reason":"fixed"}
poam2 = lf.build_poam("r2","2026-11-20T20:01:00+00:00", catalog, decisions2, poam)

from trestle.oscal.assessment_results import AssessmentResults
from trestle.oscal.poam import PlanOfActionAndMilestones
AssessmentResults.parse_obj(ar["assessment-results"])
PlanOfActionAndMilestones.parse_obj(poam["plan-of-action-and-milestones"])
PlanOfActionAndMilestones.parse_obj(poam2["plan-of-action-and-milestones"])
items = {next(p["value"] for p in i["props"] if p["name"]=="control-id"): {p["name"]:p["value"] for p in i["props"]} for i in poam2["plan-of-action-and-milestones"]["poam-items"]}
print("ia-2.1 in run 2:", items["ia-2.1"])
assert items["ia-2.1"]["status"]=="closed" and items["ia-2.1"]["first-seen"]=="2026-11-13"
r = ar["assessment-results"]["results"][0]
print("AR valid. findings:", len(r["findings"]), "observations:", len(r["observations"]))
print("POA&M valid. run1 items:", len(poam["plan-of-action-and-milestones"]["poam-items"]))
json.dump(ar, open("/tmp/sample-ar.json","w"), indent=2)
print("ALL PASS")
