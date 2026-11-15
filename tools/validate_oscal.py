"""Validate every OSCAL JSON file in oscal/ against the official OSCAL models (compliance-trestle).

Usage: python tools/validate_oscal.py      exit code 1 if any file fails
"""
import glob
import json
import os
import sys

from trestle.oscal.assessment_plan import AssessmentPlan
from trestle.oscal.assessment_results import AssessmentResults
from trestle.oscal.poam import PlanOfActionAndMilestones
from trestle.oscal.ssp import SystemSecurityPlan

MODELS = {
    "system-security-plan": SystemSecurityPlan,
    "assessment-plan": AssessmentPlan,
    "assessment-results": AssessmentResults,
    "plan-of-action-and-milestones": PlanOfActionAndMilestones,
}
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
failed = 0
for path in sorted(glob.glob(os.path.join(ROOT, "oscal", "**", "*.json"), recursive=True)):
    doc = json.load(open(path))
    root = next((k for k in doc if k in MODELS), None)
    rel = os.path.relpath(path, ROOT)
    if not root:
        print(f"skip  {rel} (not an OSCAL document)")
        continue
    try:
        MODELS[root].parse_obj(doc[root])
        print(f"ok    {rel} ({root})")
    except Exception as e:  # pydantic ValidationError
        failed += 1
        print(f"FAIL  {rel}: {e}")
sys.exit(1 if failed else 0)
