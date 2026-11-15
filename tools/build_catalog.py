"""Build a compact lookup of NIST SP 800-53 Rev 5 Moderate controls for the chat Lambda.

Input:  NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json (usnistgov/oscal-content)
Output: moderate_controls.json  {"ac-2": {"title": ..., "family": ..., "statement": ...}, ...}

Usage:  python build_catalog.py <resolved-catalog.json> <out.json>
"""
import json
import re
import sys


def param_text(params, pid):
    p = params.get(pid, {})
    if p.get("values"):
        return ", ".join(p["values"])
    if p.get("select"):
        choices = p["select"].get("choice", [])
        return "[Selection: " + "; ".join(choices) + "]"
    label = p.get("label") or (p.get("guidelines") or [{}])[0].get("prose", "organization-defined value")
    return f"[Assignment: {label}]"


def fill(prose, params):
    return re.sub(r"\{\{\s*insert:\s*param,\s*([\w.\-]+)\s*\}\}", lambda m: param_text(params, m.group(1)), prose or "")


def walk_parts(parts, params, depth=0):
    lines = []
    for part in parts or []:
        label = next((p["value"] for p in part.get("props", []) if p.get("name") == "label"), "")
        text = fill(part.get("prose", ""), params)
        if text or label:
            lines.append(("  " * depth) + (f"{label} " if label else "") + text)
        lines.extend(walk_parts(part.get("parts"), params, depth + 1))
    return lines


def collect(controls, family, params, out):
    for c in controls or []:
        for p in c.get("params", []):
            params[p["id"]] = p
        stmt = [pt for pt in c.get("parts", []) if pt.get("name") == "statement"]
        out[c["id"]] = {
            "title": c.get("title", ""),
            "family": family,
            "statement": "\n".join(walk_parts(stmt, params)).strip(),
        }
        collect(c.get("controls"), family, params, out)


def main(src, dst):
    cat = json.load(open(src, encoding="utf-8"))["catalog"]
    out, params = {}, {}
    for g in cat.get("groups", []):
        collect(g.get("controls"), g.get("title", g.get("id", "")), params, out)
    json.dump(out, open(dst, "w", encoding="utf-8"), indent=1, sort_keys=True)
    print(f"wrote {len(out)} controls to {dst}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
