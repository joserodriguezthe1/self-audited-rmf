import os, sys, json, hashlib
os.environ.update(AWS_DEFAULT_REGION="us-east-1", MODEL_ID="m", EVIDENCE_BUCKET="b")
sys.path.insert(0, "src/chat")
import lambda_function as ch
from decimal import Decimal
assert ch.norm("AC-2(1)")=="ac-2.1" and ch.norm("ac-2.1")=="ac-2.1" and ch.norm("SC 28")=="sc-28" and ch.norm("AC 2 (1)")=="ac-2.1"
body=b'[{"x":1}]'; dig=hashlib.sha256(body).hexdigest()
rows={"sc-28":{"control_id":"sc-28","display_id":"SC-28","state":"not-satisfied","source":"securityhub","evidence_key":"raw/x.json","evidence_sha256":dig,"finding_uuid":"u1","failing":["S3.17 on bucket"],"checks_total":Decimal(2)}}
class T:
    def get_item(self,Key): return {"Item":rows[Key["control_id"]]} if Key["control_id"] in rows else {}
    def scan(self,**k): return {"Items":list(rows.values())}
ch.table=T()
class S3:
    class exceptions: NoSuchKey=KeyError
    def get_object(self,Bucket,Key):
        import io
        return {"Body":io.BytesIO(body),"Metadata":{"sha256":dig},"VersionId":"v1"}
ch.s3=S3()
seq=iter([
 {"stopReason":"tool_use","output":{"message":{"role":"assistant","content":[{"toolUse":{"toolUseId":"t1","name":"get_evidence","input":{"control_id":"SC-28"}}}]}}},
 {"stopReason":"end_turn","output":{"message":{"role":"assistant","content":[{"text":"SC-28 is not-satisfied."}]}}},
])
captured=[]
class BR:
    def converse(self,**k): captured.append(k["messages"][-1]); return next(seq)
ch.br=BR()
out=ch.lambda_handler({"question":"Is SC-28 satisfied?"},None)
print(out["answer"], out["tool_calls"])
tr=captured[1]["content"][0]["toolResult"]["content"][0]["json"]
print("hash_verified:",tr["hash_verified"]); assert tr["hash_verified"]
print(ch.get_control_status("ac-2"))
print(ch.explain_control("AC-2(1)")["statement"][:80])
api=ch.lambda_handler({"body":json.dumps({"question":""})},None); assert api["statusCode"]==400
print("CHAT TESTS PASS")
# summary must count every row, not just the first page of list_controls
states = ["satisfied"]*18 + ["not-satisfied"]*59 + ["inherited"]*20 + ["not-assessed"]*190
big = {f"zz-{n}": {"control_id": f"zz-{n}", "state": s, "last_assessed": "2026-11-14T19:35:38+00:00", "run_id": "r1"} for n, s in enumerate(states)}
class T2:
    def scan(self, **k): return {"Items": list(big.values())}
ch.table = T2()
s = ch.get_summary(); print(s)
assert s["by_state"] == {"satisfied": 18, "not-satisfied": 59, "inherited": 20, "not-assessed": 190} and s["controls_in_table"] == 287
lc = ch.list_controls(); assert lc["count"] == 287 and len(lc["controls"]) == 150 and "note" in lc
print("SUMMARY FIX PASS")
