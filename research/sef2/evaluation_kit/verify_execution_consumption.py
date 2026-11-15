"""Independent verifier for execution-consumption receipts.

This verifies that a pinned witness key signed consumption of the exact
operation/request/capability/challenge. It does not prove an external effect
occurred, only that the single-use boundary was durably consumed according to
the witness.
"""
import argparse,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent))
from execution_consumption_witness import verify_consumption_receipt

def verify_bundle(bundle,public_hex,witness_id):
    try:
        if type(bundle) is not dict or set(bundle)!={"schema","request","capability","challenge","receipt"}:
            return False
        if bundle["schema"]!="AML-SEF2-EXECUTION-CONSUMPTION-EVIDENCE-V1":
            return False
        return verify_consumption_receipt(bundle["receipt"],public_hex,witness_id,
            bundle["request"],bundle["capability"],bundle["challenge"])
    except (ValueError,TypeError,KeyError,OverflowError):
        return False

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--input",required=True)
    p.add_argument("--witness-public-hex",required=True)
    p.add_argument("--witness-id",required=True)
    a=p.parse_args()
    try: bundle=json.loads(pathlib.Path(a.input).read_text())
    except (OSError,ValueError): bundle=None
    ok=verify_bundle(bundle,a.witness_public_hex,a.witness_id)
    print("EXECUTION_CONSUMPTION_EVIDENCE_VERIFIED" if ok else "EXECUTION_CONSUMPTION_EVIDENCE_REJECTED")
    if ok:
        print("external_execution_proven=false")
        print("boundary_consumption_proven=true")
    raise SystemExit(0 if ok else 2)
