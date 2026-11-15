"""Complete independent verifier for session authorization + consumption.

Combines authority capability, broker-authenticated challenge, holder proof and
independent execution-consumption receipt. It deliberately does NOT claim the
external effect itself occurred.
"""
import argparse,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent))
from verify_session_authorization import verify_session_authorization
from execution_consumption_witness import verify_consumption_receipt

SCHEMA="AML-SEF2-COMPLETE-SESSION-EXECUTION-EVIDENCE-V1"

def verify_complete(bundle,authority_public_hex,broker_public_hex,witness_public_hex,
                    issuer,audience,broker_instance_id,witness_id,policy_epoch):
    try:
        required={"schema","authorization","consumption_receipt"}
        if type(bundle) is not dict or set(bundle)!=required or bundle["schema"]!=SCHEMA:
            return False
        auth=bundle["authorization"]
        if not verify_session_authorization(auth,authority_public_hex,broker_public_hex,
            issuer,audience,broker_instance_id,policy_epoch):
            return False
        challenge=auth["broker_challenge"]["payload"]["challenge"]
        return verify_consumption_receipt(bundle["consumption_receipt"],witness_public_hex,
            witness_id,auth["request"],auth["capability"],challenge)
    except (ValueError,TypeError,KeyError,OverflowError):
        return False

if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in ("input","authority-public-hex","broker-public-hex","witness-public-hex",
                 "issuer","audience","broker-instance-id","witness-id"):
        p.add_argument("--"+name,required=True)
    p.add_argument("--policy-epoch",type=int,required=True)
    a=p.parse_args()
    try: bundle=json.loads(pathlib.Path(a.input).read_text())
    except (OSError,ValueError): bundle=None
    ok=verify_complete(bundle,a.authority_public_hex,a.broker_public_hex,a.witness_public_hex,
        a.issuer,a.audience,a.broker_instance_id,a.witness_id,a.policy_epoch)
    print("COMPLETE_SESSION_BOUNDARY_EVIDENCE_VERIFIED" if ok else "COMPLETE_SESSION_BOUNDARY_EVIDENCE_REJECTED")
    if ok:
        print("authorization_proven=true")
        print("boundary_consumption_proven=true")
        print("external_execution_proven=false")
    raise SystemExit(0 if ok else 2)
