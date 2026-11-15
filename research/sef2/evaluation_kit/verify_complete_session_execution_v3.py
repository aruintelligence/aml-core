"""Independent verifier for the full V3 synthetic execution authorization chain.

Proves that the exact authority capability, broker challenge, holder proof and
evaluator authorization were bound into the independently signed consumption
receipt. It does not prove an external real-world effect occurred.
"""
import argparse,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent))
from verify_session_authorization import verify_session_authorization
from execution_gate_receipt import verify_evaluator_authorization
from authorized_execution_consumption import verify_authorized_consumption_receipt

SCHEMA="AML-SEF2-COMPLETE-SESSION-EXECUTION-EVIDENCE-V3"

def verify_complete_v3(bundle,authority_public_hex,broker_public_hex,
                       evaluator_public_hex,witness_public_hex,
                       issuer,audience,broker_instance_id,evaluator_id,
                       evaluator_witness_id,consumption_witness_id,policy_epoch):
    try:
        required={"schema","authorization","evaluator_authorization","consumption_receipt"}
        if type(bundle) is not dict or set(bundle)!=required or bundle["schema"]!=SCHEMA:
            return False
        auth=bundle["authorization"]
        if not verify_session_authorization(auth,authority_public_hex,broker_public_hex,
            issuer,audience,broker_instance_id,policy_epoch):
            return False
        request=auth["request"]; capability=auth["capability"]
        challenge=auth["broker_challenge"]; holder_proof=auth["holder_proof"]
        evaluator=bundle["evaluator_authorization"]
        if not verify_evaluator_authorization(evaluator,evaluator_public_hex,evaluator_id,
            audience,evaluator_witness_id,request,capability,challenge,policy_epoch):
            return False
        raw_challenge=challenge["payload"]["challenge"]
        return verify_authorized_consumption_receipt(bundle["consumption_receipt"],
            witness_public_hex,consumption_witness_id,request,capability,raw_challenge,
            holder_proof,evaluator)
    except (ValueError,TypeError,KeyError,OverflowError,AttributeError):
        return False

if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in ("input","authority-public-hex","broker-public-hex","evaluator-public-hex",
                 "witness-public-hex","issuer","audience","broker-instance-id",
                 "evaluator-id","evaluator-witness-id","consumption-witness-id"):
        p.add_argument("--"+name,required=True)
    p.add_argument("--policy-epoch",type=int,required=True)
    a=p.parse_args()
    try: bundle=json.loads(pathlib.Path(a.input).read_text())
    except (OSError,ValueError): bundle=None
    ok=verify_complete_v3(bundle,a.authority_public_hex,a.broker_public_hex,
        a.evaluator_public_hex,a.witness_public_hex,a.issuer,a.audience,
        a.broker_instance_id,a.evaluator_id,a.evaluator_witness_id,
        a.consumption_witness_id,a.policy_epoch)
    print("COMPLETE_SESSION_EXECUTION_V3_VERIFIED" if ok else "COMPLETE_SESSION_EXECUTION_V3_REJECTED")
    if ok:
        print("authority_capability_proven=true")
        print("broker_challenge_proven=true")
        print("holder_proof_proven=true")
        print("evaluator_authorization_proven=true")
        print("full_authorization_consumption_proven=true")
        print("external_execution_proven=false")
    raise SystemExit(0 if ok else 2)
