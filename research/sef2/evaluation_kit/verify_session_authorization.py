"""Independent verifier for holder-bound session authorization evidence.

Verifies the public authorization chain without trusting the broker's own
success message. This proves authority/challenge/holder provenance, not that an
external effect occurred.
"""
import argparse,json,sys,pathlib
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent))
from session_capability import verify_session_capability,verify_holder_proof
from authenticated_execution_challenge import verify_execution_challenge
from signed_receipt import canonical
import hashlib

SCHEMA="AML-SEF2-SESSION-AUTHORIZATION-EVIDENCE-V1"

def decision_digest(bundle):
    return hashlib.sha256(canonical(bundle)).hexdigest()

def verify_session_authorization(bundle,authority_public_hex,broker_public_hex,
                                 issuer,audience,broker_instance_id,expected_policy_epoch):
    try:
        required={"schema","request","capability","broker_challenge","holder_proof"}
        if type(bundle) is not dict or set(bundle)!=required or bundle["schema"]!=SCHEMA:
            return False
        request=bundle["request"]; capability=bundle["capability"]
        challenge=bundle["broker_challenge"]; proof=bundle["holder_proof"]
        if not verify_session_capability(capability,authority_public_hex,issuer,audience,
                                         request,expected_policy_epoch):
            return False
        if not verify_execution_challenge(challenge,broker_public_hex,broker_instance_id,
                                          audience,request,capability,expected_policy_epoch):
            return False
        cp=challenge["payload"]
        if not verify_holder_proof(proof,capability,request,cp["challenge"]):
            return False
        if proof["payload"]["challenge"]!=cp["challenge"]:
            return False
        return True
    except (ValueError,TypeError,KeyError,OverflowError):
        return False

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--input",required=True)
    p.add_argument("--authority-public-hex",required=True)
    p.add_argument("--broker-public-hex",required=True)
    p.add_argument("--issuer",required=True)
    p.add_argument("--audience",required=True)
    p.add_argument("--broker-instance-id",required=True)
    p.add_argument("--policy-epoch",type=int,required=True)
    a=p.parse_args()
    try:
        bundle=json.loads(pathlib.Path(a.input).read_text())
    except (OSError,ValueError):
        bundle=None
    ok=verify_session_authorization(bundle,a.authority_public_hex,a.broker_public_hex,
        a.issuer,a.audience,a.broker_instance_id,a.policy_epoch)
    print("SESSION_AUTHORIZATION_EVIDENCE_VERIFIED" if ok else "SESSION_AUTHORIZATION_EVIDENCE_REJECTED")
    if ok:
        print("decision_sha256="+decision_digest(bundle))
        print("external_execution_proven=false")
    raise SystemExit(0 if ok else 2)
