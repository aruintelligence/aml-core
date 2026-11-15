"""Independent verifier for exported recovery-authority approval evidence.

Checks the authority's hash-linked event ledger, Ed25519 signatures, optional
expected head pin, and optional pinned recovery policy membership. This verifier
does not trust the authority process that produced the bundle.
"""
import argparse
import json
import pathlib
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent))
from threshold_recovery import verify_approval_ledger,validate_policy

def verify_recovery_authority_evidence(bundle,authority_public_hex,
                                       expected_head_sha256=None,policy=None):
    try:
        raw=bytes.fromhex(authority_public_hex)
        if len(raw)!=32:
            return False
        public=Ed25519PublicKey.from_public_bytes(raw)
        if policy is not None:
            if not validate_policy(policy):
                return False
            authority_id=bundle.get("authority_id") if type(bundle) is dict else None
            if authority_id not in policy["authorities"]:
                return False
            if policy["authorities"][authority_id]!=authority_public_hex:
                return False
        return verify_approval_ledger(bundle,public,expected_head_sha256)
    except (ValueError,TypeError,KeyError,AttributeError):
        return False

def load_unique(path):
    def hook(pairs):
        out={}
        for key,value in pairs:
            if key in out:
                raise ValueError("duplicate JSON key")
            out[key]=value
        return out
    data=pathlib.Path(path).read_text()
    parsed=json.loads(data,object_pairs_hook=hook)
    if json.dumps(parsed,sort_keys=True,separators=(",",":"),ensure_ascii=False)!=data:
        raise ValueError("noncanonical JSON evidence")
    return parsed

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--ledger",required=True)
    p.add_argument("--authority-public-hex",required=True)
    p.add_argument("--expected-head-sha256")
    p.add_argument("--policy")
    a=p.parse_args()
    try:
        bundle=load_unique(a.ledger)
        policy=load_unique(a.policy) if a.policy else None
        ok=verify_recovery_authority_evidence(bundle,a.authority_public_hex,
             a.expected_head_sha256,policy)
    except (OSError,ValueError,TypeError,KeyError):
        ok=False
    print("RECOVERY_AUTHORITY_EVIDENCE_VERIFIED" if ok else "RECOVERY_AUTHORITY_EVIDENCE_REJECTED")
    sys.exit(0 if ok else 2)
