"""Council-level verifier joining threshold approvals to independent authority ledgers."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from threshold_recovery import (policy_digest,payload_digest,verify_approval_bundle,
    verify_approval_ledger,validate_policy)

def verify_recovery_council_evidence(payload,approval_bundle,policy,authority_ledgers,expected_heads):
    try:
        if not validate_policy(policy) or not verify_approval_bundle(payload,approval_bundle,policy):
            return False
        if type(authority_ledgers) is not dict or type(expected_heads) is not dict:
            return False
        approving={item["authority_id"]:item["signature"] for item in approval_bundle["approvals"]}
        if set(authority_ledgers)!=set(approving) or set(expected_heads)!=set(approving):
            return False
        pd=policy_digest(policy); md=payload_digest(payload)
        for authority_id,signature in approving.items():
            raw=bytes.fromhex(policy["authorities"][authority_id])
            if len(raw)!=32:
                return False
            ledger=authority_ledgers[authority_id]
            head=expected_heads[authority_id]
            if not verify_approval_ledger(ledger,Ed25519PublicKey.from_public_bytes(raw),head):
                return False
            if ledger.get("authority_id")!=authority_id:
                return False
            matches=[event for event in ledger.get("events",[])
                if event.get("authority_id")==authority_id
                and event.get("policy_sha256")==pd
                and event.get("payload_sha256")==md
                and event.get("signature")==signature]
            if len(matches)!=1:
                return False
        return True
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError):
        return False
