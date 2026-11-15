"""Independent recovery transparency verifier.

Verifies a threshold-authorized witness recovery against:
- a pinned recovery policy digest,
- the exact predecessor state digest,
- the threshold recovery transition,
- independently pinned heads of every approving authority's append-only ledger.

This does not prove the authority operators are independent or that their pinned
ledger heads were distributed securely. It makes the recovery evidence
reproducible by an external evaluator under those trust assumptions.
"""
import json
from witness_key_recovery import verify_transition,state_digest
from threshold_recovery import (ThresholdRecoveryPublicKey,policy_digest,payload_digest,
    verify_approval_bundle,verify_approval_ledger)

SCHEMA="AML-SEF2-RECOVERY-TRANSPARENCY-BUNDLE-V1"

def build_recovery_transparency_bundle(current_state,transition,policy,authority_ledgers):
    if type(authority_ledgers) is not dict:
        raise ValueError("authority ledgers must be a mapping")
    try:
        approvals=json.loads(bytes.fromhex(transition["recovery_signature"]).decode("utf-8"))
    except (ValueError,TypeError,KeyError,UnicodeDecodeError) as exc:
        raise ValueError("transition does not contain canonical threshold approvals") from exc
    approvers=[item["authority_id"] for item in approvals.get("approvals",[])]
    if set(approvers)!=set(authority_ledgers):
        raise ValueError("must provide exactly the approving authority ledgers")
    return {"schema":SCHEMA,
        "policy_sha256":policy_digest(policy),
        "predecessor_state_sha256":state_digest(current_state),
        "transition":transition,
        "authority_ledgers":authority_ledgers}

def verify_recovery_transparency_bundle(bundle,current_state,policy,
        pinned_policy_sha256,pinned_authority_heads):
    try:
        if type(bundle) is not dict or set(bundle)!={"schema","policy_sha256",
            "predecessor_state_sha256","transition","authority_ledgers"}:
            return False
        if bundle["schema"]!=SCHEMA or bundle["policy_sha256"]!=pinned_policy_sha256:
            return False
        if policy_digest(policy)!=pinned_policy_sha256:
            return False
        if bundle["predecessor_state_sha256"]!=state_digest(current_state):
            return False
        transition=bundle["transition"]
        verifier=ThresholdRecoveryPublicKey(policy)
        if not verify_transition(transition,current_state,verifier,policy["policy_id"]):
            return False
        approvals=json.loads(bytes.fromhex(transition["recovery_signature"]).decode("utf-8"))
        if not verify_approval_bundle(transition["payload"],approvals,policy):
            return False
        approval_by_id={item["authority_id"]:item for item in approvals["approvals"]}
        if len(approval_by_id)!=len(approvals["approvals"]):
            return False
        ledgers=bundle["authority_ledgers"]
        if type(ledgers) is not dict or set(ledgers)!=set(approval_by_id):
            return False
        if type(pinned_authority_heads) is not dict or set(pinned_authority_heads)!=set(approval_by_id):
            return False
        pd=policy_digest(policy)
        digest=payload_digest(transition["payload"])
        payload=transition["payload"]
        for authority_id,approval in approval_by_id.items():
            ledger=ledgers[authority_id]
            public_hex=policy["authorities"].get(authority_id)
            if public_hex is None:
                return False
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            public=Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
            if not verify_approval_ledger(ledger,public,pinned_authority_heads[authority_id]):
                return False
            matching=[event for event in ledger["events"]
                if event["authority_id"]==authority_id
                and event["witness_id"] in (
                    payload["schema"]+":"+payload["witness_id"],
                    payload["witness_id"])
                and event["generation"]==payload["generation"]
                and event["policy_sha256"]==pd
                and event["previous_state_sha256"]==payload["previous_state_sha256"]
                and event["payload_sha256"]==digest
                and event["signature"]==approval["signature"]]
            if len(matching)!=1:
                return False
        return True
    except (ValueError,TypeError,KeyError,OverflowError,AttributeError,UnicodeDecodeError):
        return False
