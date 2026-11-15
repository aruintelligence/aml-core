"""Dual-consent rotation proof for the recovery anchor council.

Both the outgoing and incoming anchor councils must produce threshold approval
bundles over the exact same rotation payload. Durable RecoveryAuthoritySigner
instances provide per-identity anti-equivocation ledgers. This module verifies
the handoff proof; it does not mutate RecoveryAnchorWitness state.
"""
from threshold_recovery import (POLICY_SCHEMA as RECOVERY_POLICY_SCHEMA,
    RecoveryAuthoritySigner,make_approval_bundle,verify_approval_bundle)
from recovery_anchor_quorum import validate_anchor_policy,policy_digest

SCHEMA="AML-SEF2-RECOVERY-ANCHOR-POLICY-ROTATION-V1"

def _shadow(policy):
    return {"schema":RECOVERY_POLICY_SCHEMA,"policy_id":policy["policy_id"],
        "threshold":policy["threshold"],"max_faults":policy["max_faults"],
        "authorities":dict(policy["authorities"])}

def make_anchor_policy_rotation(current_policy,next_policy,generation,
        previous_anchor_pin,old_signers,new_signers):
    if not validate_anchor_policy(current_policy) or not validate_anchor_policy(next_policy):
        raise ValueError("invalid current or successor anchor policy")
    if type(generation) is not int or generation<1:
        raise ValueError("invalid anchor policy generation")
    if type(previous_anchor_pin) is not str or len(previous_anchor_pin)!=64 or any(c not in "0123456789abcdef" for c in previous_anchor_pin):
        raise ValueError("invalid previous anchor pin")
    if current_policy["policy_id"]==next_policy["policy_id"] or policy_digest(current_policy)==policy_digest(next_policy):
        raise ValueError("successor anchor policy must differ and use a new policy id")
    old_keys={bytes.fromhex(v) for v in current_policy["authorities"].values()}
    new_keys={bytes.fromhex(v) for v in next_policy["authorities"].values()}
    if old_keys & new_keys:
        raise ValueError("successor anchor council must use disjoint public keys")
    if (set(current_policy["administrative_domains"].values())
        & set(next_policy["administrative_domains"].values())):
        raise ValueError("successor anchor council must use disjoint administrative domains")
    payload={"schema":SCHEMA,"generation":generation,"witness_id":"recovery-anchor-policy",
        "previous_state_sha256":policy_digest(current_policy),
        "previous_policy_sha256":policy_digest(current_policy),
        "next_policy_sha256":policy_digest(next_policy),
        "previous_anchor_pin":previous_anchor_pin}
    return {"schema":SCHEMA,"payload":payload,
        "outgoing_approval":make_approval_bundle(payload,_shadow(current_policy),old_signers),
        "incoming_acceptance":make_approval_bundle(payload,_shadow(next_policy),new_signers)}

def verify_anchor_policy_rotation(current_policy,next_policy,rotation,
        expected_generation,expected_previous_anchor_pin):
    try:
        if not validate_anchor_policy(current_policy) or not validate_anchor_policy(next_policy):
            return False
        if type(expected_generation) is not int or expected_generation<1:
            return False
        if type(expected_previous_anchor_pin) is not str or len(expected_previous_anchor_pin)!=64:
            return False
        if type(rotation) is not dict or set(rotation)!={"schema","payload","outgoing_approval","incoming_acceptance"}:
            return False
        p=rotation["payload"]
        required={"schema","generation","witness_id","previous_state_sha256",
            "previous_policy_sha256","next_policy_sha256","previous_anchor_pin"}
        if type(p) is not dict or set(p)!=required:
            return False
        old_digest=policy_digest(current_policy); new_digest=policy_digest(next_policy)
        if (rotation["schema"]!=SCHEMA or p["schema"]!=SCHEMA
            or p["generation"]!=expected_generation
            or p["witness_id"]!="recovery-anchor-policy"
            or p["previous_state_sha256"]!=old_digest
            or p["previous_policy_sha256"]!=old_digest
            or p["next_policy_sha256"]!=new_digest
            or p["previous_anchor_pin"]!=expected_previous_anchor_pin
            or current_policy["policy_id"]==next_policy["policy_id"]
            or old_digest==new_digest):
            return False
        if ({bytes.fromhex(v) for v in current_policy["authorities"].values()}
            & {bytes.fromhex(v) for v in next_policy["authorities"].values()}):
            return False
        if (set(current_policy["administrative_domains"].values())
            & set(next_policy["administrative_domains"].values())):
            return False
        return (verify_approval_bundle(p,rotation["outgoing_approval"],_shadow(current_policy))
            and verify_approval_bundle(p,rotation["incoming_acceptance"],_shadow(next_policy)))
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError):
        return False
