"""Dual-consent recovery council rotation.

The outgoing council authorizes succession and the incoming council proves
acceptance. Verifiers must pin the current policy and last accepted generation
outside the rotating council's unilateral control.
"""
from threshold_recovery import (policy_digest,validate_policy,make_approval_bundle,
    verify_approval_bundle,RecoveryAuthoritySigner)

ROTATION_SCHEMA="AML-SEF2-RECOVERY-POLICY-ROTATION-V1"

def make_policy_rotation(current_policy,next_policy,generation,old_signers,new_signers):
    if not validate_policy(current_policy) or not validate_policy(next_policy):
        raise ValueError("invalid current or successor recovery policy")
    if type(generation) is not int or generation<1:
        raise ValueError("invalid policy generation")
    if (current_policy["policy_id"]==next_policy["policy_id"]
        or policy_digest(current_policy)==policy_digest(next_policy)):
        raise ValueError("successor policy must use a new policy identifier and differ")
    old_keys={bytes.fromhex(value) for value in current_policy["authorities"].values()}
    next_keys={bytes.fromhex(value) for value in next_policy["authorities"].values()}
    if old_keys & next_keys:
        raise ValueError("successor recovery council must use disjoint public keys")
    if "administrative_domains" not in current_policy or "administrative_domains" not in next_policy:
        raise ValueError("planned rotation requires explicit administrative domains")
    old_domains=set(current_policy["administrative_domains"].values())
    next_domains=set(next_policy["administrative_domains"].values())
    if old_domains & next_domains:
        raise ValueError("successor recovery council must use disjoint administrative domains")
    if next_policy["max_faults"]<current_policy["max_faults"]:
        raise ValueError("planned rotation cannot reduce Byzantine fault bound")
    if (type(old_signers) is not dict or type(new_signers) is not dict
        or any(not isinstance(s,RecoveryAuthoritySigner) for s in old_signers.values())
        or any(not isinstance(s,RecoveryAuthoritySigner) for s in new_signers.values())):
        raise ValueError("policy rotation requires durable anti-equivocation signers")
    previous=policy_digest(current_policy)
    payload={"schema":ROTATION_SCHEMA,"generation":generation,
        "witness_id":"recovery-policy","previous_state_sha256":previous,
        "previous_policy_sha256":previous,
        "next_policy_sha256":policy_digest(next_policy)}
    old_approval=make_approval_bundle(payload,current_policy,old_signers)
    new_acceptance=make_approval_bundle(payload,next_policy,new_signers)
    return {"schema":ROTATION_SCHEMA,"payload":payload,
        "outgoing_approval":old_approval,"incoming_acceptance":new_acceptance}

def verify_policy_rotation(current_policy,next_policy,rotation,expected_generation):
    try:
        if not validate_policy(current_policy) or not validate_policy(next_policy):
            return False
        if type(expected_generation) is not int or expected_generation<1:
            return False
        if type(rotation) is not dict or set(rotation)!={"schema","payload","outgoing_approval","incoming_acceptance"}:
            return False
        payload=rotation["payload"]
        if type(payload) is not dict or set(payload)!={"schema","generation","witness_id","previous_state_sha256","previous_policy_sha256","next_policy_sha256"}:
            return False
        if (rotation["schema"]!=ROTATION_SCHEMA or payload["schema"]!=ROTATION_SCHEMA
            or type(payload["generation"]) is not int or payload["generation"]!=expected_generation
            or payload["witness_id"]!="recovery-policy"
            or payload["previous_state_sha256"]!=policy_digest(current_policy)
            or payload["previous_policy_sha256"]!=policy_digest(current_policy)
            or payload["next_policy_sha256"]!=policy_digest(next_policy)
            or current_policy["policy_id"]==next_policy["policy_id"]
            or policy_digest(current_policy)==policy_digest(next_policy)
            or ({bytes.fromhex(v) for v in current_policy["authorities"].values()}
                & {bytes.fromhex(v) for v in next_policy["authorities"].values()})
            or "administrative_domains" not in current_policy
            or "administrative_domains" not in next_policy
            or (set(current_policy["administrative_domains"].values())
                & set(next_policy["administrative_domains"].values()))
            or next_policy["max_faults"]<current_policy["max_faults"]):
            return False
        return (verify_approval_bundle(payload,rotation["outgoing_approval"],current_policy)
            and verify_approval_bundle(payload,rotation["incoming_acceptance"],next_policy))
    except (ValueError,TypeError,KeyError,AttributeError):
        return False
