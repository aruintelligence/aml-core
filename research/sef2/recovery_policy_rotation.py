"""Dual-consent recovery council rotation.

The outgoing council authorizes succession and the incoming council proves
acceptance. Verifiers must pin the current policy and last accepted generation
outside the rotating council's unilateral control.
"""
from threshold_recovery import (policy_digest,validate_policy,make_approval_bundle,
    verify_approval_bundle)

ROTATION_SCHEMA="AML-SEF2-RECOVERY-POLICY-ROTATION-V1"

def make_policy_rotation(current_policy,next_policy,generation,old_signers,new_signers):
    if not validate_policy(current_policy) or not validate_policy(next_policy):
        raise ValueError("invalid current or successor recovery policy")
    if type(generation) is not int or generation<1:
        raise ValueError("invalid policy generation")
    if policy_digest(current_policy)==policy_digest(next_policy):
        raise ValueError("successor policy must differ")
    payload={"schema":ROTATION_SCHEMA,"generation":generation,
        "previous_policy_sha256":policy_digest(current_policy),
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
        if type(payload) is not dict or set(payload)!={"schema","generation","previous_policy_sha256","next_policy_sha256"}:
            return False
        if (rotation["schema"]!=ROTATION_SCHEMA or payload["schema"]!=ROTATION_SCHEMA
            or type(payload["generation"]) is not int or payload["generation"]!=expected_generation
            or payload["previous_policy_sha256"]!=policy_digest(current_policy)
            or payload["next_policy_sha256"]!=policy_digest(next_policy)
            or policy_digest(current_policy)==policy_digest(next_policy)):
            return False
        return (verify_approval_bundle(payload,rotation["outgoing_approval"],current_policy)
            and verify_approval_bundle(payload,rotation["incoming_acceptance"],next_policy))
    except (ValueError,TypeError,KeyError,AttributeError):
        return False
