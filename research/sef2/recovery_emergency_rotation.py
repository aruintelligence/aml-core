"""Distributed break-glass recovery-council replacement.

Emergency guardians cannot authorize actions or witness effects. They may only
authorize succession from the currently pinned recovery policy to a successor
policy, and the successor council must independently accept the exact same
transition. This is a separate root of trust and must be independently pinned.

No time-lock or human-identity proof is claimed here. The incident digest is an
opaque commitment to external incident evidence.
"""
from threshold_recovery import (RecoveryAuthoritySigner,make_approval_bundle,
    policy_digest,validate_policy,verify_approval_bundle)

SCHEMA="AML-SEF2-EMERGENCY-RECOVERY-ROTATION-V1"
REASONS={"QUORUM_LOSS","KEY_COMPROMISE","OPERATOR_LOSS","DISASTER_RECOVERY"}

def _require_disjoint(old_policy,new_policy):
    old_keys={bytes.fromhex(v) for v in old_policy["authorities"].values()}
    new_keys={bytes.fromhex(v) for v in new_policy["authorities"].values()}
    if old_keys & new_keys:
        raise ValueError("emergency successor must use disjoint public keys")
    if "administrative_domains" not in old_policy or "administrative_domains" not in new_policy:
        raise ValueError("emergency rotation requires explicit administrative domains")
    if set(old_policy["administrative_domains"].values()) & set(new_policy["administrative_domains"].values()):
        raise ValueError("emergency successor must use disjoint administrative domains")
    if new_policy["max_faults"]<old_policy["max_faults"]:
        raise ValueError("emergency rotation cannot reduce Byzantine fault bound")

def make_emergency_rotation(current_policy,next_policy,emergency_policy,generation,
        current_registry_head,incident_sha256,reason,guardian_signers,incoming_signers):
    if not all(validate_policy(p) for p in (current_policy,next_policy,emergency_policy)):
        raise ValueError("invalid emergency recovery policy input")
    if type(generation) is not int or generation<1:
        raise ValueError("invalid emergency generation")
    if type(current_registry_head) is not str or len(current_registry_head)!=64:
        raise ValueError("invalid current registry head")
    if type(incident_sha256) is not str or len(incident_sha256)!=64:
        raise ValueError("invalid incident digest")
    if any(c not in "0123456789abcdef" for c in current_registry_head+incident_sha256):
        raise ValueError("noncanonical digest")
    if reason not in REASONS:
        raise ValueError("invalid emergency reason")
    _require_disjoint(current_policy,next_policy)
    if (type(guardian_signers) is not dict or type(incoming_signers) is not dict
        or any(not isinstance(s,RecoveryAuthoritySigner) for s in guardian_signers.values())
        or any(not isinstance(s,RecoveryAuthoritySigner) for s in incoming_signers.values())):
        raise ValueError("emergency rotation requires durable anti-equivocation signers")
    payload={"schema":SCHEMA,"generation":generation,
        "witness_id":"emergency-recovery-policy",
        "previous_state_sha256":current_registry_head,
        "current_policy_sha256":policy_digest(current_policy),
        "next_policy_sha256":policy_digest(next_policy),
        "emergency_policy_sha256":policy_digest(emergency_policy),
        "incident_sha256":incident_sha256,"reason":reason}
    return {"schema":SCHEMA,"payload":payload,
        "guardian_approval":make_approval_bundle(payload,emergency_policy,guardian_signers),
        "incoming_acceptance":make_approval_bundle(payload,next_policy,incoming_signers)}

def verify_emergency_rotation(current_policy,next_policy,emergency_policy,rotation,
        expected_generation,expected_registry_head):
    try:
        if not all(validate_policy(p) for p in (current_policy,next_policy,emergency_policy)):
            return False
        _require_disjoint(current_policy,next_policy)
        if type(rotation) is not dict or set(rotation)!={"schema","payload","guardian_approval","incoming_acceptance"}:
            return False
        p=rotation["payload"]
        if type(p) is not dict or set(p)!={"schema","generation","witness_id",
            "previous_state_sha256","current_policy_sha256","next_policy_sha256",
            "emergency_policy_sha256","incident_sha256","reason"}:
            return False
        if (rotation["schema"]!=SCHEMA or p["schema"]!=SCHEMA
            or p["generation"]!=expected_generation
            or p["witness_id"]!="emergency-recovery-policy"
            or p["previous_state_sha256"]!=expected_registry_head
            or p["current_policy_sha256"]!=policy_digest(current_policy)
            or p["next_policy_sha256"]!=policy_digest(next_policy)
            or p["emergency_policy_sha256"]!=policy_digest(emergency_policy)
            or p["reason"] not in REASONS
            or type(p["incident_sha256"]) is not str or len(p["incident_sha256"])!=64
            or any(c not in "0123456789abcdef" for c in p["incident_sha256"])):
            return False
        return (verify_approval_bundle(p,rotation["guardian_approval"],emergency_policy)
            and verify_approval_bundle(p,rotation["incoming_acceptance"],next_policy))
    except (ValueError,TypeError,KeyError,OverflowError,AttributeError):
        return False
