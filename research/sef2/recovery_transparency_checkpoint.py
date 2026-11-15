"""Deterministic recovery transparency checkpoint.

Combines the active recovery policy digest, policy-registry head, and every
recovery-authority approval-ledger head into one hash that can be pinned by an
independent compare-and-set/quorum anchor.
"""
import hashlib
from signed_receipt import canonical
from threshold_recovery import policy_digest,validate_policy

SCHEMA="AML-SEF2-RECOVERY-TRANSPARENCY-CHECKPOINT-V1"

def _hex64(value):
    return type(value) is str and len(value)==64 and all(c in "0123456789abcdef" for c in value)

def build_transparency_checkpoint(policy,policy_generation,policy_registry_head,authority_heads):
    if not validate_policy(policy):
        raise ValueError("invalid recovery policy")
    if type(policy_generation) is not int or policy_generation<1:
        raise ValueError("invalid recovery policy generation")
    if not _hex64(policy_registry_head):
        raise ValueError("invalid recovery policy registry head")
    if type(authority_heads) is not dict or set(authority_heads)!=set(policy["authorities"]):
        raise ValueError("authority heads must cover the complete recovery council")
    if any(type(name) is not str or not name or not _hex64(head)
           for name,head in authority_heads.items()):
        raise ValueError("invalid recovery authority head")
    payload={"schema":SCHEMA,"policy_generation":policy_generation,
        "policy_sha256":policy_digest(policy),
        "policy_registry_head_sha256":policy_registry_head,
        "authority_heads":{name:authority_heads[name] for name in sorted(authority_heads)}}
    root=hashlib.sha256(canonical(payload)).hexdigest()
    return {"payload":payload,"checkpoint_sha256":root}

def verify_transparency_checkpoint(checkpoint,policy,expected_generation=None,
                                   expected_checkpoint_sha256=None):
    try:
        if type(checkpoint) is not dict or set(checkpoint)!={"payload","checkpoint_sha256"}:
            return False
        p=checkpoint["payload"]
        if type(p) is not dict or set(p)!={"schema","policy_generation","policy_sha256",
            "policy_registry_head_sha256","authority_heads"}:
            return False
        if p["schema"]!=SCHEMA or not validate_policy(policy):
            return False
        if type(p["policy_generation"]) is not int or p["policy_generation"]<1:
            return False
        if expected_generation is not None and p["policy_generation"]!=expected_generation:
            return False
        if p["policy_sha256"]!=policy_digest(policy):
            return False
        if not _hex64(p["policy_registry_head_sha256"]):
            return False
        heads=p["authority_heads"]
        if type(heads) is not dict or list(heads)!=sorted(heads) or set(heads)!=set(policy["authorities"]):
            return False
        if any(not _hex64(value) for value in heads.values()):
            return False
        calculated=hashlib.sha256(canonical(p)).hexdigest()
        if checkpoint["checkpoint_sha256"]!=calculated:
            return False
        if expected_checkpoint_sha256 is not None and calculated!=expected_checkpoint_sha256:
            return False
        return True
    except (ValueError,TypeError,KeyError,AttributeError):
        return False
