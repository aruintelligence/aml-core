"""Bind recovery-policy registry generations to an independent anchor quorum.

The generic anchor checkpoint's authority_key_sha256 field is used here as a
fingerprint of the complete recovery council public-key set (sorted identity
and public-key pairs), not as the fingerprint of one member key. The registry
head commits to the full policy, transition history, and generation.
"""
import hashlib
from signed_receipt import canonical
from threshold_recovery import validate_policy,policy_digest
from recovery_anchor_quorum import (CHECKPOINT_SCHEMA,checkpoint_pin,make_anchor_payload,
    verify_anchor_certificate)

REGISTRY_ID_DEFAULT="aml-sef2-recovery-policy-registry-v1"

def authority_set_fingerprint(policy):
    if not validate_policy(policy): raise ValueError("invalid recovery policy")
    members=sorted(policy["authorities"].items())
    return hashlib.sha256(canonical({"policy_id":policy["policy_id"],"members":members})).hexdigest()

def registry_checkpoint(state,registry_id=REGISTRY_ID_DEFAULT):
    if type(state) is not dict or set(state)!={"generation","policy","policy_sha256","head_sha256"}:
        raise ValueError("invalid recovery policy registry state")
    policy=state["policy"]
    if (type(state["generation"]) is not int or state["generation"]<1
        or not validate_policy(policy) or state["policy_sha256"]!=policy_digest(policy)):
        raise ValueError("invalid recovery policy registry state")
    for field in ("head_sha256",):
        value=state[field]
        if type(value) is not str or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("invalid recovery policy registry head")
    if type(registry_id) is not str or not registry_id:
        raise ValueError("invalid registry identity")
    return {"schema":CHECKPOINT_SCHEMA,"authority_id":registry_id,
        "authority_key_sha256":authority_set_fingerprint(policy),
        "sequence":state["generation"],"head_hash":state["head_sha256"]}

def make_registry_anchor_payload(state,sequence,previous_pin_sha256,anchor_policy,
                                  registry_id=REGISTRY_ID_DEFAULT):
    checkpoint=registry_checkpoint(state,registry_id)
    if type(sequence) is not int or sequence!=checkpoint["sequence"]:
        raise ValueError("anchor sequence must equal registry generation")
    return make_anchor_payload(checkpoint,sequence,previous_pin_sha256,anchor_policy)

def verify_registry_anchor(state,payload,certificate,anchor_policy,expected_sequence,
                           expected_previous_pin,registry_id=REGISTRY_ID_DEFAULT):
    try:
        expected=registry_checkpoint(state,registry_id)
        if type(payload) is not dict or payload.get("checkpoint")!=expected:
            return False
        return verify_anchor_certificate(payload,certificate,anchor_policy,
            expected_sequence,expected_previous_pin,registry_id,
            expected["authority_key_sha256"])
    except (ValueError,TypeError,KeyError,AttributeError):
        return False

def registry_checkpoint_pin(state,registry_id=REGISTRY_ID_DEFAULT):
    return checkpoint_pin(registry_checkpoint(state,registry_id))
