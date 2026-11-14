"""Offline-authorized witness key replacement after suspected key compromise.

The recovery authority is a separately held trust root. No signature from the
suspected old witness key is required. The evaluator must supply the current
state from a separately protected monotonic registry; this module does not
provide anti-rollback storage for that state.
"""
import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from signed_receipt import canonical
from checkpoint_council import valid_checkpoint

AUTH_DOMAIN=b"AML-SEF2-WITNESS-KEY-RECOVERY-AUTH-V1\x00"
POP_DOMAIN=b"AML-SEF2-WITNESS-KEY-RECOVERY-POP-V1\x00"
SCHEMA="AML-SEF2-WITNESS-KEY-RECOVERY-V1"

def key_fingerprint(public_hex):
    raw=bytes.fromhex(public_hex)
    if len(raw)!=32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return hashlib.sha256(raw).hexdigest()

def state_digest(state):
    return hashlib.sha256(canonical(state)).hexdigest()

def make_transition(recovery_private,new_witness_private,witness_id,current_state,
                    checkpoint,recovery_authority_id):
    if type(witness_id) is not str or not witness_id or len(witness_id)>128:
        raise ValueError("invalid witness identity")
    if type(recovery_authority_id) is not str or not recovery_authority_id:
        raise ValueError("invalid recovery authority identity")
    if type(current_state) is not dict or set(current_state)!={"witness_id","generation","public_key_sha256","checkpoint","transition_sha256"}:
        raise ValueError("invalid current state")
    new_hex=new_witness_private.public_key().public_bytes_raw().hex()
    payload={"schema":SCHEMA,"witness_id":witness_id,
        "generation":current_state["generation"]+1,
        "previous_state_sha256":state_digest(current_state),
        "previous_public_key_sha256":current_state["public_key_sha256"],
        "new_public_key_hex":new_hex,
        "checkpoint":checkpoint,
        "recovery_authority_id":recovery_authority_id}
    auth_sig=recovery_private.sign(AUTH_DOMAIN+canonical(payload)).hex()
    pop_sig=new_witness_private.sign(POP_DOMAIN+canonical(payload)).hex()
    return {"payload":payload,"recovery_signature":auth_sig,"proof_of_possession":pop_sig}

def verify_transition(envelope,current_state,recovery_public_key,recovery_authority_id):
    try:
        if type(envelope) is not dict or set(envelope)!={"payload","recovery_signature","proof_of_possession"}:
            return False
        p=envelope["payload"]
        if type(p) is not dict or set(p)!={"schema","witness_id","generation","previous_state_sha256","previous_public_key_sha256","new_public_key_hex","checkpoint","recovery_authority_id"}:
            return False
        if type(current_state) is not dict or set(current_state)!={"witness_id","generation","public_key_sha256","checkpoint","transition_sha256"}:
            return False
        if (type(p["witness_id"]) is not str or type(current_state["witness_id"]) is not str
            or not p["witness_id"] or type(p["schema"]) is not str
            or not _digest(current_state["public_key_sha256"])
            or not _digest(current_state["transition_sha256"])
            or p["schema"]!=SCHEMA or p["witness_id"]!=current_state["witness_id"]
            or type(p["generation"]) is not int
            or p["generation"]!=current_state["generation"]+1
            or type(current_state["generation"]) is not int or current_state["generation"]<0
            or p["previous_state_sha256"]!=state_digest(current_state)
            or p["previous_public_key_sha256"]!=current_state["public_key_sha256"]
            or p["recovery_authority_id"]!=recovery_authority_id
            or not valid_checkpoint(p["checkpoint"])
            or not valid_checkpoint(current_state["checkpoint"])):
            return False
        old=current_state["checkpoint"]
        new=p["checkpoint"]
        if new["epoch"]<old["epoch"]:
            return False
        if new["epoch"]==old["epoch"] and new["head_hash"]!=old["head_hash"]:
            return False
        new_hex=p["new_public_key_hex"]
        new_raw=bytes.fromhex(new_hex)
        if len(new_raw)!=32 or key_fingerprint(new_hex)==current_state["public_key_sha256"]:
            return False
        recovery_public_key.verify(bytes.fromhex(envelope["recovery_signature"]),AUTH_DOMAIN+canonical(p))
        Ed25519PublicKey.from_public_bytes(new_raw).verify(
            bytes.fromhex(envelope["proof_of_possession"]),POP_DOMAIN+canonical(p))
        return True
    except (InvalidSignature,ValueError,TypeError,KeyError,OverflowError,AttributeError):
        return False

def advance_state(envelope,current_state,recovery_public_key,recovery_authority_id):
    if not verify_transition(envelope,current_state,recovery_public_key,recovery_authority_id):
        raise ValueError("invalid or stale witness key recovery transition")
    p=envelope["payload"]
    return {"witness_id":p["witness_id"],"generation":p["generation"],
        "public_key_sha256":key_fingerprint(p["new_public_key_hex"]),
        "checkpoint":dict(p["checkpoint"]),
        "transition_sha256":hashlib.sha256(canonical(envelope)).hexdigest()}

def _digest(value):
    return (type(value) is str and len(value)==64
        and all(c in "0123456789abcdef" for c in value))
