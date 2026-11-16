"""Signed policy-floor transitions for the SEF2 synthetic effect authority.

The pinned verification key must be configured by the operator outside the
untrusted agent's control. This does not provide rollback resistance if the
effect database itself can be restored to an older snapshot.
"""
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

DOMAIN = b"AML-SEF2-POLICY-FLOOR-V1\x00"
SCHEMA = "AML-SEF2-POLICY-FLOOR-V1"

def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sign_transition(private_key, authority_id, generation):
    if (type(authority_id) is not str or not authority_id
        or type(generation) is not int or generation < 0):
        raise ValueError("invalid policy floor transition")
    payload = {"schema": SCHEMA, "authority_id": authority_id, "generation": generation}
    return {"payload": payload, "signature": private_key.sign(DOMAIN + canonical(payload)).hex()}

def verify_transition(envelope, public_key_hex, authority_id):
    try:
        if type(envelope) is not dict or set(envelope) != {"payload", "signature"}:
            return None
        payload = envelope["payload"]
        if (type(payload) is not dict
            or set(payload) != {"schema", "authority_id", "generation"}
            or payload["schema"] != SCHEMA or payload["authority_id"] != authority_id
            or type(payload["generation"]) is not int or payload["generation"] < 0
            or type(envelope["signature"]) is not str):
            return None
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            bytes.fromhex(envelope["signature"]), DOMAIN + canonical(payload))
        return payload["generation"]
    except (ValueError, TypeError, KeyError, InvalidSignature, OverflowError):
        return None

class SignedPolicyFloor:
    """Operator-side verified floor adapter; never expose raw floor advancement to agents."""
    def __init__(self, effect_authority, public_key_hex, authority_id):
        self.effect_authority = effect_authority
        self.public_key_hex = public_key_hex
        self.authority_id = authority_id

    def apply(self, envelope):
        generation = verify_transition(envelope, self.public_key_hex, self.authority_id)
        if generation is None:
            return False
        return self.effect_authority.advance_policy_floor(generation)
