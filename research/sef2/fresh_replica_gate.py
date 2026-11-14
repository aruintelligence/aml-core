"""Authenticated challenge-response for replica state freshness (synthetic).

The evaluator chooses an unpredictable nonce and validates signatures from
enrolled replica identities. A signature proves response to that challenge,
not that a remote service or separate administrator exists. The verifier
must generate its own nonce; callers must not supply a reusable challenge.
"""
import secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from signed_receipt import canonical
from pin_registry import _pin

DOMAIN=b"AML-SEF2-FRESH-REPLICA-V1\x00"
SCHEMA="AML-SEF2-FRESH-REPLICA-V1"

def sign_challenge(replica,identity,witness,nonce,private_key):
    if (type(identity) is not str or not identity or type(witness) is not str
        or not witness or type(nonce) is not str or len(nonce)!=64):
        raise ValueError("invalid challenge")
    bytes.fromhex(nonce)
    generation,pin=replica.latest(witness)
    payload={"schema":SCHEMA,"identity":identity,"witness":witness,
             "nonce":nonce,"generation":generation,"pin":pin}
    return {"payload":payload,"signature":private_key.sign(DOMAIN+canonical(payload)).hex()}

def verify_fresh(registry,witness,replicas,enrolled_keys,responders,nonce_factory=None):
    """Challenge every enrolled identity; all must agree with durable state.

    Responders are callables owned by independent signers in a real deployment.
    The default challenge is generated inside the evaluator. Injection is
    intended only for deterministic research tests.
    """
    if (type(enrolled_keys) is not dict or len(enrolled_keys)<2
        or type(responders) is not dict or set(responders)!=set(enrolled_keys)
        or len(set(enrolled_keys.values()))!=len(enrolled_keys)
        or len(replicas)!=len(enrolled_keys)):
        return False
    try:
        from pin_replication import verified_state
        state=verified_state(registry,witness,replicas,2)
        nonce=secrets.token_hex(32) if nonce_factory is None else nonce_factory()
        if type(nonce) is not str or len(nonce)!=64 or len(bytes.fromhex(nonce))!=32:
            return False
        for identity,responder in responders.items():
            envelope=responder(nonce)
            if type(envelope) is not dict or set(envelope)!={"payload","signature"}:
                return False
            payload=envelope["payload"]
            if (type(payload) is not dict
                or set(payload)!={"schema","identity","witness","nonce","generation","pin"}
                or payload["schema"]!=SCHEMA or payload["identity"]!=identity
                or payload["witness"]!=witness or payload["nonce"]!=nonce
                or type(payload["generation"]) is not int
                or payload["generation"]!=state["generation"] or not _pin(payload["pin"])
                or payload["pin"]!=state["active"]):
                return False
            key=Ed25519PublicKey.from_public_bytes(bytes.fromhex(enrolled_keys[identity]))
            key.verify(bytes.fromhex(envelope["signature"]),DOMAIN+canonical(payload))
        return True
    except (OSError,ValueError,TypeError,KeyError,InvalidSignature,OverflowError):
        return False
