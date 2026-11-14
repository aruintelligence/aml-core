"""Signed replica identity attestations, bound to evaluator-pinned public keys.

These are offline signed observations, not networked independent authorities.
Trust depends on out-of-band enrollment, key isolation and non-rollbackable
evaluator policy. Replaying an old signed observation is detected only against
the evaluator's independently retained current generation.
"""
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from signed_receipt import canonical
from pin_registry import _pin

DOMAIN=b"AML-SEF2-PIN-REPLICA-V1\x00"

def attest(replica,replica_id,witness,private_key):
    if type(replica_id) is not str or not replica_id:
        raise ValueError("invalid replica identity")
    generation,pin=replica.latest(witness)
    payload={"schema":"AML-SEF2-PIN-REPLICA-ATTESTATION-V1",
             "replica_id":replica_id,"witness_id":witness,
             "generation":generation,"pin":pin}
    return {"payload":payload,"signature":private_key.sign(DOMAIN+canonical(payload)).hex()}

def verify_attestations(registry,witness,attestations,enrolled_keys):
    """All enrolled identities must attest current state; zero Byzantine tolerance."""
    if (type(attestations) is not list or type(enrolled_keys) is not dict
        or len(enrolled_keys)<2 or len(attestations)!=len(enrolled_keys)
        or len(set(enrolled_keys.values()))!=len(enrolled_keys)):
        return False
    try:
        state=registry.state(witness)
        seen=set()
        for envelope in attestations:
            if type(envelope) is not dict or set(envelope)!={"payload","signature"}:
                return False
            payload=envelope["payload"]
            if type(payload) is not dict or set(payload)!={"schema","replica_id","witness_id","generation","pin"}:
                return False
            identity=payload["replica_id"]
            if (type(identity) is not str or identity not in enrolled_keys or identity in seen
                or payload["schema"]!="AML-SEF2-PIN-REPLICA-ATTESTATION-V1"
                or payload["witness_id"]!=witness or type(payload["generation"]) is not int
                or payload["generation"]!=state["generation"] or not _pin(payload["pin"])
                or payload["pin"]!=state["active"]):
                return False
            key=Ed25519PublicKey.from_public_bytes(bytes.fromhex(enrolled_keys[identity]))
            key.verify(bytes.fromhex(envelope["signature"]),DOMAIN+canonical(payload))
            seen.add(identity)
        return seen==set(enrolled_keys)
    except (OSError,ValueError,TypeError,KeyError,InvalidSignature,OverflowError):
        return False
