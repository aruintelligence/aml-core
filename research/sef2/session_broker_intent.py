"""Broker-authenticated intent for issuing holder-bound session capabilities."""
import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from signed_receipt import canonical
from gated_action_broker import canonical_request

DOMAIN=b"AML-SEF2-SESSION-BROKER-INTENT-V1\x00"
SCHEMA="AML-SEF2-SESSION-BROKER-INTENT-V1"

def _holder(value):
    raw=bytes.fromhex(value)
    if len(raw)!=32: raise ValueError("holder public key must be 32-byte Ed25519")
    return value

def create_session_intent(private_key,broker_id,audience,request,challenge,policy_epoch,holder_public_hex):
    if (type(broker_id) is not str or not broker_id or type(audience) is not str or not audience
        or type(challenge) is not str or not 32<=len(challenge)<=128
        or type(policy_epoch) is not int or policy_epoch<0):
        raise ValueError("invalid session intent scope")
    holder_public_hex=_holder(holder_public_hex)
    payload={"schema":SCHEMA,"broker_id":broker_id,"audience":audience,
        "operation_id":request["operation_id"],
        "request_sha256":hashlib.sha256(canonical_request(request)).hexdigest(),
        "challenge":challenge,"policy_epoch":policy_epoch,
        "holder_public_key_hex":holder_public_hex}
    return {"payload":payload,"signature":private_key.sign(DOMAIN+canonical(payload)).hex()}

def verify_session_intent(envelope,broker_public_hex,broker_id,audience,request,policy_epoch):
    try:
        if type(envelope) is not dict or set(envelope)!={"payload","signature"}: return False
        p=envelope["payload"]
        required={"schema","broker_id","audience","operation_id","request_sha256",
            "challenge","policy_epoch","holder_public_key_hex"}
        if type(p) is not dict or set(p)!=required: return False
        _holder(p["holder_public_key_hex"])
        if (p["schema"]!=SCHEMA or p["broker_id"]!=broker_id or p["audience"]!=audience
            or p["operation_id"]!=request["operation_id"]
            or p["request_sha256"]!=hashlib.sha256(canonical_request(request)).hexdigest()
            or type(p["challenge"]) is not str or not 32<=len(p["challenge"])<=128
            or type(p["policy_epoch"]) is not int or p["policy_epoch"]!=policy_epoch):
            return False
        raw=bytes.fromhex(broker_public_hex)
        if len(raw)!=32: return False
        sig=bytes.fromhex(envelope["signature"])
        if len(sig)!=64: return False
        Ed25519PublicKey.from_public_bytes(raw).verify(sig,DOMAIN+canonical(p))
        return True
    except (InvalidSignature,ValueError,TypeError,KeyError,OverflowError): return False
