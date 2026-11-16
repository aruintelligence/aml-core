"""Broker-originated, nonce-bound signed action intent (synthetic SEF/2)."""
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from signed_receipt import canonical
from gated_action_broker import canonical_request

DOMAIN=b"AML-SEF2-BROKER-INTENT-V1\x00"
SCHEMA="AML-SEF2-BROKER-INTENT-V1"

def create_intent(private_key,broker_id,audience,request,challenge):
    if (type(broker_id) is not str or not broker_id or type(audience) is not str or not audience
        or type(challenge) is not str or not 32<=len(challenge)<=128):
        raise ValueError("invalid broker intent scope")
    payload={"schema":SCHEMA,"broker_id":broker_id,"audience":audience,
             "operation_id":request["operation_id"],
             "request_sha256":hashlib.sha256(canonical_request(request)).hexdigest(),
             "challenge":challenge}
    return {"payload":payload,
            "signature":private_key.sign(DOMAIN+canonical(payload)).hex()}

def verify_intent(envelope,public_hex,broker_id,audience,request):
    try:
        if type(envelope) is not dict or set(envelope)!={"payload","signature"}:
            return False
        p=envelope["payload"]
        if (type(p) is not dict or set(p)!={"schema","broker_id","audience","operation_id","request_sha256","challenge"}
            or p["schema"]!=SCHEMA or p["broker_id"]!=broker_id or p["audience"]!=audience
            or p["operation_id"]!=request["operation_id"]
            or type(p["challenge"]) is not str or not 32<=len(p["challenge"])<=128
            or p["request_sha256"]!=hashlib.sha256(canonical_request(request)).hexdigest()):
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
            bytes.fromhex(envelope["signature"]),DOMAIN+canonical(p))
        return True
    except (ValueError,TypeError,KeyError,InvalidSignature,OverflowError):
        return False
