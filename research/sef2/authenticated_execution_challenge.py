"""Authenticated broker execution challenges for isolated holder proof services."""
import hashlib,secrets
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from signed_receipt import canonical
from gated_action_broker import canonical_request
from session_capability import capability_digest

DOMAIN=b"AML-SEF2-AUTHENTICATED-EXECUTION-CHALLENGE-V1\x00"
SCHEMA="AML-SEF2-AUTHENTICATED-EXECUTION-CHALLENGE-V1"

def make_execution_challenge(private_key,broker_id,audience,request,capability,policy_epoch,challenge=None):
    if (type(broker_id) is not str or not broker_id or type(audience) is not str or not audience
        or type(policy_epoch) is not int or policy_epoch<0):
        raise ValueError("invalid broker challenge scope")
    challenge=secrets.token_hex(32) if challenge is None else challenge
    if type(challenge) is not str or not 32<=len(challenge)<=128:
        raise ValueError("invalid challenge")
    payload={"schema":SCHEMA,"broker_id":broker_id,"audience":audience,
        "operation_id":request["operation_id"],
        "request_sha256":hashlib.sha256(canonical_request(request)).hexdigest(),
        "capability_sha256":capability_digest(capability),
        "policy_epoch":policy_epoch,"challenge":challenge}
    return {"payload":payload,"signature":private_key.sign(DOMAIN+canonical(payload)).hex()}

def verify_execution_challenge(envelope,broker_public_hex,broker_id,audience,request,capability,policy_epoch):
    try:
        if type(envelope) is not dict or set(envelope)!={"payload","signature"}: return False
        p=envelope["payload"]
        required={"schema","broker_id","audience","operation_id","request_sha256",
            "capability_sha256","policy_epoch","challenge"}
        if type(p) is not dict or set(p)!=required: return False
        if (p["schema"]!=SCHEMA or p["broker_id"]!=broker_id or p["audience"]!=audience
            or p["operation_id"]!=request["operation_id"]
            or p["request_sha256"]!=hashlib.sha256(canonical_request(request)).hexdigest()
            or p["capability_sha256"]!=capability_digest(capability)
            or type(p["policy_epoch"]) is not int or p["policy_epoch"]!=policy_epoch
            or type(p["challenge"]) is not str or not 32<=len(p["challenge"])<=128):
            return False
        raw=bytes.fromhex(broker_public_hex)
        if len(raw)!=32: return False
        sig=bytes.fromhex(envelope["signature"])
        if len(sig)!=64: return False
        Ed25519PublicKey.from_public_bytes(raw).verify(sig,DOMAIN+canonical(p))
        return True
    except (InvalidSignature,ValueError,TypeError,KeyError,OverflowError): return False
