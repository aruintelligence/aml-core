"""Action-bound Ed25519 capabilities for synthetic broker execution.

Capabilities are scoped to one exact request digest, issuer, audience and
policy epoch. The broker must separately pin the issuer key; a signed token
alone is not permission to bypass the evaluator or broker.
"""
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from signed_receipt import canonical
from gated_action_broker import canonical_request

DOMAIN=b"AML-SEF2-ACTION-CAPABILITY-V1\x00"
SCHEMA="AML-SEF2-ACTION-CAPABILITY-V1"

def issue_capability(private_key,issuer,audience,request,policy_epoch):
    if (type(issuer) is not str or not issuer or type(audience) is not str
        or not audience or type(policy_epoch) is not int or policy_epoch<0):
        raise ValueError("invalid capability scope")
    digest=hashlib.sha256(canonical_request(request)).hexdigest()
    payload={"schema":SCHEMA,"issuer":issuer,"audience":audience,
             "operation_id":request["operation_id"],"request_sha256":digest,
             "policy_epoch":policy_epoch}
    return {"payload":payload,"signature":private_key.sign(DOMAIN+canonical(payload)).hex()}

def verify_capability(envelope,public_hex,issuer,audience,request,policy_epoch):
    try:
        if type(envelope) is not dict or set(envelope)!={"payload","signature"}:
            return False
        p=envelope["payload"]
        if (type(p) is not dict or set(p)!={"schema","issuer","audience","operation_id","request_sha256","policy_epoch"}
            or p["schema"]!=SCHEMA or p["issuer"]!=issuer or p["audience"]!=audience
            or p["operation_id"]!=request["operation_id"]
            or type(p["policy_epoch"]) is not int or p["policy_epoch"]!=policy_epoch
            or p["request_sha256"]!=hashlib.sha256(canonical_request(request)).hexdigest()):
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
            bytes.fromhex(envelope["signature"]),DOMAIN+canonical(p))
        return True
    except (ValueError,TypeError,KeyError,InvalidSignature,OverflowError):
        return False
