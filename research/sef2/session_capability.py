"""Proof-of-possession, session-bound capabilities for synthetic SEF/2.

A capability is public and transferable as data but unusable without the
private holder key. Execution additionally requires a fresh broker challenge.
Security assumes the holder private key and generated proof are kept outside
model-visible conversation/context and inaccessible to the model itself.
"""
import hashlib,json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from signed_receipt import canonical
from gated_action_broker import canonical_request

CAP_DOMAIN=b"AML-SEF2-SESSION-CAPABILITY-V1\x00"
PROOF_DOMAIN=b"AML-SEF2-SESSION-HOLDER-PROOF-V1\x00"
CAP_SCHEMA="AML-SEF2-SESSION-CAPABILITY-V1"
PROOF_SCHEMA="AML-SEF2-SESSION-HOLDER-PROOF-V1"

def _public_hex(value):
    raw=bytes.fromhex(value)
    if len(raw)!=32: raise ValueError("holder public key must be Ed25519 raw 32 bytes")
    return value

def issue_session_capability(authority_private,issuer,audience,request,policy_epoch,holder_public_hex):
    if (type(issuer) is not str or not issuer or type(audience) is not str or not audience
        or type(policy_epoch) is not int or policy_epoch<0):
        raise ValueError("invalid capability scope")
    holder_public_hex=_public_hex(holder_public_hex)
    payload={"schema":CAP_SCHEMA,"issuer":issuer,"audience":audience,
        "operation_id":request["operation_id"],
        "request_sha256":hashlib.sha256(canonical_request(request)).hexdigest(),
        "policy_epoch":policy_epoch,"holder_public_key_hex":holder_public_hex}
    return {"payload":payload,"signature":authority_private.sign(CAP_DOMAIN+canonical(payload)).hex()}

def verify_session_capability(envelope,authority_public_hex,issuer,audience,request,policy_epoch):
    try:
        if type(envelope) is not dict or set(envelope)!={"payload","signature"}: return False
        p=envelope["payload"]
        required={"schema","issuer","audience","operation_id","request_sha256","policy_epoch","holder_public_key_hex"}
        if type(p) is not dict or set(p)!=required: return False
        _public_hex(p["holder_public_key_hex"])
        if (p["schema"]!=CAP_SCHEMA or p["issuer"]!=issuer or p["audience"]!=audience
            or p["operation_id"]!=request["operation_id"] or type(p["policy_epoch"]) is not int
            or p["policy_epoch"]!=policy_epoch
            or p["request_sha256"]!=hashlib.sha256(canonical_request(request)).hexdigest()):
            return False
        raw=bytes.fromhex(authority_public_hex)
        if len(raw)!=32: return False
        Ed25519PublicKey.from_public_bytes(raw).verify(bytes.fromhex(envelope["signature"]),
            CAP_DOMAIN+canonical(p))
        return True
    except (ValueError,TypeError,KeyError,InvalidSignature,OverflowError): return False

def capability_digest(capability):
    return hashlib.sha256(canonical(capability)).hexdigest()

def make_holder_proof(holder_private,capability,request,challenge):
    if type(challenge) is not str or not 32<=len(challenge)<=128:
        raise ValueError("invalid execution challenge")
    p=capability.get("payload") if type(capability) is dict else None
    if type(p) is not dict or type(p.get("holder_public_key_hex")) is not str:
        raise ValueError("invalid capability")
    if holder_private.public_key().public_bytes_raw().hex()!=p["holder_public_key_hex"]:
        raise ValueError("holder key does not match capability")
    payload={"schema":PROOF_SCHEMA,"capability_sha256":capability_digest(capability),
        "request_sha256":hashlib.sha256(canonical_request(request)).hexdigest(),
        "challenge":challenge}
    return {"payload":payload,"signature":holder_private.sign(PROOF_DOMAIN+canonical(payload)).hex()}

def verify_holder_proof(proof,capability,request,challenge):
    try:
        if type(proof) is not dict or set(proof)!={"payload","signature"}: return False
        p=proof["payload"]; required={"schema","capability_sha256","request_sha256","challenge"}
        if type(p) is not dict or set(p)!=required: return False
        cap=capability["payload"]; holder=bytes.fromhex(cap["holder_public_key_hex"])
        if len(holder)!=32: return False
        if (p["schema"]!=PROOF_SCHEMA or p["challenge"]!=challenge
            or p["capability_sha256"]!=capability_digest(capability)
            or p["request_sha256"]!=hashlib.sha256(canonical_request(request)).hexdigest()):
            return False
        Ed25519PublicKey.from_public_bytes(holder).verify(bytes.fromhex(proof["signature"]),
            PROOF_DOMAIN+canonical(p))
        return True
    except (ValueError,TypeError,KeyError,InvalidSignature,OverflowError): return False
