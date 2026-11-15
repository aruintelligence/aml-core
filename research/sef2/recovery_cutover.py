"""Signed recovery-policy cutover acknowledgments.

A planned recovery council rotation is not considered globally activated until
a Byzantine-safe quorum of independently pinned verifier identities signs the
same rotation hash, target policy hash and generation.

This does not provide network consensus or force lagging verifiers to update;
it provides a portable activation certificate and explicit fault assumptions.
"""
import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from signed_receipt import canonical
from quorum_model import validate_bft_quorum

ACK_DOMAIN=b"AML-SEF2-RECOVERY-CUTOVER-ACK-V1\x00"
SCHEMA="AML-SEF2-RECOVERY-CUTOVER-CERTIFICATE-V1"

def rotation_digest(rotation):
    return hashlib.sha256(canonical(rotation)).hexdigest()

def make_cutover_ack(private_key,verifier_id,rotation,next_policy_sha256,generation):
    if (type(verifier_id) is not str or not verifier_id
        or type(next_policy_sha256) is not str or len(next_policy_sha256)!=64
        or type(generation) is not int or generation<1):
        raise ValueError("invalid recovery cutover scope")
    payload={"verifier_id":verifier_id,"rotation_sha256":rotation_digest(rotation),
        "next_policy_sha256":next_policy_sha256,"generation":generation}
    return {"payload":payload,
        "signature":private_key.sign(ACK_DOMAIN+canonical(payload)).hex()}

def build_cutover_certificate(rotation,next_policy_sha256,generation,acks):
    if type(acks) is not list:
        raise ValueError("acks must be a list")
    return {"schema":SCHEMA,"rotation_sha256":rotation_digest(rotation),
        "next_policy_sha256":next_policy_sha256,"generation":generation,"acks":acks}

def verify_cutover_certificate(certificate,rotation,next_policy_sha256,generation,
        pinned_verifier_keys,threshold,max_faults):
    try:
        if type(certificate) is not dict or set(certificate)!={"schema","rotation_sha256",
            "next_policy_sha256","generation","acks"}:
            return False
        if (certificate["schema"]!=SCHEMA
            or certificate["rotation_sha256"]!=rotation_digest(rotation)
            or certificate["next_policy_sha256"]!=next_policy_sha256
            or certificate["generation"]!=generation
            or type(certificate["acks"]) is not list
            or type(pinned_verifier_keys) is not dict):
            return False
        validate_bft_quorum(len(pinned_verifier_keys),threshold,max_faults)
        expected={"rotation_sha256":certificate["rotation_sha256"],
            "next_policy_sha256":next_policy_sha256,"generation":generation}
        seen=set()
        valid=0
        for ack in certificate["acks"]:
            if type(ack) is not dict or set(ack)!={"payload","signature"}:
                return False
            payload=ack["payload"]
            if type(payload) is not dict or set(payload)!={"verifier_id","rotation_sha256",
                "next_policy_sha256","generation"}:
                return False
            verifier_id=payload["verifier_id"]
            if verifier_id in seen or verifier_id not in pinned_verifier_keys:
                return False
            seen.add(verifier_id)
            if any(payload[k]!=v for k,v in expected.items()):
                return False
            raw=bytes.fromhex(pinned_verifier_keys[verifier_id])
            if len(raw)!=32:
                return False
            signature=bytes.fromhex(ack["signature"])
            if len(signature)!=64:
                return False
            Ed25519PublicKey.from_public_bytes(raw).verify(signature,
                ACK_DOMAIN+canonical(payload))
            valid+=1
        return valid>=threshold
    except (InvalidSignature,ValueError,TypeError,KeyError,OverflowError,AttributeError):
        return False
