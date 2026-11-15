"""Signed evaluator authorization for an independent effect executor.

The evaluator issues this receipt only after strict replica/pin verification.
The receipt binds the exact request, capability, broker challenge, policy epoch,
and the evaluator-observed registry state. It is evidence of the evaluator's
decision under pinned keys, not proof of external execution.
"""
import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from signed_receipt import canonical
from gated_action_broker import canonical_request
from session_capability import capability_digest
from strict_evaluator import verify_strict_evaluator

DOMAIN=b"AML-SEF2-EVALUATOR-EXECUTION-AUTH-V1\x00"
SCHEMA="AML-SEF2-EVALUATOR-EXECUTION-AUTH-V1"

def challenge_digest(execution_challenge):
    return hashlib.sha256(canonical(execution_challenge)).hexdigest()

def evaluate_and_issue(registry,witness,replicas,threshold,attestations,enrolled_keys,
        private_key,evaluator_id,audience,request,capability,execution_challenge,policy_epoch):
    if not verify_strict_evaluator(registry,witness,replicas,threshold,attestations,enrolled_keys):
        raise PermissionError("strict evaluator denied execution authorization")
    if (type(evaluator_id) is not str or not evaluator_id
        or type(audience) is not str or not audience
        or type(policy_epoch) is not int or policy_epoch<0):
        raise ValueError("invalid evaluator authorization scope")
    state=registry.state(witness)
    payload={"schema":SCHEMA,"evaluator_id":evaluator_id,"audience":audience,
        "witness_id":witness,"operation_id":request["operation_id"],
        "request_sha256":hashlib.sha256(canonical_request(request)).hexdigest(),
        "capability_sha256":capability_digest(capability),
        "execution_challenge_sha256":challenge_digest(execution_challenge),
        "policy_epoch":policy_epoch,
        "registry_state_sha256":hashlib.sha256(canonical(state)).hexdigest()}
    return {"payload":payload,"signature":private_key.sign(DOMAIN+canonical(payload)).hex()}

def verify_evaluator_authorization(envelope,public_hex,evaluator_id,audience,witness,
        request,capability,execution_challenge,policy_epoch):
    try:
        if type(envelope) is not dict or set(envelope)!={"payload","signature"}:
            return False
        p=envelope["payload"]
        required={"schema","evaluator_id","audience","witness_id","operation_id",
            "request_sha256","capability_sha256","execution_challenge_sha256",
            "policy_epoch","registry_state_sha256"}
        if type(p) is not dict or set(p)!=required:
            return False
        if (p["schema"]!=SCHEMA or p["evaluator_id"]!=evaluator_id
            or p["audience"]!=audience or p["witness_id"]!=witness
            or p["operation_id"]!=request["operation_id"]
            or p["request_sha256"]!=hashlib.sha256(canonical_request(request)).hexdigest()
            or p["capability_sha256"]!=capability_digest(capability)
            or p["execution_challenge_sha256"]!=challenge_digest(execution_challenge)
            or type(p["policy_epoch"]) is not int or p["policy_epoch"]!=policy_epoch
            or type(p["registry_state_sha256"]) is not str
            or len(p["registry_state_sha256"])!=64):
            return False
        raw=bytes.fromhex(public_hex); sig=bytes.fromhex(envelope["signature"])
        if len(raw)!=32 or len(sig)!=64:
            return False
        Ed25519PublicKey.from_public_bytes(raw).verify(sig,DOMAIN+canonical(p))
        return True
    except (ValueError,TypeError,KeyError,InvalidSignature,OverflowError):
        return False
