"""Authenticated checkpoint publication: approver signature binds full checkpoint."""
from cryptography.exceptions import InvalidSignature
from signed_receipt import canonical
from checkpoint_council import valid_checkpoint
DOMAIN=b"AML-SEF2-CHECKPOINT-PUBLISH-V1\x00"

def sign_checkpoint(approver_private,checkpoint):
    if not valid_checkpoint(checkpoint):
        raise ValueError("invalid checkpoint")
    return {"checkpoint":checkpoint,"signature":approver_private.sign(DOMAIN+canonical(checkpoint)).hex()}

def verify_checkpoint_publication(envelope,approver_public):
    if type(envelope) is not dict or set(envelope)!={"checkpoint","signature"}:
        return False
    if not valid_checkpoint(envelope["checkpoint"]) or type(envelope["signature"]) is not str:
        return False
    try:
        approver_public.verify(bytes.fromhex(envelope["signature"]),DOMAIN+canonical(envelope["checkpoint"]))
        return True
    except (InvalidSignature,ValueError,TypeError):
        return False
