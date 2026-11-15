"""Post-commit recovery activation attestations.

A RecoveryActivationAttestor signs only after its local monotonic activation
registry reports the exact generation, policy digest and head. A quorum of
these attestations is portable evidence that the configured attestor software
observed committed local state.

The signature cannot prove the attestor implementation itself was not replaced;
that requires independently controlled deployment/attestation outside this
synthetic reference.
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from signed_receipt import canonical
from quorum_model import validate_bft_quorum
from witness_independence import verify_independence

DOMAIN=b"AML-SEF2-RECOVERY-ACTIVATION-COMMIT-V1\x00"
SCHEMA="AML-SEF2-RECOVERY-ACTIVATION-COMMIT-V1"

class RecoveryActivationAttestor:
    def __init__(self,verifier_id,private_key,registry):
        if type(verifier_id) is not str or not verifier_id:
            raise ValueError("invalid activation verifier identity")
        self.verifier_id=verifier_id; self.private_key=private_key; self.registry=registry
    def public_key(self):
        return self.private_key.public_key()
    def attest(self,generation,policy_sha256,head_sha256):
        state=self.registry.state()
        if (state.get("generation")!=generation or state.get("policy_sha256")!=policy_sha256
            or state.get("head_sha256")!=head_sha256):
            raise PermissionError("local activation state does not match requested attestation")
        payload={"schema":SCHEMA,"verifier_id":self.verifier_id,
            "generation":generation,"policy_sha256":policy_sha256,"head_sha256":head_sha256}
        return {"payload":payload,
            "signature":self.private_key.sign(DOMAIN+canonical(payload)).hex()}

def verify_activation_commit_quorum(attestations,generation,policy_sha256,head_sha256,
        pinned_verifier_keys,threshold,max_faults,independence_manifest,independence_pin):
    try:
        if type(attestations) is not list or type(pinned_verifier_keys) is not dict:
            return False
        validate_bft_quorum(len(pinned_verifier_keys),threshold,max_faults)
        if not verify_independence(independence_manifest,tuple(pinned_verifier_keys),
            independence_pin,pinned_verifier_keys):
            return False
        seen=set(); valid=0
        for envelope in attestations:
            if type(envelope) is not dict or set(envelope)!={"payload","signature"}:
                return False
            p=envelope["payload"]
            if type(p) is not dict or set(p)!={"schema","verifier_id","generation","policy_sha256","head_sha256"}:
                return False
            verifier_id=p["verifier_id"]
            if verifier_id in seen or verifier_id not in pinned_verifier_keys:
                return False
            seen.add(verifier_id)
            if (p["schema"]!=SCHEMA or p["generation"]!=generation
                or p["policy_sha256"]!=policy_sha256 or p["head_sha256"]!=head_sha256):
                return False
            raw=bytes.fromhex(pinned_verifier_keys[verifier_id]); sig=bytes.fromhex(envelope["signature"])
            if len(raw)!=32 or len(sig)!=64:
                return False
            Ed25519PublicKey.from_public_bytes(raw).verify(sig,DOMAIN+canonical(p))
            valid+=1
        return valid>=threshold
    except (InvalidSignature,ValueError,TypeError,KeyError,OverflowError,AttributeError):
        return False
