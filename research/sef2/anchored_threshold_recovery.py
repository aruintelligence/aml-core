"""Two-quorum, proof-carrying witness recovery.

A threshold recovery council authorizes the exact replacement payload. A
separate anchor council certifies the digest of that payload plus its recovery
approval bundle, chained to the verifier's externally retained previous pin.
The adapter is compatible with WitnessRecoveryEnrollment's Ed25519 verify
interface; callers must update expected_previous_pin only from an independently
retained, successfully accepted anchor checkpoint.
"""
import hashlib,json
from cryptography.exceptions import InvalidSignature
from signed_receipt import canonical
from threshold_recovery import (DOMAIN,verify_approval_bundle,validate_policy,
    policy_digest,make_threshold_transition)
from recovery_anchor_quorum import (make_anchor_payload,make_anchor_certificate,
    verify_anchor_certificate,validate_anchor_policy)
from recovery_ledger_anchor import CHECKPOINT_SCHEMA,checkpoint_pin
from witness_key_recovery import AUTH_DOMAIN

SCHEMA="AML-SEF2-ANCHORED-THRESHOLD-RECOVERY-V1"

def authority_set_fingerprint(policy):
    if not validate_policy(policy): raise ValueError("invalid recovery policy")
    return hashlib.sha256(canonical(policy["authorities"])).hexdigest()

def make_anchored_threshold_transition(new_witness_private,witness_id,current_state,
        checkpoint,recovery_policy,recovery_signers,anchor_policy,anchor_witnesses,
        previous_anchor_pin):
    if not validate_anchor_policy(anchor_policy):
        raise ValueError("invalid independent anchor policy")
    transition=make_threshold_transition(new_witness_private,witness_id,current_state,
        checkpoint,recovery_policy,recovery_signers)
    payload=transition["payload"]
    threshold_bundle=json.loads(bytes.fromhex(transition["recovery_signature"]).decode("utf-8"))
    head=hashlib.sha256(canonical({"payload":payload,"threshold_bundle":threshold_bundle})).hexdigest()
    anchor_checkpoint={"schema":CHECKPOINT_SCHEMA,"authority_id":recovery_policy["policy_id"],
        "authority_key_sha256":authority_set_fingerprint(recovery_policy),
        "sequence":payload["generation"],"head_hash":head}
    anchor_payload=make_anchor_payload(anchor_checkpoint,payload["generation"],
        previous_anchor_pin,anchor_policy)
    certificate=make_anchor_certificate(anchor_payload,anchor_policy,anchor_witnesses)
    composite={"schema":SCHEMA,"threshold_bundle":threshold_bundle,
        "anchor_payload":anchor_payload,"anchor_certificate":certificate}
    transition["recovery_signature"]=canonical(composite).hex()
    return transition,checkpoint_pin(anchor_checkpoint)

class AnchoredThresholdRecoveryPublicKey:
    """Verify threshold authorization AND independent anchor quorum evidence."""
    def __init__(self,recovery_policy,anchor_policy,expected_previous_pin):
        if not validate_policy(recovery_policy) or not validate_anchor_policy(anchor_policy):
            raise ValueError("invalid recovery or anchor policy")
        if (type(expected_previous_pin) is not str or len(expected_previous_pin)!=64
            or any(c not in "0123456789abcdef" for c in expected_previous_pin)):
            raise ValueError("invalid externally retained previous anchor pin")
        self.recovery_policy=recovery_policy
        self.anchor_policy=anchor_policy
        self.expected_previous_pin=expected_previous_pin

    @staticmethod
    def _unique_object(pairs):
        result={}
        for key,value in pairs:
            if key in result: raise ValueError("duplicate JSON key")
            result[key]=value
        return result

    def verify(self,signature,message):
        if not message.startswith(AUTH_DOMAIN): raise InvalidSignature
        try:
            payload_bytes=message[len(AUTH_DOMAIN):]
            payload=json.loads(payload_bytes.decode("utf-8"),object_pairs_hook=self._unique_object)
            if canonical(payload)!=payload_bytes: raise InvalidSignature
            composite=json.loads(signature.decode("utf-8"),object_pairs_hook=self._unique_object)
            if canonical(composite)!=signature or type(composite) is not dict:
                raise InvalidSignature
            if set(composite)!={"schema","threshold_bundle","anchor_payload","anchor_certificate"}:
                raise InvalidSignature
            if composite["schema"]!=SCHEMA: raise InvalidSignature
            bundle=composite["threshold_bundle"]
            if not verify_approval_bundle(payload,bundle,self.recovery_policy):
                raise InvalidSignature
            expected_head=hashlib.sha256(canonical({"payload":payload,"threshold_bundle":bundle})).hexdigest()
            anchor_payload=composite["anchor_payload"]
            if (type(anchor_payload) is not dict
                or anchor_payload.get("checkpoint",{}).get("head_hash")!=expected_head
                or anchor_payload.get("checkpoint",{}).get("sequence")!=payload.get("generation")
                or anchor_payload.get("checkpoint",{}).get("authority_id")!=self.recovery_policy["policy_id"]
                or anchor_payload.get("checkpoint",{}).get("authority_key_sha256")!=authority_set_fingerprint(self.recovery_policy)):
                raise InvalidSignature
            if not verify_anchor_certificate(anchor_payload,composite["anchor_certificate"],
                self.anchor_policy,payload["generation"],self.expected_previous_pin,
                self.recovery_policy["policy_id"],authority_set_fingerprint(self.recovery_policy)):
                raise InvalidSignature
        except (InvalidSignature,ValueError,TypeError,KeyError,UnicodeDecodeError,
                json.JSONDecodeError,OverflowError,AttributeError):
            raise InvalidSignature
