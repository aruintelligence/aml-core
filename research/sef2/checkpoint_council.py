"""Synthetic multi-witness checkpoint publication with independently pinned keys.

Each witness must retain its own last accepted checkpoint outside the history
writer's control. A quorum is not proof of independence or global freshness.
"""
import hashlib
import json
from cryptography.exceptions import InvalidSignature
from signed_receipt import canonical
from signed_history import digest

DOMAIN=b"AML-SEF2-CHECKPOINT-WITNESS-V1\x00"

def publish(private_key,witness_id,checkpoint):
    if type(witness_id) is not str or not witness_id or len(witness_id)>128:
        raise ValueError("invalid witness id")
    if not valid_checkpoint(checkpoint):
        raise ValueError("invalid checkpoint")
    payload={"version":1,"witness_id":witness_id,"checkpoint":checkpoint}
    return {"payload":payload,"signature":private_key.sign(DOMAIN+canonical(payload)).hex()}

def valid_checkpoint(cp):
    return (type(cp) is dict and set(cp)=={"schema","epoch","head_hash","count","approver_key_id"}
        and cp["schema"]=="AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1"
        and type(cp["epoch"]) is int and cp["epoch"]>0
        and type(cp["count"]) is int and cp["count"]>0
        and all(type(cp[k]) is str and len(cp[k])==64
                and all(c in "0123456789abcdef" for c in cp[k])
                for k in ("head_hash","approver_key_id")))

class WitnessCouncil:
    def __init__(self,pinned_public_keys,threshold,retained=None):
        if type(pinned_public_keys) is not dict or len(pinned_public_keys)<2:
            raise ValueError("need multiple independently provisioned witnesses")
        if type(threshold) is not int or threshold<2 or threshold>len(pinned_public_keys):
            raise ValueError("invalid quorum")
        if len({k.public_bytes_raw() for k in pinned_public_keys.values()})!=len(pinned_public_keys):
            raise ValueError("duplicate witness public key")
        self.keys=dict(pinned_public_keys)
        self.threshold=threshold
        self.retained={} if retained is None else dict(retained)

    def adjudicate(self,envelopes,expected_checkpoint):
        if not valid_checkpoint(expected_checkpoint) or type(envelopes) is not list:
            return "INVALID"
        verified={}
        for envelope in envelopes:
            if type(envelope) is not dict or set(envelope)!={"payload","signature"}:
                return "INVALID"
            p=envelope["payload"]
            if type(p) is not dict or set(p)!={"version","witness_id","checkpoint"}:
                return "INVALID"
            witness=p["witness_id"]
            if type(witness) is not str or witness not in self.keys or witness in verified:
                return "UNTRUSTED_OR_DUPLICATE"
            if type(p["version"]) is not int or p["version"]!=1 or not valid_checkpoint(p["checkpoint"]):
                return "INVALID"
            try:
                self.keys[witness].verify(bytes.fromhex(envelope["signature"]),
                    DOMAIN+canonical(p))
            except (InvalidSignature,ValueError,TypeError,KeyError):
                return "INVALID_SIGNATURE"
            previous=self.retained.get(witness)
            if previous is not None:
                if not valid_checkpoint(previous):
                    return "INVALID_RETAINED_STATE"
                if p["checkpoint"]["epoch"]<previous["epoch"]:
                    return "STALE_HISTORY"
                if (p["checkpoint"]["epoch"]==previous["epoch"]
                    and p["checkpoint"]["head_hash"]!=previous["head_hash"]):
                    return "FORK_DETECTED"
            verified[witness]=p["checkpoint"]
        if len(verified)<self.threshold:
            return "INSUFFICIENT_WITNESSES"
        if any(cp["epoch"]!=expected_checkpoint["epoch"] for cp in verified.values()):
            return "STALE_HISTORY"
        if any(cp!=expected_checkpoint for cp in verified.values()):
            return "FORK_DETECTED"
        return "WITNESS_QUORUM_CONSISTENT"

    def retain(self,envelopes,expected_checkpoint):
        verdict=self.adjudicate(envelopes,expected_checkpoint)
        if verdict!="WITNESS_QUORUM_CONSISTENT":
            return verdict
        for envelope in envelopes:
            self.retained[envelope["payload"]["witness_id"]]=dict(expected_checkpoint)
        return verdict
