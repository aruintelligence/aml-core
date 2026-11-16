"""Synthetic multi-witness checkpoint publication with independently pinned keys.

A quorum is agreement by at least threshold distinct pinned identities on the
independently expected checkpoint. Minority equivocation is tolerated for
safety only within the declared fault bound; conflicting evidence is not erased.
"""
import json
from cryptography.exceptions import InvalidSignature
from signed_receipt import canonical

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
                self.keys[witness].verify(bytes.fromhex(envelope["signature"]),DOMAIN+canonical(p))
            except (InvalidSignature,ValueError,TypeError,KeyError):
                return "INVALID_SIGNATURE"
            previous=self.retained.get(witness)
            candidate=p["checkpoint"]
            if previous is not None:
                if not valid_checkpoint(previous):
                    return "INVALID_RETAINED_STATE"
                if candidate["epoch"]<previous["epoch"]:
                    return "STALE_HISTORY"
                if candidate["epoch"]==previous["epoch"] and candidate["head_hash"]!=previous["head_hash"]:
                    return "FORK_DETECTED"
            verified[witness]=candidate
        matching=[name for name,cp in verified.items() if cp==expected_checkpoint]
        if len(matching)>=self.threshold:
            return "WITNESS_QUORUM_CONSISTENT"
        if len(verified)<self.threshold:
            if any(cp["epoch"]==expected_checkpoint["epoch"] and cp!=expected_checkpoint
                   for cp in verified.values()):
                return "FORK_DETECTED"
            return "INSUFFICIENT_WITNESSES"
        if any(cp["epoch"]<expected_checkpoint["epoch"] for cp in verified.values()):
            return "STALE_HISTORY"
        if any(cp["epoch"]>expected_checkpoint["epoch"] for cp in verified.values()):
            return "ADVANCED_HISTORY"
        if any(cp!=expected_checkpoint for cp in verified.values()):
            return "FORK_DETECTED"
        return "INSUFFICIENT_WITNESSES"

    def retain(self,envelopes,expected_checkpoint):
        verdict=self.adjudicate(envelopes,expected_checkpoint)
        if verdict!="WITNESS_QUORUM_CONSISTENT":
            return verdict
        # Retain only identities that signed the agreed checkpoint. A dissenting
        # identity is not silently advanced by the council.
        for envelope in envelopes:
            name=envelope["payload"]["witness_id"]
            if envelope["payload"]["checkpoint"]==expected_checkpoint:
                self.retained[name]=dict(expected_checkpoint)
        return verdict
