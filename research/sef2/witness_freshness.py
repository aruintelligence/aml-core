"""Challenge-bound freshness from independently administered witness stores.

The service adapter is transport agnostic: deploy each WitnessEndpoint in a
separate process/security domain, authenticate its signing key out of band.
"""
import os
from cryptography.exceptions import InvalidSignature
from checkpoint_council import valid_checkpoint
from signed_receipt import canonical

DOMAIN=b"AML-SEF2-FRESHNESS-V1\x00"

class WitnessEndpoint:
    def __init__(self,store):
        self.store=store

    def latest(self,challenge):
        if type(challenge) is not str or len(challenge)!=64:
            raise ValueError("invalid challenge")
        bytes.fromhex(challenge)
        envelope=self.store.latest()
        if envelope is None:
            raise ValueError("no checkpoint")
        payload={"version":1,"witness_id":self.store.name,
                 "challenge":challenge,"checkpoint":envelope["payload"]["checkpoint"]}
        return {"payload":payload,"signature":self.store.private.sign(DOMAIN+canonical(payload)).hex()}

def challenge():
    return os.urandom(32).hex()

def verify_fresh(responses,nonce,pinned_keys,threshold,expected):
    if type(nonce) is not str or len(nonce)!=64 or not valid_checkpoint(expected):
        return "INVALID"
    try:
        bytes.fromhex(nonce)
    except ValueError:
        return "INVALID"
    if type(responses) is not list or type(threshold) is not int or threshold<2:
        return "INVALID"
    if type(pinned_keys) is not dict or threshold>len(pinned_keys):
        return "INVALID"
    if len({key.public_bytes_raw() for key in pinned_keys.values()})!=len(pinned_keys):
        return "INVALID"
    seen=set()
    checkpoints=[]
    for envelope in responses:
        if type(envelope) is not dict or set(envelope)!={"payload","signature"}:
            return "INVALID"
        p=envelope["payload"]
        if type(p) is not dict or set(p)!={"version","witness_id","challenge","checkpoint"}:
            return "INVALID"
        name=p["witness_id"]
        if type(name) is not str or name not in pinned_keys or name in seen:
            return "UNTRUSTED_OR_DUPLICATE"
        if type(p["version"]) is not int or p["version"]!=1 or p["challenge"]!=nonce or not valid_checkpoint(p["checkpoint"]):
            return "INVALID"
        try:
            pinned_keys[name].verify(bytes.fromhex(envelope["signature"]),DOMAIN+canonical(p))
        except (ValueError,TypeError,InvalidSignature,KeyError):
            return "INVALID_SIGNATURE"
        seen.add(name)
        checkpoints.append(p["checkpoint"])
    if len(seen)<threshold:
        return "INSUFFICIENT_WITNESSES"
    if any(cp["epoch"]<expected["epoch"] for cp in checkpoints):
        return "STALE_HISTORY"
    if any(cp!=expected for cp in checkpoints):
        return "FORK_OR_ADVANCED_HISTORY"
    return "FRESH_QUORUM_CONSISTENT"
