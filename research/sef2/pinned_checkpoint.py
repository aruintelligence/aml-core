"""Pinned, signed, monotonic checkpoint verifier for the synthetic effect authority.

The checkpoint provider must be independently hosted and its signing key pinned
outside the untrusted agent. A valid signature alone cannot establish freshness.
"""
import json
import threading
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN = b"AML-SEF2-CHECKPOINT-V1\x00"
SCHEMA = "AML-SEF2-CHECKPOINT-V1"

def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def issue_checkpoint(private_key, authority_id, generation, sequence):
    if (type(authority_id) is not str or not authority_id
        or type(generation) is not int or generation < 0
        or type(sequence) is not int or sequence < 0):
        raise ValueError("invalid checkpoint")
    payload = {"schema": SCHEMA, "authority_id": authority_id,
               "generation": generation, "sequence": sequence}
    return {"payload": payload, "signature": private_key.sign(DOMAIN + canonical(payload)).hex()}

def verify_checkpoint(envelope, public_hex, authority_id):
    try:
        if type(envelope) is not dict or set(envelope) != {"payload", "signature"}:
            return None
        payload = envelope["payload"]
        if (type(payload) is not dict or
            set(payload) != {"schema", "authority_id", "generation", "sequence"}
            or payload["schema"] != SCHEMA or payload["authority_id"] != authority_id
            or type(payload["generation"]) is not int or payload["generation"] < 0
            or type(payload["sequence"]) is not int or payload["sequence"] < 0
            or type(envelope["signature"]) is not str):
            return None
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
            bytes.fromhex(envelope["signature"]), DOMAIN + canonical(payload))
        return payload["generation"], payload["sequence"]
    except (ValueError, TypeError, KeyError, OverflowError, InvalidSignature):
        return None

class PinnedCheckpoint:
    """Fetches signed checkpoint; rejects stale/reordered observations.

    The sequence/generation high-water marks live only in this process.
    Persistence and independent anti-rollback are outside this prototype.
    """
    def __init__(self, fetch, public_hex, authority_id, durable_store=None, require_durable=False):
        if not callable(fetch):
            raise TypeError("checkpoint fetch must be callable")
        if type(require_durable) is not bool:
            raise TypeError("require_durable must be bool")
        if require_durable and durable_store is None:
            raise ValueError("durable checkpoint state required")
        self.fetch = fetch
        self.public_hex = public_hex
        self.authority_id = authority_id
        self.durable_store = durable_store
        self._lock = threading.Lock()
        self.last_sequence = -1
        self.last_generation = 0

    def __call__(self):
        # Fetch, verify, compare and advance must be one serialized operation.
        # Otherwise an older concurrent response can overwrite a newer mark.
        with self._lock:
            checked = verify_checkpoint(self.fetch(), self.public_hex, self.authority_id)
            if checked is None:
                raise ValueError("invalid signed checkpoint")
            generation, sequence = checked
            if sequence < self.last_sequence or generation < self.last_generation:
                raise ValueError("checkpoint rollback detected")
            if sequence == self.last_sequence and generation != self.last_generation:
                raise ValueError("checkpoint equivocation detected")
            # Durable store atomically checks and records observations from
            # other processes and previous verifier instances.
            if self.durable_store is not None:
                self.durable_store.observe(self.authority_id, sequence, generation)
            self.last_sequence = sequence
            self.last_generation = generation
            return generation
