"""Strict evaluator gate for signed, pinned replica-state observations.

Fail closed unless both the local durable replica state and independently
enrolled signing identities agree with the evaluator registry. No quorum
availability semantics: every enrolled replica must respond.
"""
from pin_replication import verified_state
from replica_attestation import verify_attestations

def verify_strict_evaluator(registry,witness,replicas,threshold,attestations,enrolled_keys):
    try:
        if not verify_attestations(registry,witness,attestations,enrolled_keys):
            return False
        verified_state(registry,witness,replicas,threshold)
        if len(replicas)!=len(enrolled_keys):
            return False
        return True
    except (OSError,ValueError,TypeError,KeyError,OverflowError):
        return False
