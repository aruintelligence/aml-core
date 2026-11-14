"""Offline, synthetic-only enterprise evaluator: python3 evaluation_kit/demo.py."""
import json
import pathlib
import sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signed_receipt import issue, key_id
from evidence_gate import adjudicate
from witness_chain import append, checkpoint, verify

def evaluate():
    private = {role: Ed25519PrivateKey.generate() for role in ("authority", "provider", "witness")}
    public = {role: {key_id(k.public_key()): k.public_key()} for role, k in private.items()}
    digest = "a" * 64
    evidence = "c" * 64
    auth = issue(private["authority"], "authority", "synthetic-operation-001", digest, "CONSUMED", "0" * 64)
    provider = issue(private["provider"], "provider", "synthetic-operation-001", digest, "PROVIDER_REPORTED", evidence)
    witness = issue(private["witness"], "witness", "synthetic-operation-001", digest, "OBSERVED_SYNTHETIC_EFFECT", evidence)
    normal = adjudicate(auth, provider, witness, public)
    missing = adjudicate(auth, provider, None, public)
    conflicting = issue(private["witness"], "witness", "synthetic-operation-001", digest, "OBSERVED_SYNTHETIC_EFFECT", "d" * 64)
    conflict = adjudicate(auth, provider, conflicting, public)
    chain = [append([], digest)]
    retained = checkpoint(chain)
    rollback = not verify([], retained)
    result = {"protocol": "SEF2-EVALUATION-V1", "synthetic_only": True,
        "consistent_claims": normal, "missing_witness": missing,
        "conflicting_witness": conflict, "checkpoint_rollback_detected": rollback,
        "external_execution_proven": False, "independent_observation_proven": False}
    expected = {"consistent_claims": "THREE_SIGNED_CONSISTENT_CLAIMS",
        "missing_witness": "MISSING_INDEPENDENT_EVIDENCE",
        "conflicting_witness": "EVIDENCE_CONFLICT",
        "checkpoint_rollback_detected": True, "external_execution_proven": False,
        "independent_observation_proven": False}
    if any(result[k] != v for k, v in expected.items()):
        raise AssertionError("evaluation invariant failed")
    return result

if __name__ == "__main__":
    print(json.dumps(evaluate(), sort_keys=True, indent=2))
