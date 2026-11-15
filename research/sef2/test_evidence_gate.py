import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signed_receipt import issue, key_id
from evidence_gate import adjudicate

class EvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.keys_private = {r: Ed25519PrivateKey.generate()
            for r in ("authority", "provider", "witness")}
        self.trust = {r: {key_id(k.public_key()): k.public_key()}
            for r, k in self.keys_private.items()}
        self.a = self.sign("authority", "CONSUMED", "0"*64)
        self.p = self.sign("provider", "PROVIDER_REPORTED", "c"*64)
        self.w = self.sign("witness", "OBSERVED_SYNTHETIC_EFFECT", "c"*64)

    def sign(self, role, state, evidence, op="op-1", digest="a"*64):
        return issue(self.keys_private[role], role, op, digest, state, evidence)

    def test_three_consistent_signed_claims(self):
        self.assertEqual(adjudicate(self.a, self.p, self.w, self.trust),
            "THREE_SIGNED_CONSISTENT_CLAIMS")

    def test_missing_witness_is_not_success(self):
        self.assertEqual(adjudicate(self.a, self.p, None, self.trust),
            "MISSING_INDEPENDENT_EVIDENCE")

    def test_untrusted_witness_key_rejected(self):
        outsider = Ed25519PrivateKey.generate()
        forged = issue(outsider, "witness", "op-1", "a"*64,
            "OBSERVED_SYNTHETIC_EFFECT", "c"*64)
        self.assertEqual(adjudicate(self.a, self.p, forged, self.trust),
            "UNTRUSTED_WITNESS")

    def test_conflicting_evidence_digest_rejected(self):
        witness = self.sign("witness", "OBSERVED_SYNTHETIC_EFFECT", "d"*64)
        self.assertEqual(adjudicate(self.a, self.p, witness, self.trust),
            "EVIDENCE_CONFLICT")

    def test_cross_operation_rejected(self):
        witness = self.sign("witness", "OBSERVED_SYNTHETIC_EFFECT", "c"*64, op="op-2")
        self.assertEqual(adjudicate(self.a, self.p, witness, self.trust),
            "EVIDENCE_CONFLICT")

    def test_cross_request_rejected(self):
        witness = self.sign("witness", "OBSERVED_SYNTHETIC_EFFECT", "c"*64, digest="b"*64)
        self.assertEqual(adjudicate(self.a, self.p, witness, self.trust),
            "EVIDENCE_CONFLICT")

    def test_witness_does_not_override_unconsumed_authority(self):
        authority = self.sign("authority", "PENDING", "0"*64)
        self.assertEqual(adjudicate(authority, self.p, self.w, self.trust), "INCOMPLETE")

    def test_witness_must_claim_observation(self):
        witness = self.sign("witness", "PENDING", "c"*64)
        self.assertEqual(adjudicate(self.a, self.p, witness, self.trust), "INCOMPLETE")

    def test_provider_cannot_self_sign_witness(self):
        forged = issue(self.keys_private["provider"], "witness", "op-1",
            "a"*64, "OBSERVED_SYNTHETIC_EFFECT", "c"*64)
        self.assertEqual(adjudicate(self.a, self.p, forged, self.trust),
            "UNTRUSTED_WITNESS")
