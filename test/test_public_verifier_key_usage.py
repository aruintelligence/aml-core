"""Regression tests: public verification JWKs must not advertise signing operations."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "independent" / "python"))
from verify_witness import verify_p256_raw_signature
from verify_signed_quorum import public_point

# P-256 generator is a valid curve point; no private key or signature required.
JWK = {
    "kty": "EC", "crv": "P-256",
    "x": "axfR8uEsQkf4vhbmY6RA8ncDeBLeM_6PChOU2YgsKZY",
    "y": "T-NC4fKugH7rZQ8PnbODe3a1drQWj7tAFnLLZr9f1F8",
}

class PublicKeyUsageTests(unittest.TestCase):
    def test_witness_rejects_signing_capability(self):
        for operations in (["sign"], ["verify", "sign"], ["verify", "deriveBits"]):
            with self.subTest(operations=operations):
                valid, reason = verify_p256_raw_signature(
                    {**JWK, "key_ops": operations}, b"test", "AA"
                )
                self.assertFalse(valid)
                self.assertEqual(reason, "AML_PY_KEY_USAGE_INVALID")

    def test_quorum_rejects_signing_capability(self):
        for operations in (["sign"], ["verify", "sign"], ["verify", "deriveBits"]):
            with self.subTest(operations=operations):
                with self.assertRaisesRegex(ValueError, "invalid_key_usage"):
                    public_point({**JWK, "key_ops": operations})

if __name__ == "__main__":
    unittest.main()
