"""Adversarial witness protocol validation tests."""
import unittest
from reservation_receipt_chain import GENESIS, reservation_chain_hash
from witness_protocol import validate_witness_advance

class WitnessProtocolTests(unittest.TestCase):
    def setUp(self):
        self.entry = ("authority", "op-1", "a" * 64, 1)
        self.request = {
            "authority_id": "authority", "sequence": 1,
            "head": reservation_chain_hash(GENESIS, *self.entry),
            "previous_sequence": 0, "previous_head": GENESIS,
            "entry": list(self.entry)}

    def test_valid_extension(self):
        self.assertEqual(validate_witness_advance(self.request, "authority"),
                         (1, self.request["head"], 0, GENESIS, self.entry))

    def test_foreign_authority_denied(self):
        self.assertIsNone(validate_witness_advance(self.request, "foreign"))
        changed = dict(self.request, authority_id="foreign")
        self.assertIsNone(validate_witness_advance(changed, "authority"))

    def test_extra_field_denied(self):
        changed = dict(self.request, debug=True)
        self.assertIsNone(validate_witness_advance(changed, "authority"))

    def test_missing_field_denied(self):
        changed = dict(self.request)
        del changed["entry"]
        self.assertIsNone(validate_witness_advance(changed, "authority"))

    def test_boolean_sequence_denied(self):
        self.assertIsNone(validate_witness_advance(
            dict(self.request, sequence=True), "authority"))

    def test_forged_head_denied(self):
        self.assertIsNone(validate_witness_advance(
            dict(self.request, head="f" * 64), "authority"))

    def test_entry_authority_mismatch_denied(self):
        entry = ["foreign", *self.entry[1:]]
        head = reservation_chain_hash(GENESIS, *entry)
        self.assertIsNone(validate_witness_advance(
            dict(self.request, entry=entry, head=head), "authority"))

if __name__ == "__main__":
    unittest.main()
