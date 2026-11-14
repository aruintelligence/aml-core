"""Adversarial dual-role HMAC receipt checks; no external effect."""
import copy
import os
import unittest
from receipt import issue, verify, reconcile

class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.a = os.urandom(32)
        self.p = os.urandom(32)
        self.auth = issue("authority", self.a, "op-1", "a" * 64, "CONSUMED", "b" * 64)
        self.provider = issue("provider", self.p, "op-1", "a" * 64,
            "PROVIDER_REPORTED", "c" * 64)

    def test_distinct_roles_corroborate_claims_not_execution(self):
        self.assertEqual(reconcile(self.auth, self.provider, self.a, self.p),
            "CORROBORATED_CLAIMS_ONLY")

    def test_mutation_breaks_authentication(self):
        changed = copy.deepcopy(self.provider)
        changed["payload"]["evidence_sha256"] = "0" * 64
        self.assertFalse(verify(changed, "provider", self.p))
        self.assertEqual(reconcile(self.auth, changed, self.a, self.p),
            "UNTRUSTED_PROVIDER_RECEIPT")

    def test_cross_role_key_confusion_fails(self):
        self.assertFalse(verify(self.auth, "provider", self.a))
        self.assertFalse(verify(self.provider, "provider", self.a))
        self.assertEqual(reconcile(self.auth, self.provider, self.p, self.a),
            "UNTRUSTED_AUTHORITY_RECEIPT")

    def test_operation_binding_rejects_cross_action_receipt(self):
        wrong = issue("provider", self.p, "op-2", "a" * 64,
            "PROVIDER_REPORTED", "c" * 64)
        self.assertEqual(reconcile(self.auth, wrong, self.a, self.p),
            "EVIDENCE_CONFLICT")

    def test_digest_binding_rejects_cross_request_receipt(self):
        wrong = issue("provider", self.p, "op-1", "d" * 64,
            "PROVIDER_REPORTED", "c" * 64)
        self.assertEqual(reconcile(self.auth, wrong, self.a, self.p),
            "EVIDENCE_CONFLICT")

    def test_unconsumed_authority_cannot_corroborate(self):
        pending = issue("authority", self.a, "op-1", "a" * 64,
            "PENDING", "b" * 64)
        self.assertEqual(reconcile(pending, self.provider, self.a, self.p),
            "INCOMPLETE")

    def test_extra_fields_are_rejected(self):
        changed = copy.deepcopy(self.auth)
        changed["payload"]["surprise"] = "yes"
        self.assertFalse(verify(changed, "authority", self.a))
