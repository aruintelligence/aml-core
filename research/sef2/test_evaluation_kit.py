import pathlib
import sys
import unittest
ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "evaluation_kit"))
from demo import evaluate

class EvaluationKitTests(unittest.TestCase):
    def test_deterministic_verdicts(self):
        a = evaluate()
        b = evaluate()
        self.assertEqual(a, b)
        self.assertEqual(a["consistent_claims"], "THREE_SIGNED_CONSISTENT_CLAIMS")

    def test_missing_witness_fails_closed(self):
        self.assertEqual(evaluate()["missing_witness"], "MISSING_INDEPENDENT_EVIDENCE")

    def test_conflicting_witness_fails_closed(self):
        self.assertEqual(evaluate()["conflicting_witness"], "EVIDENCE_CONFLICT")

    def test_does_not_claim_external_execution(self):
        self.assertFalse(evaluate()["external_execution_proven"])
        self.assertFalse(evaluate()["independent_observation_proven"])

    def test_checkpoint_rollback_detection(self):
        self.assertTrue(evaluate()["checkpoint_rollback_detected"])
