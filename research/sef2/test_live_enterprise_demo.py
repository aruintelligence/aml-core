import pathlib
import sys
import tempfile
import unittest
from evaluation_kit.live_enterprise_demo import execute
class LiveEnterpriseDemoTests(unittest.TestCase):
    def test_full_separate_process_enterprise_demo(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=execute(pathlib.Path(tmp))
            self.assertEqual(result["result"],"PASS")
            self.assertTrue(all(result["controls"].values()))
            self.assertFalse(result["external_independence_proven"])
            self.assertTrue((pathlib.Path(tmp)/"live-demo-report.json").exists())
