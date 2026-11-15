"""Linux root-only witness isolation integration test.

Execute explicitly as root in an isolated CI runner or disposable VM:
  python3 research/sef2/test_witness_separate_uid.py
Tests real SO_PEERCRED and POSIX file permissions with distinct processes.
Never run this against a production witness database.
"""
import os
import pwd
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from durable_receipt_witness import DurableReceiptWitness
from reservation_receipt_chain import GENESIS, reservation_chain_hash
from witness_socket import WitnessServer

@unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                     "requires Linux root in an isolated test environment")
class WitnessSeparateUIDTests(unittest.TestCase):
    def test_authorized_uid_and_denied_uid(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            os.chmod(base, 0o755)
            db = base / "witness.sqlite"
            sock = base / "witness.sock"
            store = DurableReceiptWitness(db, "authority")
            self.assertTrue(store.observe(0, GENESIS, 0, GENESIS))
            os.chmod(db, 0o600)
            allowed_uid, denied_uid = 65534, 65533
            server = WitnessServer(sock, allowed_uid=allowed_uid, store=store)
            os.chmod(sock, 0o666)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                entry = ["authority", "op-1", "a" * 64, 1]
                head = reservation_chain_hash(GENESIS, *entry)
                request = {"authority_id": "authority", "sequence": 1, "head": head,
                           "previous_sequence": 0, "previous_head": GENESIS, "entry": entry}
                script = (
                    "import json,sys; from witness_socket import advance_via_socket; "
                    "print(json.dumps({'advance':advance_via_socket(sys.argv[1],json.loads(sys.argv[2]))}));"
                )
                import json
                env = dict(os.environ)
                env["PYTHONPATH"] = str(Path(__file__).resolve().parent)
                def run_as(uid, req):
                    def demote():
                        os.setgroups([])
                        os.setgid(uid)
                        os.setuid(uid)
                    return subprocess.run(
                        [sys.executable, "-c", script, str(sock), json.dumps(req)],
                        env=env, capture_output=True, text=True, timeout=10,
                        preexec_fn=demote, check=True).stdout.strip()
                self.assertEqual(run_as(denied_uid, request), '{"advance": false}')
                self.assertEqual(store.inspect(), (0, GENESIS))
                self.assertEqual(run_as(allowed_uid, request), '{"advance": true}')
                self.assertEqual(store.inspect(), (1, head))
                self.assertEqual(run_as(allowed_uid, request), '{"advance": false}')
                direct = subprocess.run(
                    [sys.executable, "-c",
                     "import sqlite3,sys; sqlite3.connect(sys.argv[1]).execute('DELETE FROM witness_heads')",
                     str(db)],
                    env=env, capture_output=True, text=True, timeout=10,
                    preexec_fn=lambda: (os.setgroups([]), os.setgid(allowed_uid), os.setuid(allowed_uid)))
                self.assertNotEqual(direct.returncode, 0)
                self.assertEqual(store.inspect(), (1, head))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

if __name__ == "__main__":
    unittest.main()
