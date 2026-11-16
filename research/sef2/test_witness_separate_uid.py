"""Linux root-only witness isolation integration test.

Execute explicitly as root in an isolated CI runner or disposable VM:
  python3 research/sef2/test_witness_separate_uid.py
Tests real SO_PEERCRED and POSIX file permissions with distinct processes.
Never run this against a production witness database.
"""
import os
import pwd
import socket
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from durable_receipt_witness import DurableReceiptWitness
from reservation_receipt_chain import GENESIS, reservation_chain_hash
from witness_socket import WitnessServer
from atomic_receipt_reservations import AtomicReceiptReservations
from pinned_ledger_witness_bridge import PinnedLedgerWitnessBridge

@unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                     "requires Linux root in an isolated test environment")
class WitnessSeparateUIDTests(unittest.TestCase):
    def test_strict_committed_evidence_with_distinct_client_uid(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            os.chmod(base, 0o755)
            for module in ("witness_socket.py", "witness_protocol.py",
                           "reservation_receipt_chain.py"):
                shutil.copy2(Path(__file__).resolve().parent / module, base / module)
            ledger_path = base / "ledger.sqlite"
            witness_path = base / "witness.sqlite"
            sock = base / "strict.sock"
            ledger = AtomicReceiptReservations(ledger_path, "authority")
            store = DurableReceiptWitness(witness_path, "authority")
            self.assertTrue(store.observe(0, GENESIS, 0, GENESIS))
            os.chmod(ledger_path, 0o600)
            os.chmod(witness_path, 0o600)
            bridge = PinnedLedgerWitnessBridge(ledger_path, "authority", expected_uid=0)
            server = WitnessServer(sock, allowed_uid=65534, store=store,
                                   committed_bridge=bridge, require_committed_evidence=True)
            os.chmod(sock, 0o666)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                entry = ["authority", "op-strict", "b" * 64, 1]
                head = reservation_chain_hash(GENESIS, *entry)
                request = {"authority_id": "authority", "sequence": 1, "head": head,
                           "previous_sequence": 0, "previous_head": GENESIS, "entry": entry}
                import json
                script = ("import json,sys; from witness_socket import advance_via_socket; "
                          "print(json.dumps({'advance':advance_via_socket(sys.argv[1],json.loads(sys.argv[2]))}));")
                env = dict(os.environ, PYTHONPATH=str(base))
                def request_as(uid):
                    return subprocess.run([sys.executable, "-c", script, str(sock), json.dumps(request)],
                                          env=env, capture_output=True, text=True, timeout=10,
                                          user=uid, group=uid, extra_groups=[], check=True).stdout.strip()
                self.assertEqual(request_as(65534), '{"advance": false}')
                self.assertTrue(ledger.reserve("op-strict", "b" * 64, 1))
                self.assertEqual(request_as(65533), '{"advance": false}')
                self.assertEqual(request_as(65534), '{"advance": true}')
                self.assertEqual(store.inspect(), (1, head))
                self.assertEqual(request_as(65534), '{"advance": false}')
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_authorized_uid_and_denied_uid(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            os.chmod(base, 0o755)
            for module in ("witness_socket.py", "witness_protocol.py", "reservation_receipt_chain.py"):
                shutil.copy2(Path(__file__).resolve().parent / module, base / module)
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
                env["PYTHONPATH"] = str(base)
                def run_as(uid, req):
                    return subprocess.run(
                        [sys.executable, "-c", script, str(sock), json.dumps(req)],
                        env=env, capture_output=True, text=True, timeout=10,
                        user=uid, group=uid, extra_groups=[], check=True).stdout.strip()
                self.assertEqual(run_as(denied_uid, request), '{"advance": false}')
                self.assertEqual(run_as(allowed_uid, dict(request, authority_id="foreign")), '{"advance": false}')
                self.assertEqual(run_as(allowed_uid, dict(request, head="f" * 64)), '{"advance": false}')
                self.assertEqual(store.inspect(), (0, GENESIS))
                self.assertEqual(run_as(allowed_uid, request), '{"advance": true}')
                self.assertEqual(store.inspect(), (1, head))
                self.assertEqual(run_as(allowed_uid, request), '{"advance": false}')
                direct = subprocess.run(
                    [sys.executable, "-c",
                     "import sqlite3,sys; sqlite3.connect(sys.argv[1]).execute('DELETE FROM witness_heads')",
                     str(db)],
                    env=env, capture_output=True, text=True, timeout=10,
                    user=allowed_uid, group=allowed_uid, extra_groups=[])
                self.assertNotEqual(direct.returncode, 0)
                self.assertEqual(store.inspect(), (1, head))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

if __name__ == "__main__":
    unittest.main()
