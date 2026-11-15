"""Linux witness socket authentication and adversarial tests."""
import os
import socket
import tempfile
import threading
import unittest

from durable_receipt_witness import DurableReceiptWitness
from reservation_receipt_chain import GENESIS, reservation_chain_hash
from witness_socket import WitnessServer, advance_via_socket

@unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Linux peer credentials required")
class WitnessSocketTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "witness.sock")
        self.store = DurableReceiptWitness(os.path.join(self.tmp.name, "witness.db"), "authority")
        self.assertTrue(self.store.observe(0, GENESIS, 0, GENESIS))
        self.server = WitnessServer(self.path, allowed_uid=os.getuid(), store=self.store)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.entry = ["authority", "op-1", "a" * 64, 1]
        self.request = {
            "authority_id": "authority", "sequence": 1,
            "head": reservation_chain_hash(GENESIS, *self.entry),
            "previous_sequence": 0, "previous_head": GENESIS, "entry": self.entry}

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_valid_extension_and_replay_denied(self):
        self.assertTrue(advance_via_socket(self.path, self.request))
        self.assertFalse(advance_via_socket(self.path, self.request))
        self.assertEqual(self.store.inspect(), (1, self.request["head"]))

    def test_denied_peer_uid(self):
        self.server.allowed_uid = os.getuid() + 1
        self.assertFalse(advance_via_socket(self.path, self.request))
        self.assertEqual(self.store.inspect(), (0, GENESIS))

    def test_forged_authority_denied(self):
        request = dict(self.request, authority_id="foreign")
        self.assertFalse(advance_via_socket(self.path, request))
        self.assertEqual(self.store.inspect(), (0, GENESIS))

    def test_unavailable_socket_denies(self):
        self.assertFalse(advance_via_socket(self.path + ".missing", self.request))

    def test_oversized_request_denies(self):
        self.assertFalse(advance_via_socket(self.path, dict(self.request, extra="x" * 2000)))

if __name__ == "__main__":
    unittest.main()
