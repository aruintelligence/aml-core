"""Synthetic reservation RPC tests; actual separate UID tests run separately."""
import os
import socket
import tempfile
import threading
import unittest
from independent_effect_reservations import IndependentEffectReservations
from reservation_socket import ReservationServer, reserve_via_socket

@unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Linux peer credentials required")
class ReservationSocketTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "reserve.sock")
        store = IndependentEffectReservations(os.path.join(self.tmp.name, "reserve.db"), "authority-a")
        self.server = ReservationServer(self.path, allowed_uid=os.getuid(), store=store)
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.shutdown)

    def test_reserve_once_then_reject_replay(self):
        self.assertTrue(reserve_via_socket(self.path, "op-1", "a" * 64, 2))
        self.assertFalse(reserve_via_socket(self.path, "op-1", "a" * 64, 2))
        self.assertFalse(reserve_via_socket(self.path, "op-1", "b" * 64, 2))

    def test_denied_peer(self):
        self.server.allowed_uid = os.getuid() + 10000
        self.assertFalse(reserve_via_socket(self.path, "op-1", "a" * 64, 2))

    def test_unavailable_service_denies(self):
        self.assertFalse(reserve_via_socket(self.path + ".missing", "op-1", "a" * 64, 2))

    def test_invalid_inputs_denied(self):
        self.assertFalse(reserve_via_socket(self.path, "op-1", "bad", 2))
        self.assertFalse(reserve_via_socket(self.path, "op-1", "a" * 64, True))

    def test_duplicate_request_keys_denied(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(self.path)
            client.sendall(b'{"operation_id":"x","operation_id":"x","digest":"'
                           + b'a' * 64 + b'","generation":1}' + bytes([10]))
            self.assertEqual(client.recv(128), b"")

if __name__ == "__main__":
    unittest.main()
