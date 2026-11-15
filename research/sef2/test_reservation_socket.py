"""Synthetic reservation RPC tests; actual separate UID tests run separately."""
import os
import socket
import tempfile
import threading
import time
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

    def test_handler_capacity_rejects_excess_connections(self):
        self.server.MAX_ACTIVE = 2
        self.server._slots = threading.BoundedSemaphore(2)
        clients = []
        try:
            for _ in range(2):
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.settimeout(2)
                client.connect(self.path)
                clients.append(client)
            # Wait until both server handlers have acquired their slots.
            deadline = time.monotonic() + 2
            while self.server._slots._value != 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(self.server._slots._value, 0)
            self.assertFalse(reserve_via_socket(self.path, "op-capacity", "a" * 64, 1))
        finally:
            for client in clients:
                client.close()

    def test_idle_client_has_bounded_socket_timeout(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(self.path)
            client.settimeout(5)
            self.assertEqual(client.recv(128), b"")

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
