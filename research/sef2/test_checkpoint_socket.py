"""Linux socket checkpoint reader integration tests."""
import json
import os
import socket
import tempfile
import threading
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from checkpoint_socket import CheckpointServer, fetch_checkpoint
from pinned_checkpoint import verify_checkpoint, PinnedCheckpoint
from durable_checkpoint_highwater import DurableCheckpointHighWater
from effect_authority import EffectAuthority

@unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Linux peer credentials required")
class CheckpointSocketTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "checkpoint.sock")
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        self.server = CheckpointServer(
            self.path, allowed_uid=os.getuid(), authority_id="tenant-a",
            signing_key=self.key, read_state=lambda: (7, 3))
        self.addCleanup(self.server.server_close)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.shutdown)

    def test_authorized_client_receives_verifiable_checkpoint(self):
        envelope = fetch_checkpoint(self.path, "tenant-a")
        self.assertEqual(verify_checkpoint(envelope, self.public, "tenant-a"), (7, 3))

    def test_socket_checkpoint_blocks_stale_effect_and_allows_updated_floor(self):
        effect_path = os.path.join(self.tmp.name, "effects.sqlite")
        marks_path = os.path.join(self.tmp.name, "marks.sqlite")
        store = DurableCheckpointHighWater(marks_path)
        verifier = PinnedCheckpoint(
            lambda: fetch_checkpoint(self.path, "tenant-a"),
            self.public, "tenant-a", durable_store=store, require_durable=True)
        authority = EffectAuthority(effect_path, lambda *args: True, verifier)
        effect = {"operation_id": "socket-op", "kind": "fixture:write",
                  "target": "fixture:protected", "value": 7}
        self.assertEqual(authority.commit(effect, 7), "DENIED")
        self.assertTrue(authority.advance_policy_floor(7))
        self.assertEqual(authority.commit(effect, 7), "APPLIED")
        self.assertEqual(authority.commit(effect, 7), "ALREADY_APPLIED")

    def test_wrong_authority_request_fails_closed(self):
        with self.assertRaises((ValueError, OSError)):
            fetch_checkpoint(self.path, "tenant-b")

    def test_unauthorized_uid_is_rejected(self):
        self.server.allowed_uid = os.getuid() + 10000
        with self.assertRaises((ValueError, OSError)):
            fetch_checkpoint(self.path, "tenant-a")

    def test_duplicate_authority_fields_are_rejected(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(self.path)
            client.sendall(b'{"authority_id":"tenant-a","authority_id":"tenant-a"}' + bytes([10]))
            self.assertEqual(client.recv(4096), b"")

    def test_oversized_request_is_rejected(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(self.path)
            client.sendall(b"x" * 600 + bytes([10]))
            self.assertEqual(client.recv(4096), b"")

    def test_idle_client_is_disconnected_after_timeout(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(self.path)
            client.settimeout(5)
            self.assertEqual(client.recv(128), b"")

    def test_unavailable_service_fails_closed(self):
        with self.assertRaises((ValueError, OSError)):
            fetch_checkpoint(os.path.join(self.tmp.name, "missing.sock"), "tenant-a")

if __name__ == "__main__":
    unittest.main()
