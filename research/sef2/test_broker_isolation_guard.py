"""Deployment preflight checks (no privileged users created in CI)."""
import os
import pathlib
import tempfile
import unittest
from broker_isolation_guard import validate_isolation
from broker_socket import IsolatedBrokerServer,grant_client_socket_access

class IsolationGuardTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.parent=pathlib.Path(tmp.name)/"private"
        self.parent.mkdir(mode=0o700)
        self.db=self.parent/"effects.sqlite"
        self.db.write_bytes(b"synthetic fixture")
        self.db.chmod(0o600)
        self.uid=os.getuid()
    def test_owner_only_distinct_client_accepted(self):
        self.assertTrue(validate_isolation(self.db,self.uid,frozenset({self.uid+1})))
    def test_same_uid_rejected(self):
        with self.assertRaises(ValueError):
            validate_isolation(self.db,self.uid,frozenset({self.uid}))
    def test_world_readable_database_rejected(self):
        self.db.chmod(0o644)
        with self.assertRaises(ValueError):
            validate_isolation(self.db,self.uid,frozenset({self.uid+1}))
    def test_group_accessible_directory_rejected(self):
        self.parent.chmod(0o750)
        with self.assertRaises(ValueError):
            validate_isolation(self.db,self.uid,frozenset({self.uid+1}))
    def test_symlink_database_rejected(self):
        link=self.parent/"alias.sqlite"
        link.symlink_to(self.db)
        with self.assertRaises(ValueError):
            validate_isolation(link,self.uid,frozenset({self.uid+1}))

    def test_claimed_broker_identity_must_match_process_uid(self):
        with self.assertRaises(ValueError):
            validate_isolation(self.db,self.uid+1,frozenset({self.uid+2}))

    def test_strict_broker_server_rejects_same_uid_client(self):
        class Broker:
            path=str(self.db)
        with self.assertRaises(ValueError):
            IsolatedBrokerServer(self.parent/"socket",Broker(),frozenset({self.uid}))
        self.assertFalse((self.parent/"socket").exists())

    def test_strict_server_accepts_valid_private_storage_profile(self):
        class Broker:
            path=str(self.db)
        socket_path=self.parent.parent/"socket"
        with IsolatedBrokerServer(socket_path,Broker(),frozenset({self.uid+1})):
            self.assertTrue(socket_path.exists())
        socket_path.unlink(missing_ok=True)
    def test_strict_server_rejects_world_readable_database(self):
        class Broker:
            path=str(self.db)
        self.db.chmod(0o644)
        with self.assertRaises(ValueError):
            IsolatedBrokerServer(self.parent/"socket",Broker(),frozenset({self.uid+1}))
        self.assertFalse((self.parent/"socket").exists())

    def test_strict_server_rejects_socket_inside_private_database_directory(self):
        class Broker:
            path=str(self.db)
        with self.assertRaises(ValueError):
            IsolatedBrokerServer(self.parent/"socket",Broker(),frozenset({self.uid+1}))

    def test_explicit_group_socket_grant_never_world_access(self):
        class Broker:
            path=str(self.db)
        socket_path=self.parent.parent/"group-socket"
        with IsolatedBrokerServer(socket_path,Broker(),frozenset({self.uid+1})):
            grant_client_socket_access(socket_path,os.getegid())
            self.assertEqual(socket_path.stat().st_mode & 0o777,0o660)
        socket_path.unlink(missing_ok=True)
    def test_group_grant_rejects_regular_file(self):
        with self.assertRaises(ValueError):
            grant_client_socket_access(self.db,os.getegid())
