"""Deployment preflight checks (no privileged users created in CI)."""
import os
import pathlib
import tempfile
import unittest
from broker_isolation_guard import validate_isolation

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
