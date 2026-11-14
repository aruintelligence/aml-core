"""Adversarial evaluator-registry rollback and independently replicated pin tests."""
import pathlib
import sqlite3
import tempfile
import unittest
from pin_registry import PinRegistry
from pin_replication import PinReplica,verified_state,replicate_committed

class PinReplicationTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root=pathlib.Path(tmp.name)
        self.registry=PinRegistry(root/"registry.sqlite")
        self.replicas=[PinReplica(root/("replica-%d.sqlite"%i)) for i in range(3)]
        self.witness="north"
        self.first="a"*64
        self.second="b"*64
        self.registry.enroll(self.witness,self.first)
        for replica in self.replicas:
            self.assertEqual(replica.record(self.witness,0,self.first),"RECORDED")
    def advance(self):
        self.registry.prepare(self.witness,self.first,self.second)
        self.registry.commit(self.witness,self.first,self.second)
    def test_consistent_genesis(self):
        self.assertEqual(verified_state(self.registry,self.witness,self.replicas,2)["generation"],0)
    def test_committed_replication(self):
        self.advance()
        self.assertEqual(replicate_committed(self.registry,self.witness,self.replicas,2)["generation"],1)
    def test_registry_rollback_rejected_after_replication(self):
        self.advance()
        replicate_committed(self.registry,self.witness,self.replicas,2)
        with sqlite3.connect(self.registry.path) as db:
            db.execute("UPDATE pins SET active=?,generation=0,pending=NULL WHERE witness=?",(self.first,self.witness))
        with self.assertRaises(ValueError):
            verified_state(self.registry,self.witness,self.replicas,2)
    def test_one_replica_rollback_fails_closed(self):
        self.advance()
        replicate_committed(self.registry,self.witness,self.replicas,2)
        with sqlite3.connect(self.replicas[0].path) as db:
            db.execute("DELETE FROM history WHERE generation=1")
        with self.assertRaises(ValueError):
            verified_state(self.registry,self.witness,self.replicas,2)
    def test_forged_advanced_replica_fails_closed(self):
        self.advance()
        replicate_committed(self.registry,self.witness,self.replicas,2)
        self.replicas[1].record(self.witness,2,"f"*64)
        with self.assertRaises(ValueError):
            verified_state(self.registry,self.witness,self.replicas,2)
    def test_duplicate_replica_path_rejected(self):
        with self.assertRaises(ValueError):
            verified_state(self.registry,self.witness,[self.replicas[0],self.replicas[0]],2)
    def test_replica_replay_does_not_advance(self):
        self.assertEqual(self.replicas[0].record(self.witness,0,self.first),"REPLAY")
        self.assertEqual(self.replicas[0].latest(self.witness),(0,self.first))
    def test_replica_generation_skip_rejected(self):
        with self.assertRaises(ValueError):
            self.replicas[0].record(self.witness,2,self.second)

    def test_interrupted_replication_catches_up_identical_predecessors(self):
        self.advance()
        self.replicas[0].record(self.witness,1,self.second)
        self.assertEqual(replicate_committed(self.registry,self.witness,self.replicas,2)["generation"],1)
    def test_divergent_predecessor_rejected_before_any_replica_write(self):
        self.advance()
        with sqlite3.connect(self.replicas[0].path) as db:
            db.execute("UPDATE history SET pin=? WHERE witness=? AND generation=0",("f"*64,self.witness))
        with self.assertRaises(ValueError):
            replicate_committed(self.registry,self.witness,self.replicas,2)
        self.assertEqual(self.replicas[1].latest(self.witness),(0,self.first))
    def test_registry_replay_does_not_override_replica_advance(self):
        self.advance()
        replicate_committed(self.registry,self.witness,self.replicas,2)
        with sqlite3.connect(self.registry.path) as db:
            db.execute("UPDATE pins SET generation=0,active=?,pending=NULL WHERE witness=?",(self.first,self.witness))
        with self.assertRaises(ValueError):
            replicate_committed(self.registry,self.witness,self.replicas,2)

    def test_deterministic_crash_at_each_replica_boundary(self):
        for index in range(4):
            with self.subTest(boundary=index):
                # Each iteration gets a fresh independent fixture.
                import tempfile,pathlib
                with tempfile.TemporaryDirectory() as folder:
                    root=pathlib.Path(folder)
                    registry=PinRegistry(root/"registry.sqlite")
                    replicas=[PinReplica(root/("replica-%d.sqlite"%i)) for i in range(3)]
                    registry.enroll("north",self.first)
                    for replica in replicas:
                        replica.record("north",0,self.first)
                    registry.prepare("north",self.first,self.second)
                    registry.commit("north",self.first,self.second)
                    with self.assertRaises(RuntimeError):
                        replicate_committed(registry,"north",replicas,2,crash_after=index)
                    self.assertEqual(replicate_committed(registry,"north",replicas,2)["generation"],1)
