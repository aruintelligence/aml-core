"""Challenge-response replica freshness regression tests."""
import pathlib
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pin_registry import PinRegistry
from pin_replication import PinReplica
from fresh_replica_gate import sign_challenge,verify_fresh

class FreshReplicaTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root=pathlib.Path(temp.name)
        self.registry=PinRegistry(root/"registry.sqlite")
        self.registry.enroll("north","a"*64)
        self.replicas=[PinReplica(root/("replica%d.sqlite"%i)) for i in range(3)]
        self.keys=[Ed25519PrivateKey.generate() for _ in range(3)]
        self.enrolled={"r%d"%i:key.public_key().public_bytes_raw().hex() for i,key in enumerate(self.keys)}
        for replica in self.replicas:
            replica.record("north",0,"a"*64)
        self.responders={"r%d"%i:(lambda nonce,r=r,k=k,i=i:sign_challenge(r,"r%d"%i,"north",nonce,k))
            for i,(r,k) in enumerate(zip(self.replicas,self.keys))}
    def test_fresh_challenge_passes(self):
        self.assertTrue(verify_fresh(self.registry,"north",self.replicas,self.enrolled,self.responders))
    def test_replayed_old_challenge_fails(self):
        old="a"*64
        replay={identity:(lambda nonce,r=responder: r(old))
                for identity,responder in self.responders.items()}
        self.assertFalse(verify_fresh(self.registry,"north",self.replicas,self.enrolled,replay,
                                      nonce_factory=lambda:"b"*64))
    def test_wrong_signing_key_fails(self):
        bad=dict(self.responders)
        bad["r0"]=lambda nonce:sign_challenge(self.replicas[0],"r0","north",nonce,self.keys[1])
        self.assertFalse(verify_fresh(self.registry,"north",self.replicas,self.enrolled,bad))
    def test_missing_signer_fails(self):
        responders=dict(self.responders)
        responders.pop("r2")
        self.assertFalse(verify_fresh(self.registry,"north",self.replicas,self.enrolled,responders))
    def test_replica_rollback_fails(self):
        import sqlite3
        with sqlite3.connect(self.replicas[1].path) as db:
            db.execute("UPDATE history SET pin=? WHERE witness=?",("f"*64,"north"))
        self.assertFalse(verify_fresh(self.registry,"north",self.replicas,self.enrolled,self.responders))
