"""Adversarial synthetic broker execution-gate tests."""
import pathlib
import sqlite3
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pin_registry import PinRegistry
from pin_replication import PinReplica
from replica_attestation import attest
from gated_action_broker import GatedBroker
from capability_broker import CapabilityBroker
from action_capability import issue_capability

class BrokerBoundaryTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root=pathlib.Path(temp.name)
        self.registry=PinRegistry(root/"evaluator.sqlite")
        self.registry.enroll("north","a"*64)
        self.replicas=[PinReplica(root/("replica%d.sqlite"%i)) for i in range(3)]
        self.keys=[Ed25519PrivateKey.generate() for _ in range(3)]
        self.enrolled={"r%d"%i:k.public_key().public_bytes_raw().hex() for i,k in enumerate(self.keys)}
        for r in self.replicas:
            r.record("north",0,"a"*64)
        self.broker=GatedBroker(root/"effects.sqlite",self.registry,"north",self.replicas,2,self.enrolled)
        self.request={"operation_id":"op-1","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
    def signed(self):
        return [attest(r,"r%d"%i,"north",self.keys[i]) for i,r in enumerate(self.replicas)]
    def count(self):
        with sqlite3.connect(self.broker.path) as db:
            return db.execute("SELECT COUNT(*) FROM effects").fetchone()[0]
    def test_authorized_action_persists_once(self):
        self.assertEqual(self.broker.execute(self.request,self.signed()),"APPLIED")
        self.assertEqual(self.broker.execute(self.request,self.signed()),"ALREADY_APPLIED")
        self.assertEqual(self.count(),1)
    def test_missing_attestations_cannot_execute(self):
        self.assertEqual(self.broker.execute(self.request,[]),"DENIED")
        self.assertEqual(self.count(),0)
    def test_forged_attestation_cannot_execute(self):
        receipts=self.signed()
        receipts[0]["signature"]="00"*64
        self.assertEqual(self.broker.execute(self.request,receipts),"DENIED")
        self.assertEqual(self.count(),0)
    def test_registry_rollback_or_replica_divergence_blocks_execution(self):
        with sqlite3.connect(self.replicas[0].path) as db:
            db.execute("UPDATE history SET pin=? WHERE witness=?",("f"*64,"north"))
        self.assertEqual(self.broker.execute(self.request,self.signed()),"DENIED")
        self.assertEqual(self.count(),0)
    def test_action_substitution_denied(self):
        request=dict(self.request,action="payment:real")
        self.assertEqual(self.broker.execute(request,self.signed()),"DENIED")
        self.assertEqual(self.count(),0)
    def test_conflicting_operation_id_cannot_overwrite_effect(self):
        self.assertEqual(self.broker.execute(self.request,self.signed()),"APPLIED")
        self.assertEqual(self.broker.execute(dict(self.request,amount_cents=200),self.signed()),"DENIED")
        self.assertEqual(self.count(),1)

class CapabilityBoundaryTests(unittest.TestCase):
    signed=BrokerBoundaryTests.signed
    count=BrokerBoundaryTests.count
    def setUp(self):
        BrokerBoundaryTests.setUp(self)
        self.issuer_key=Ed25519PrivateKey.generate()
        self.broker=CapabilityBroker(self.broker.path,self.registry,"north",self.replicas,2,
            self.enrolled,"authority",self.issuer_key.public_key().public_bytes_raw().hex(),"broker-a")
    def token(self,request=None,epoch=None):
        return issue_capability(self.issuer_key,"authority","broker-a",
            request or self.request,self.broker.current_epoch() if epoch is None else epoch)
    def test_capability_required(self):
        self.assertEqual(self.broker.execute(self.request,self.signed()),"DENIED")
        self.assertEqual(self.count(),0)
    def test_signed_exact_action_accepted_once(self):
        token=self.token()
        self.assertEqual(self.broker.execute(self.request,self.signed(),token),"APPLIED")
        self.assertEqual(self.broker.execute(self.request,self.signed(),token),"ALREADY_APPLIED")
        self.assertEqual(self.count(),1)
    def test_scope_substitution_denied(self):
        token=self.token()
        self.assertEqual(self.broker.execute(dict(self.request,amount_cents=101),self.signed(),token),"DENIED")
        self.assertEqual(self.count(),0)
    def test_wrong_issuer_signature_denied(self):
        other=Ed25519PrivateKey.generate()
        token=issue_capability(other,"authority","broker-a",self.request,0)
        self.assertEqual(self.broker.execute(self.request,self.signed(),token),"DENIED")
    def test_wrong_audience_denied(self):
        token=issue_capability(self.issuer_key,"authority","broker-b",self.request,0)
        self.assertEqual(self.broker.execute(self.request,self.signed(),token),"DENIED")
    def test_revoked_epoch_denied(self):
        token=self.token()
        self.broker.revoke_all()
        self.assertEqual(self.broker.execute(self.request,self.signed(),token),"DENIED")
        self.assertEqual(self.count(),0)
        self.assertEqual(self.broker.execute(self.request,self.signed(),self.token()),"APPLIED")
    def test_revocation_persists_across_restart(self):
        token=self.token()
        self.broker.revoke_all()
        broker=CapabilityBroker(self.broker.path,self.registry,"north",self.replicas,2,
            self.enrolled,"authority",self.issuer_key.public_key().public_bytes_raw().hex(),"broker-a")
        self.assertEqual(broker.current_epoch(),1)
        self.assertEqual(broker.execute(self.request,self.signed(),token),"DENIED")

    def test_legacy_base_method_cannot_bypass_capability_broker(self):
        self.assertEqual(GatedBroker.execute(self.broker,self.request,self.signed()),"DENIED")
        self.assertEqual(self.count(),0)

    def test_concurrent_revocation_and_execution_linearize(self):
        import concurrent.futures
        token=self.token()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            future_execute=pool.submit(self.broker.execute,self.request,self.signed(),token)
            future_revoke=pool.submit(self.broker.revoke_all)
            result=future_execute.result(timeout=10)
            future_revoke.result(timeout=10)
        self.assertIn(result,{"APPLIED","DENIED"})
        self.assertEqual(self.count(),1 if result=="APPLIED" else 0)
        self.assertEqual(self.broker.execute(dict(self.request,operation_id="op-2"),
            self.signed(),issue_capability(self.issuer_key,"authority","broker-a",
            dict(self.request,operation_id="op-2"),0)),"DENIED")
