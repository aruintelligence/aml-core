import shutil
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signer_policy import SignerPolicy
from broker_intent import create_intent
from signer_witness import SignerWitness

class SignerWitnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.signer_db=self.root/"signer.sqlite"
        self.witness_db=self.root/"witness.sqlite"
        self.key=Ed25519PrivateKey.generate()
        self.broker=Ed25519PrivateKey.generate()
        self.request={"operation_id":"rollback-op","action":"payment:simulate",
                      "target":"fixture:merchant-a","amount_cents":100}
        self.intent=create_intent(self.broker,"broker-1","broker",
                                  self.request,"r"*48)
        self.witness=SignerWitness(self.witness_db)
        self.signer=SignerPolicy(self.signer_db,self.key,"issuer","broker","broker-1",
            self.broker.public_key().public_bytes_raw().hex(),signer_witness=self.witness)

    def test_restored_signer_database_cannot_resurrect_consumed_intent(self):
        baseline=self.root/"baseline.sqlite"
        shutil.copy2(self.signer_db,baseline)
        self.signer.authorize(self.request,self.intent)
        shutil.copy2(baseline,self.signer_db)
        restarted=SignerPolicy(self.signer_db,self.key,"issuer","broker","broker-1",
            self.broker.public_key().public_bytes_raw().hex(),
            signer_witness=SignerWitness(self.witness_db))
        with self.assertRaises(PermissionError):
            restarted.authorize(self.request,self.intent)

    def test_witness_rejects_same_nonce_and_new_nonce_for_same_operation(self):
        first=dict(self.request,operation_id="op-a")
        self.witness.consume("s"*48,"op-a",first)
        with self.assertRaises(PermissionError):
            self.witness.consume("s"*48,"op-b",dict(self.request,operation_id="op-b"))
        with self.assertRaises(PermissionError):
            self.witness.consume("t"*48,"op-a",first)

    def test_witness_failure_prevents_capability_issuance(self):
        class Unavailable:
            def consume(self,*args):
                raise PermissionError("witness unavailable")
        blocked=SignerPolicy(self.root/"other.sqlite",self.key,"issuer","broker","broker-1",
            self.broker.public_key().public_bytes_raw().hex(),signer_witness=Unavailable())
        with self.assertRaises(PermissionError):
            blocked.authorize(self.request,self.intent)
        self.assertEqual(self.signer_db.exists(),True)

    def test_request_digest_is_bound_to_witness_record(self):
        first=dict(self.request,operation_id="op-digest")
        self.witness.consume("u"*48,"op-digest",first)
        with self.assertRaises(PermissionError):
            self.witness.consume("v"*48,"op-digest",dict(first,amount_cents=101))

    def test_signed_receipts_form_verifiable_append_chain(self):
        from signer_witness import RECEIPT_DOMAIN,ZERO_HASH
        from signed_receipt import canonical
        witness_key=Ed25519PrivateKey.generate()
        witness=SignerWitness(self.root/"signed.sqlite",witness_key)
        first=witness.consume("a"*48,"chain-a",dict(self.request,operation_id="chain-a"))
        second=witness.consume("b"*48,"chain-b",dict(self.request,operation_id="chain-b"))
        p1,p2=first["payload"],second["payload"]
        self.assertEqual(p1["sequence"],1)
        self.assertEqual(p1["previous_hash"],ZERO_HASH)
        self.assertEqual(p2["sequence"],2)
        self.assertEqual(p2["previous_hash"],p1["entry_hash"])
        witness_key.public_key().verify(bytes.fromhex(first["signature"]),RECEIPT_DOMAIN+canonical(p1))
        witness_key.public_key().verify(bytes.fromhex(second["signature"]),RECEIPT_DOMAIN+canonical(p2))
        altered=dict(p2,operation_id="attacker-op")
        with self.assertRaises(Exception):
            witness_key.public_key().verify(bytes.fromhex(second["signature"]),RECEIPT_DOMAIN+canonical(altered))

    def test_concurrent_appends_produce_one_linear_hash_chain(self):
        from concurrent.futures import ThreadPoolExecutor
        from signer_witness import RECEIPT_DOMAIN
        from signed_receipt import canonical
        key=Ed25519PrivateKey.generate()
        witness=SignerWitness(self.root/"concurrent.sqlite",key)
        def append(i):
            request=dict(self.request,operation_id="parallel-%02d"%i)
            return witness.consume(("n%047d"%i),"parallel-%02d"%i,request)
        with ThreadPoolExecutor(max_workers=8) as pool:
            receipts=list(pool.map(append,range(12)))
        receipts.sort(key=lambda item:item["payload"]["sequence"])
        self.assertEqual([r["payload"]["sequence"] for r in receipts],list(range(1,13)))
        previous="0"*64
        for receipt in receipts:
            payload=receipt["payload"]
            self.assertEqual(payload["previous_hash"],previous)
            key.public_key().verify(bytes.fromhex(receipt["signature"]),RECEIPT_DOMAIN+canonical(payload))
            previous=payload["entry_hash"]
