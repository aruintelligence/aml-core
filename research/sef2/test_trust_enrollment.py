import concurrent.futures
import pathlib
import tempfile
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from trust_enrollment import Enrollment,propose

def pub(k):
    return k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()

class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.approver=Ed25519PrivateKey.generate()
        self.keys={role:pub(Ed25519PrivateKey.generate()) for role in ("authority","provider","witness")}
        self.db=str(pathlib.Path(self.tmp.name)/"trust.sqlite")
        self.store=Enrollment(self.db,self.approver.public_key())

    def test_initial_approved_enrollment(self):
        self.assertEqual(self.store.accept(propose(self.approver,1,self.keys)),"ENROLLED")
        self.assertEqual(self.store.manifest()["public_keys"],self.keys)

    def test_untrusted_approver_rejected(self):
        self.assertEqual(self.store.accept(propose(Ed25519PrivateKey.generate(),1,self.keys)),"UNAUTHORIZED")

    def test_tampered_signed_enrollment_rejected(self):
        e=propose(self.approver,1,self.keys)
        e["payload"]["epoch"]=2
        self.assertEqual(self.store.accept(e),"UNAUTHORIZED")

    def test_replayed_epoch_rejected(self):
        e=propose(self.approver,1,self.keys)
        self.store.accept(e)
        self.assertEqual(self.store.accept(e),"STALE_EPOCH")

    def test_rotation_requires_revocation(self):
        self.store.accept(propose(self.approver,1,self.keys))
        changed=dict(self.keys)
        changed["witness"]=pub(Ed25519PrivateKey.generate())
        self.assertEqual(self.store.accept(propose(self.approver,2,changed)),"MISSING_REVOCATION")

    def test_approved_rotation_revokes_old_witness(self):
        self.store.accept(propose(self.approver,1,self.keys))
        old=self.keys["witness"]
        changed=dict(self.keys)
        changed["witness"]=pub(Ed25519PrivateKey.generate())
        self.assertEqual(self.store.accept(propose(self.approver,2,changed,[old])),"ENROLLED")
        self.assertEqual(self.store.manifest()["public_keys"]["witness"],changed["witness"])

    def test_revoked_witness_cannot_return(self):
        self.store.accept(propose(self.approver,1,self.keys))
        old=self.keys["witness"]
        changed=dict(self.keys)
        changed["witness"]=pub(Ed25519PrivateKey.generate())
        self.store.accept(propose(self.approver,2,changed,[old]))
        self.assertEqual(self.store.accept(propose(self.approver,3,self.keys,
            [changed["witness"]])),"REVOKED_KEY")

    def test_restart_persists_epoch(self):
        self.store.accept(propose(self.approver,1,self.keys))
        again=Enrollment(self.db,self.approver.public_key())
        self.assertEqual(again.accept(propose(self.approver,1,self.keys)),"STALE_EPOCH")

    def test_concurrent_same_epoch_one_wins(self):
        e=propose(self.approver,1,self.keys)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results=list(pool.map(self.store.accept,[e]*6))
        self.assertEqual(results.count("ENROLLED"),1)
        self.assertEqual(results.count("STALE_EPOCH"),5)

    def test_role_key_collision_rejected(self):
        self.keys["witness"]=self.keys["provider"]
        self.assertEqual(self.store.accept(propose(self.approver,1,self.keys)),"INVALID")

    def test_invalid_signature_rejected(self):
        e=propose(self.approver,1,self.keys)
        e["signature"]="00"*64
        self.assertEqual(self.store.accept(e),"UNAUTHORIZED")

    def test_boolean_epoch_rejected(self):
        self.assertEqual(self.store.accept(propose(self.approver,True,self.keys)),"INVALID")
