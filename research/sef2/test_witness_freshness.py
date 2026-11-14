import copy
import pathlib
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from durable_checkpoint_witness import DurableWitness
from witness_freshness import WitnessEndpoint,verify_fresh,challenge

def cp(epoch=1,head="a"*64):
    return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":epoch,
        "head_hash":head,"count":epoch,"approver_key_id":"c"*64}

class FreshWitnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.private={n:Ed25519PrivateKey.generate() for n in ("north","south","east")}
        self.public={n:k.public_key() for n,k in self.private.items()}
        self.stores={n:DurableWitness(str(pathlib.Path(self.tmp.name)/(n+".sqlite")),n,k)
                     for n,k in self.private.items()}
        for store in self.stores.values():
            self.assertEqual(store.publish(cp())[0],"PUBLISHED")
        self.nonce=challenge()
        self.responses=[WitnessEndpoint(self.stores[n]).latest(self.nonce) for n in ("north","south")]

    def check(self,responses=None,nonce=None,expected=None,threshold=2):
        return verify_fresh(self.responses if responses is None else responses,
            self.nonce if nonce is None else nonce,self.public,threshold,cp() if expected is None else expected)

    def test_challenge_bound_quorum(self):
        self.assertEqual(self.check(),"FRESH_QUORUM_CONSISTENT")

    def test_old_challenge_replay_rejected(self):
        self.assertEqual(self.check(nonce=challenge()),"INVALID")

    def test_forged_signature_rejected(self):
        bad=copy.deepcopy(self.responses)
        bad[0]["signature"]="00"*64
        self.assertEqual(self.check(responses=bad),"INVALID_SIGNATURE")

    def test_duplicate_witness_rejected(self):
        self.assertEqual(self.check(responses=self.responses[:1]*2),"UNTRUSTED_OR_DUPLICATE")

    def test_missing_quorum_rejected(self):
        self.assertEqual(self.check(responses=self.responses[:1]),"INSUFFICIENT_WITNESSES")

    def test_stale_witness_rejected(self):
        self.assertEqual(self.check(expected=cp(2)),"STALE_HISTORY")

    def test_competing_fork_rejected(self):
        self.stores["south"].publish(cp(2,"b"*64))
        newer=[WitnessEndpoint(self.stores[n]).latest(self.nonce) for n in ("north","south")]
        self.assertEqual(self.check(responses=newer),"FORK_OR_ADVANCED_HISTORY")

    def test_advanced_epoch_rejected(self):
        for store in self.stores.values():
            store.publish(cp(2,"b"*64))
        newer=[WitnessEndpoint(self.stores[n]).latest(self.nonce) for n in ("north","south")]
        self.assertEqual(self.check(responses=newer),"FORK_OR_ADVANCED_HISTORY")

    def test_separate_store_restart_retains_latest(self):
        new=DurableWitness(str(pathlib.Path(self.tmp.name)/"north.sqlite"),"north",self.private["north"])
        self.assertEqual(WitnessEndpoint(new).latest(self.nonce)["payload"]["checkpoint"],cp())

    def test_missing_checkpoint_fails_closed(self):
        blank=DurableWitness(str(pathlib.Path(self.tmp.name)/"blank.sqlite"),"blank",Ed25519PrivateKey.generate())
        with self.assertRaises(ValueError):
            WitnessEndpoint(blank).latest(self.nonce)

    def test_invalid_challenge_rejected(self):
        with self.assertRaises(ValueError):
            WitnessEndpoint(self.stores["north"]).latest("not-a-nonce")

    def test_duplicate_pinned_key_rejected(self):
        self.assertEqual(verify_fresh(self.responses,self.nonce,
            {"north":self.public["north"],"south":self.public["north"]},2,cp()),"INVALID")
