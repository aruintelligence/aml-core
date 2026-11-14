import copy
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from checkpoint_council import WitnessCouncil,publish

def cp(epoch=1,head="a"*64):
    return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":epoch,
        "head_hash":head,"count":epoch,"approver_key_id":"c"*64}

class CheckpointCouncilTests(unittest.TestCase):
    def setUp(self):
        self.private={n:Ed25519PrivateKey.generate() for n in ("north","south","east")}
        self.public={n:k.public_key() for n,k in self.private.items()}
        self.council=WitnessCouncil(self.public,2)
        self.first=[publish(self.private[n],n,cp()) for n in ("north","south")]

    def test_quorum_accepts_matching_pins(self):
        self.assertEqual(self.council.adjudicate(self.first,cp()),"WITNESS_QUORUM_CONSISTENT")

    def test_insufficient_witnesses_rejected(self):
        self.assertEqual(self.council.adjudicate(self.first[:1],cp()),"INSUFFICIENT_WITNESSES")

    def test_duplicate_witness_rejected(self):
        self.assertEqual(self.council.adjudicate(self.first[:1]*2,cp()),"UNTRUSTED_OR_DUPLICATE")

    def test_untrusted_witness_rejected(self):
        other=publish(Ed25519PrivateKey.generate(),"outsider",cp())
        self.assertEqual(self.council.adjudicate(self.first+[other],cp()),"UNTRUSTED_OR_DUPLICATE")

    def test_forged_signature_rejected(self):
        forged=copy.deepcopy(self.first)
        forged[0]["signature"]="00"*64
        self.assertEqual(self.council.adjudicate(forged,cp()),"INVALID_SIGNATURE")

    def test_checkpoint_fork_rejected(self):
        divergent=[self.first[0],publish(self.private["south"],"south",cp(head="b"*64))]
        self.assertEqual(self.council.adjudicate(divergent,cp()),"FORK_DETECTED")

    def test_stale_epoch_rejected(self):
        self.assertEqual(self.council.adjudicate(self.first,cp(2)),"STALE_HISTORY")

    def test_retained_checkpoint_rejects_rollback(self):
        self.council.retain([publish(self.private[n],n,cp(2)) for n in ("north","south")],cp(2))
        self.assertEqual(self.council.adjudicate(self.first,cp()),"STALE_HISTORY")

    def test_retained_checkpoint_rejects_same_epoch_fork(self):
        self.council.retain(self.first,cp())
        fork=[publish(self.private[n],n,cp(head="b"*64)) for n in ("north","south")]
        self.assertEqual(self.council.adjudicate(fork,cp(head="b"*64)),"FORK_DETECTED")

    def test_new_epoch_accepted_after_retention(self):
        self.council.retain(self.first,cp())
        newer=[publish(self.private[n],n,cp(2,head="b"*64)) for n in ("north","south")]
        self.assertEqual(self.council.retain(newer,cp(2,head="b"*64)),"WITNESS_QUORUM_CONSISTENT")

    def test_duplicate_public_key_configuration_rejected(self):
        with self.assertRaises(ValueError):
            WitnessCouncil({"north":self.public["north"],"south":self.public["north"]},2)

    def test_invalid_quorum_configuration_rejected(self):
        with self.assertRaises(ValueError):
            WitnessCouncil(self.public,1)

    def test_boolean_epoch_rejected(self):
        bad=cp()
        bad["epoch"]=True
        with self.assertRaises(ValueError):
            publish(self.private["north"],"north",bad)

    def test_mismatched_approver_identity_rejected(self):
        different=cp()
        different["approver_key_id"]="f"*64
        bad=[publish(self.private["north"],"north",different),self.first[1]]
        self.assertEqual(self.council.adjudicate(bad,cp()),"FORK_DETECTED")
