import concurrent.futures,threading,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signed_receipt import canonical
from threshold_recovery import (SignedRecoveryHeadAnchor,QuorumRecoveryHeadAnchor,
    RECOVERY_ANCHOR_READ_DOMAIN,RECOVERY_ANCHOR_CAS_DOMAIN)

class RemoteAnchorTransport:
 def __init__(self,anchor_id,key):
  self.anchor_id=anchor_id; self.key=key; self.head="0"*64; self.available=True; self.lock=threading.Lock()
 def read_head(self,nonce):
  if not self.available: raise OSError("simulated remote anchor outage")
  with self.lock:
   head=self.head
  body={"anchor_id":self.anchor_id,"head_sha256":head,"nonce":nonce}
  return {**body,"signature":self.key.sign(RECOVERY_ANCHOR_READ_DOMAIN+canonical(body)).hex()}
 def compare_and_set(self,expected,new,nonce):
  if not self.available: raise OSError("simulated remote anchor outage")
  with self.lock:
   accepted=self.head==expected
   if accepted: self.head=new
  body={"anchor_id":self.anchor_id,"expected_head":expected,"new_head":new,
    "accepted":accepted,"nonce":nonce}
  return {**body,"signature":self.key.sign(RECOVERY_ANCHOR_CAS_DOMAIN+canonical(body)).hex()}

class RemoteRecoveryAnchorQuorumTests(unittest.TestCase):
 def setUp(self):
  self.transports={f"anchor-{i}":RemoteAnchorTransport(f"anchor-{i}",Ed25519PrivateKey.generate()) for i in range(4)}
  self.anchors={name:SignedRecoveryHeadAnchor(name,server.key.public_key(),server)
    for name,server in self.transports.items()}
  self.quorum=QuorumRecoveryHeadAnchor([self.anchors[k] for k in sorted(self.anchors)],3,1)
  self.genesis="0"*64; self.first="a"*64; self.second="b"*64
 def test_four_signed_remote_anchors_form_three_of_four_quorum(self):
  self.assertEqual(self.quorum.read_head(),self.genesis)
  self.assertTrue(self.quorum.compare_and_set(self.genesis,self.first))
  self.assertEqual(self.quorum.read_head(),self.first)
 def test_one_remote_anchor_outage_preserves_quorum(self):
  self.transports["anchor-3"].available=False
  self.assertTrue(self.quorum.compare_and_set(self.genesis,self.first))
  self.assertEqual(self.quorum.read_head(),self.first)
 def test_forged_remote_anchor_response_is_excluded(self):
  class Forged:
   def __init__(self,inner): self.inner=inner
   def read_head(self,nonce):
    response=self.inner.read_head(nonce); response["signature"]="00"*64; return response
   def compare_and_set(self,*args):
    response=self.inner.compare_and_set(*args); response["signature"]="00"*64; return response
  forged=SignedRecoveryHeadAnchor("anchor-0",self.transports["anchor-0"].key.public_key(),Forged(self.transports["anchor-0"]))
  quorum=QuorumRecoveryHeadAnchor([forged,self.anchors["anchor-1"],self.anchors["anchor-2"],self.anchors["anchor-3"]],3,1)
  self.assertTrue(quorum.compare_and_set(self.genesis,self.first))
  self.assertEqual(quorum.read_head(),self.first)
 def test_two_two_split_brain_has_no_read_quorum(self):
  for name,head in zip(sorted(self.transports),("a"*64,"a"*64,"b"*64,"b"*64)):
   self.transports[name].head=head
  with self.assertRaisesRegex(RuntimeError,"no unique quorum"):
   self.quorum.read_head()
 def test_concurrent_conflicting_remote_cas_cannot_both_reach_quorum(self):
  barrier=threading.Barrier(2)
  def write(head):
   barrier.wait()
   return self.quorum.compare_and_set(self.genesis,head)
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
   results=list(pool.map(write,(self.first,self.second)))
  self.assertEqual(sum(results),1)
  self.assertIn(self.quorum.read_head(),(self.first,self.second))
 def test_wrong_pinned_key_excludes_one_remote_anchor(self):
  bad=SignedRecoveryHeadAnchor("anchor-0",Ed25519PrivateKey.generate().public_key(),self.transports["anchor-0"])
  quorum=QuorumRecoveryHeadAnchor([bad,self.anchors["anchor-1"],self.anchors["anchor-2"],self.anchors["anchor-3"]],3,1)
  self.assertTrue(quorum.compare_and_set(self.genesis,self.first))
  self.assertEqual(quorum.read_head(),self.first)
