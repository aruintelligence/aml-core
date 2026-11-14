"""Threshold recovery approvals with independent Ed25519 authority identities.

The policy is supplied and pinned out-of-band by the verifier. This module
validates an approval bundle over an exact canonical payload; it does not
provide secure policy distribution, key custody, revocation freshness, or
anti-rollback storage.
"""
import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from signed_receipt import canonical
DOMAIN=b"AML-SEF2-THRESHOLD-RECOVERY-APPROVAL-V1\x00"
POLICY_SCHEMA="AML-SEF2-RECOVERY-QUORUM-POLICY-V1"
BUNDLE_SCHEMA="AML-SEF2-RECOVERY-QUORUM-BUNDLE-V1"
def policy_digest(policy): return hashlib.sha256(canonical(policy)).hexdigest()
def payload_digest(payload): return hashlib.sha256(canonical(payload)).hexdigest()
def validate_policy(policy):
 try:
  if type(policy) is not dict or set(policy)!={"schema","policy_id","threshold","authorities"}: return False
  if policy["schema"]!=POLICY_SCHEMA or type(policy["policy_id"]) is not str or not policy["policy_id"]: return False
  authorities=policy["authorities"]; threshold=policy["threshold"]
  if type(authorities) is not dict or type(threshold) is not int or not 1<=threshold<=len(authorities): return False
  keys=set()
  for aid,key_hex in authorities.items():
   if type(aid) is not str or not aid or type(key_hex) is not str: return False
   raw=bytes.fromhex(key_hex)
   if len(raw)!=32 or raw in keys: return False
   keys.add(raw)
  return True
 except (ValueError,TypeError,KeyError): return False
def make_approval_bundle(payload,policy,signers):
 if not validate_policy(policy): raise ValueError("invalid threshold recovery policy")
 if type(signers) is not dict or len(signers)<policy["threshold"]: raise ValueError("insufficient recovery signers")
 pd=policy_digest(policy); md=payload_digest(payload)
 statement=DOMAIN+canonical({"policy_sha256":pd,"payload_sha256":md})
 approvals=[]
 for aid,private_key in signers.items():
  if aid not in policy["authorities"]: raise ValueError("signer is not in pinned recovery policy")
  public_hex=private_key.public_key().public_bytes_raw().hex()
  if public_hex!=policy["authorities"][aid]: raise ValueError("private key does not match authority identity")
  approvals.append({"authority_id":aid,"signature":private_key.sign(statement).hex()})
 approvals.sort(key=lambda item:item["authority_id"])
 return {"schema":BUNDLE_SCHEMA,"policy_sha256":pd,"payload_sha256":md,"approvals":approvals}
def verify_approval_bundle(payload,bundle,policy):
 try:
  if not validate_policy(policy): return False
  if type(bundle) is not dict or set(bundle)!={"schema","policy_sha256","payload_sha256","approvals"}: return False
  if (bundle["schema"]!=BUNDLE_SCHEMA or bundle["policy_sha256"]!=policy_digest(policy)
      or bundle["payload_sha256"]!=payload_digest(payload) or type(bundle["approvals"]) is not list
      or len(bundle["approvals"])<policy["threshold"]): return False
  ids=[]; statement=DOMAIN+canonical({"policy_sha256":bundle["policy_sha256"],"payload_sha256":bundle["payload_sha256"]})
  for approval in bundle["approvals"]:
   if type(approval) is not dict or set(approval)!={"authority_id","signature"}: return False
   aid=approval["authority_id"]
   if type(aid) is not str or aid not in policy["authorities"] or aid in ids: return False
   ids.append(aid); raw=bytes.fromhex(policy["authorities"][aid]); sig=bytes.fromhex(approval["signature"])
   if len(sig)!=64: return False
   Ed25519PublicKey.from_public_bytes(raw).verify(sig,statement)
  return ids==sorted(ids) and len(ids)>=policy["threshold"]
 except (InvalidSignature,ValueError,TypeError,KeyError,OverflowError,AttributeError): return False
