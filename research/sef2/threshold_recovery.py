"""Threshold recovery approvals with independent Ed25519 authority identities.

The policy is supplied and pinned out-of-band by the verifier. This module
validates an approval bundle over an exact canonical payload; it does not
provide secure policy distribution, key custody, revocation freshness, or
anti-rollback storage.
"""
import hashlib,json
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
  if type(policy) is not dict or set(policy)!={"schema","policy_id","threshold","max_faults","authorities"}: return False
  if policy["schema"]!=POLICY_SCHEMA or type(policy["policy_id"]) is not str or not policy["policy_id"]: return False
  authorities=policy["authorities"]; threshold=policy["threshold"]; faults=policy["max_faults"]
  if type(authorities) is not dict or type(threshold) is not int or type(faults) is not int: return False
  n=len(authorities)
  if faults<0 or n<3*faults+1 or threshold<1 or threshold>n-faults: return False
  if 2*threshold-n<=faults: return False
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
  public_hex=private_key.public_key().public_bytes_raw().hex() if hasattr(private_key,"public_key") else ""
  if public_hex!=policy["authorities"][aid]: raise ValueError("private key does not match authority identity")
  signature=private_key.approve(payload,policy) if isinstance(private_key,RecoveryAuthoritySigner) else private_key.sign(statement).hex()
  approvals.append({"authority_id":aid,"signature":signature})
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

class ThresholdRecoveryPublicKey:
    """Adapter implementing the Ed25519 verify interface expected by recovery."""
    def __init__(self,policy):
        if not validate_policy(policy): raise ValueError("invalid threshold recovery policy")
        self.policy=policy
    def verify(self,signature,message):
        from witness_key_recovery import AUTH_DOMAIN
        if not message.startswith(AUTH_DOMAIN): raise InvalidSignature
        try:
            payload=__import__("json").loads(message[len(AUTH_DOMAIN):].decode("utf-8"))
        except (ValueError,UnicodeDecodeError):
            raise InvalidSignature
        bundle=__import__("json").loads(signature.decode("utf-8"))
        if not verify_approval_bundle(payload,bundle,self.policy): raise InvalidSignature

def make_threshold_transition(new_witness_private,witness_id,current_state,checkpoint,
                              policy,signers):
    from witness_key_recovery import SCHEMA,POP_DOMAIN,state_digest
    from checkpoint_council import valid_checkpoint
    if not valid_policy_checkpoint(checkpoint): raise ValueError("invalid checkpoint")
    payload={"schema":SCHEMA,"witness_id":witness_id,
        "generation":current_state["generation"]+1,
        "previous_state_sha256":state_digest(current_state),
        "previous_public_key_sha256":current_state["public_key_sha256"],
        "new_public_key_hex":new_witness_private.public_key().public_bytes_raw().hex(),
        "checkpoint":checkpoint,"recovery_authority_id":policy["policy_id"]}
    bundle=make_approval_bundle(payload,policy,signers)
    return {"payload":payload,"recovery_signature":canonical(bundle).hex(),
        "proof_of_possession":new_witness_private.sign(POP_DOMAIN+canonical(payload)).hex()}

def valid_policy_checkpoint(checkpoint):
    from checkpoint_council import valid_checkpoint
    return valid_checkpoint(checkpoint)

class RecoveryAuthoritySigner:
    """Local durable anti-equivocation guard for one authority identity.

    This is not rollback-resistant. The ledger must be independently protected
    and anchored to prevent snapshot restoration from erasing prior approvals.
    """
    def __init__(self,authority_id,private_key,ledger_path):
        self.authority_id=authority_id
        self.private_key=private_key
        self.ledger_path=str(ledger_path)
        import sqlite3
        with sqlite3.connect(self.ledger_path,timeout=10) as con:
            con.execute("PRAGMA journal_mode=DELETE")
            con.execute("PRAGMA synchronous=FULL")
            con.execute("""CREATE TABLE IF NOT EXISTS recovery_approval_ledger (
                policy_sha256 TEXT NOT NULL, authority_id TEXT NOT NULL,
                witness_id TEXT NOT NULL, generation INTEGER NOT NULL,
                previous_state_sha256 TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
                signature TEXT NOT NULL,
                PRIMARY KEY(policy_sha256,authority_id,witness_id,generation,previous_state_sha256))""")

    def public_key(self):
        return self.private_key.public_key()

    def approve(self,payload,policy):
        import sqlite3
        if not validate_policy(policy) or self.authority_id not in policy["authorities"]:
            raise ValueError("authority is not enrolled in pinned policy")
        if self.public_key().public_bytes_raw().hex()!=policy["authorities"][self.authority_id]:
            raise ValueError("authority private key does not match pinned identity")
        scope=(policy_digest(policy),self.authority_id,payload.get("witness_id"),
            payload.get("generation"),payload.get("previous_state_sha256"))
        if (type(scope[2]) is not str or not scope[2] or type(scope[3]) is not int
            or scope[3]<1 or type(scope[4]) is not str or len(scope[4])!=64):
            raise ValueError("payload lacks a valid recovery scope")
        digest=payload_digest(payload)
        statement=DOMAIN+canonical({"policy_sha256":scope[0],"payload_sha256":digest})
        signature=self.private_key.sign(statement).hex()
        with sqlite3.connect(self.ledger_path,timeout=10) as con:
            con.execute("PRAGMA synchronous=FULL")
            con.execute("BEGIN IMMEDIATE")
            row=con.execute("""SELECT payload_sha256,signature FROM recovery_approval_ledger
                WHERE policy_sha256=? AND authority_id=? AND witness_id=? AND generation=? AND previous_state_sha256=?""",scope).fetchone()
            if row:
                if row[0]!=digest: raise ValueError("recovery authority equivocation refused")
                return row[1]
            con.execute("INSERT INTO recovery_approval_ledger VALUES (?,?,?,?,?,?,?)",(*scope,digest,signature))
        return signature
