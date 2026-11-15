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
        def unique_object(pairs):
            result={}
            for key,value in pairs:
                if key in result: raise ValueError("duplicate JSON key")
                result[key]=value
            return result
        if not message.startswith(AUTH_DOMAIN): raise InvalidSignature
        try:
            payload_bytes=message[len(AUTH_DOMAIN):]
            payload=json.loads(payload_bytes.decode("utf-8"),object_pairs_hook=unique_object)
            if canonical(payload)!=payload_bytes: raise InvalidSignature
            bundle=json.loads(signature.decode("utf-8"),object_pairs_hook=unique_object)
            if canonical(bundle)!=signature: raise InvalidSignature
        except (ValueError,UnicodeDecodeError,TypeError):
            raise InvalidSignature
        if not verify_approval_bundle(payload,bundle,self.policy): raise InvalidSignature

def make_threshold_transition(new_witness_private,witness_id,current_state,checkpoint,
                              policy,signers):
    from witness_key_recovery import SCHEMA,POP_DOMAIN,state_digest
    from checkpoint_council import valid_checkpoint
    if not valid_policy_checkpoint(checkpoint): raise ValueError("invalid checkpoint")
    if (type(signers) is not dict or len(signers)<policy.get("threshold",10**9)
        or any(not isinstance(signer,RecoveryAuthoritySigner) for signer in signers.values())):
        raise ValueError("threshold transitions require durable RecoveryAuthoritySigner instances")
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
        import os,stat,sqlite3
        flags=os.O_CREAT|os.O_EXCL|os.O_RDWR|getattr(os,"O_NOFOLLOW",0)
        try:
            fd=os.open(self.ledger_path,flags,0o600)
            os.close(fd)
        except FileExistsError:
            info=os.stat(self.ledger_path,follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError("recovery approval ledger must be a private regular file")
        os.chmod(self.ledger_path,0o600,follow_symlinks=False)
        with sqlite3.connect(self.ledger_path,timeout=10) as con:
            con.execute("PRAGMA journal_mode=DELETE")
            con.execute("PRAGMA synchronous=FULL")
            con.execute("CREATE TABLE IF NOT EXISTS recovery_ledger_meta (key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            authority_key_hash=hashlib.sha256(self.public_key().public_bytes_raw()).hexdigest()
            existing=con.execute("SELECT value FROM recovery_ledger_meta WHERE key='authority_id'").fetchone()
            key_existing=con.execute("SELECT value FROM recovery_ledger_meta WHERE key='authority_key_sha256'").fetchone()
            if existing is not None and (existing[0]!=self.authority_id or key_existing is None or key_existing[0]!=authority_key_hash):
                raise ValueError("recovery ledger is already bound to another authority identity")
            if existing is None:
                if key_existing is not None:
                    raise ValueError("incomplete recovery ledger identity binding")
                con.execute("INSERT INTO recovery_ledger_meta VALUES ('authority_id',?)",(self.authority_id,))
                con.execute("INSERT INTO recovery_ledger_meta VALUES ('authority_key_sha256',?)",(authority_key_hash,))
            con.execute("""CREATE TABLE IF NOT EXISTS recovery_approval_ledger_v4 (
                policy_id TEXT NOT NULL, authority_id TEXT NOT NULL,
                witness_id TEXT NOT NULL, generation INTEGER NOT NULL,
                policy_sha256 TEXT NOT NULL, previous_state_sha256 TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL, signature TEXT NOT NULL,
                PRIMARY KEY(authority_id,witness_id,generation))""")
            con.execute("""CREATE TABLE IF NOT EXISTS recovery_approval_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                previous_event_sha256 TEXT NOT NULL,
                policy_id TEXT NOT NULL, authority_id TEXT NOT NULL,
                witness_id TEXT NOT NULL, generation INTEGER NOT NULL,
                policy_sha256 TEXT NOT NULL, previous_state_sha256 TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL, signature TEXT NOT NULL,
                event_sha256 TEXT NOT NULL UNIQUE)""")
            legacy=con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='recovery_approval_ledger_v3'").fetchone()
            if legacy:
                con.execute("BEGIN IMMEDIATE")
                rows=con.execute("""SELECT policy_id,authority_id,witness_id,generation,
                    policy_sha256,previous_state_sha256,payload_sha256,signature
                    FROM recovery_approval_ledger_v3 ORDER BY policy_id,authority_id,witness_id,generation""").fetchall()
                for row in rows:
                    policy_id,authority_id,witness_id,generation,pd,parent,digest,signature=row
                    if authority_id!=self.authority_id:
                        raise ValueError("legacy ledger contains a different authority identity")
                    try:
                        self.public_key().verify(bytes.fromhex(signature),
                            DOMAIN+canonical({"policy_sha256":pd,"payload_sha256":digest}))
                    except (InvalidSignature,ValueError,TypeError):
                        raise ValueError("legacy ledger signature does not match pinned authority key")
                    prior=con.execute("""SELECT policy_id,policy_sha256,previous_state_sha256,
                        payload_sha256,signature FROM recovery_approval_ledger_v4
                        WHERE authority_id=? AND witness_id=? AND generation=?""",
                        (authority_id,witness_id,generation)).fetchone()
                    expected=(policy_id,pd,parent,digest,signature)
                    if prior is not None and tuple(prior)!=expected:
                        raise ValueError("legacy ledger has conflicting approvals; manual reconciliation required")
                    if prior is None:
                        con.execute("INSERT INTO recovery_approval_ledger_v4 VALUES (?,?,?,?,?,?,?,?)",row)
                    event_row=con.execute("""SELECT 1 FROM recovery_approval_events
                        WHERE policy_id=? AND authority_id=? AND witness_id=? AND generation=?""",
                        (policy_id,authority_id,witness_id,generation)).fetchone()
                    if event_row is None:
                        tail=con.execute("SELECT event_sha256 FROM recovery_approval_events ORDER BY sequence DESC LIMIT 1").fetchone()
                        previous=tail[0] if tail else "0"*64
                        sequence=con.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM recovery_approval_events").fetchone()[0]
                        event={"sequence":sequence,"previous_event_sha256":previous,"policy_id":policy_id,
                            "authority_id":authority_id,"witness_id":witness_id,"generation":generation,
                            "policy_sha256":pd,"previous_state_sha256":parent,"payload_sha256":digest,
                            "signature":signature}
                        event_hash=hashlib.sha256(canonical(event)).hexdigest()
                        con.execute("""INSERT INTO recovery_approval_events
                            (sequence,previous_event_sha256,policy_id,authority_id,witness_id,generation,
                             policy_sha256,previous_state_sha256,payload_sha256,signature,event_sha256)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                            (sequence,previous,policy_id,authority_id,witness_id,generation,pd,parent,digest,signature,event_hash))
                con.commit()

    def public_key(self):
        return self.private_key.public_key()

    def approve(self,payload,policy):
        import sqlite3
        if not validate_policy(policy) or self.authority_id not in policy["authorities"]:
            raise ValueError("authority is not enrolled in pinned policy")
        if self.public_key().public_bytes_raw().hex()!=policy["authorities"][self.authority_id]:
            raise ValueError("authority private key does not match pinned identity")
        scope=(policy["policy_id"],self.authority_id,payload.get("witness_id"),
            payload.get("generation"))
        previous_state=payload.get("previous_state_sha256")
        if (type(scope[2]) is not str or not scope[2] or type(scope[3]) is not int
            or scope[3]<1 or type(previous_state) is not str or len(previous_state)!=64):
            raise ValueError("payload lacks a valid recovery scope")
        digest=payload_digest(payload)
        pd=policy_digest(policy)
        statement=DOMAIN+canonical({"policy_sha256":pd,"payload_sha256":digest})
        signature=self.private_key.sign(statement).hex()
        with sqlite3.connect(self.ledger_path,timeout=10) as con:
            con.execute("PRAGMA synchronous=FULL")
            con.execute("BEGIN IMMEDIATE")
            row=con.execute("""SELECT policy_sha256,previous_state_sha256,payload_sha256,signature
                FROM recovery_approval_ledger_v4
                WHERE authority_id=? AND witness_id=? AND generation=?""",scope[1:]).fetchone()
            if row:
                if row[0]!=pd or row[1]!=previous_state or row[2]!=digest:
                    raise ValueError("recovery authority equivocation refused")
                return row[3]
            con.execute("INSERT INTO recovery_approval_ledger_v4 VALUES (?,?,?,?,?,?,?,?)",
                (*scope,pd,previous_state,digest,signature))
            prior=con.execute("SELECT event_sha256 FROM recovery_approval_events ORDER BY sequence DESC LIMIT 1").fetchone()
            previous_event=prior[0] if prior else "0"*64
            next_sequence=con.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM recovery_approval_events").fetchone()[0]
            event={"sequence":next_sequence,"previous_event_sha256":previous_event,"policy_id":scope[0],
                "authority_id":scope[1],"witness_id":scope[2],"generation":scope[3],
                "policy_sha256":pd,"previous_state_sha256":previous_state,
                "payload_sha256":digest,"signature":signature}
            event_hash=hashlib.sha256(canonical(event)).hexdigest()
            con.execute("""INSERT INTO recovery_approval_events
                (previous_event_sha256,policy_id,authority_id,witness_id,generation,
                 policy_sha256,previous_state_sha256,payload_sha256,signature,event_sha256)
                 VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (previous_event,scope[0],scope[1],scope[2],scope[3],pd,previous_state,digest,signature,event_hash))
        return signature

    def export_approval_ledger(self):
        import sqlite3
        with sqlite3.connect(self.ledger_path,timeout=10) as con:
            rows=con.execute("""SELECT sequence,previous_event_sha256,policy_id,authority_id,
                witness_id,generation,policy_sha256,previous_state_sha256,payload_sha256,
                signature,event_sha256 FROM recovery_approval_events ORDER BY sequence""").fetchall()
        fields=("sequence","previous_event_sha256","policy_id","authority_id","witness_id",
            "generation","policy_sha256","previous_state_sha256","payload_sha256","signature","event_sha256")
        events=[dict(zip(fields,row)) for row in rows]
        return {"schema":"AML-SEF2-RECOVERY-APPROVAL-LEDGER-V1","authority_id":self.authority_id,
            "events":events,"head_sha256":events[-1]["event_sha256"] if events else "0"*64}

def verify_approval_ledger(bundle,authority_public_key,expected_head_sha256=None):
    try:
        if type(bundle) is not dict or set(bundle)!={"schema","authority_id","events","head_sha256"}:
            return False
        if (bundle["schema"]!="AML-SEF2-RECOVERY-APPROVAL-LEDGER-V1"
            or type(bundle["authority_id"]) is not str or not bundle["authority_id"]
            or type(bundle["events"]) is not list or type(bundle["head_sha256"]) is not str
            or len(bundle["head_sha256"])!=64
            or any(c not in "0123456789abcdef" for c in bundle["head_sha256"])):
            return False
        if expected_head_sha256 is not None and (type(expected_head_sha256) is not str
            or len(expected_head_sha256)!=64 or any(c not in "0123456789abcdef" for c in expected_head_sha256)):
            return False
        previous="0"*64
        seen=set()
        for sequence,event in enumerate(bundle["events"],1):
            required={"sequence","previous_event_sha256","policy_id","authority_id","witness_id",
                "generation","policy_sha256","previous_state_sha256","payload_sha256","signature","event_sha256"}
            if type(event) is not dict or set(event)!=required: return False
            if (type(event["sequence"]) is not int or event["sequence"]!=sequence
                or type(event["authority_id"]) is not str or event["authority_id"]!=bundle["authority_id"]
                or type(event["policy_id"]) is not str or not event["policy_id"]
                or type(event["witness_id"]) is not str or not event["witness_id"]
                or type(event["generation"]) is not int or event["generation"]<1
                or type(event["previous_event_sha256"]) is not str or len(event["previous_event_sha256"])!=64
                or event["previous_event_sha256"]!=previous
                or type(event["signature"]) is not str or len(event["signature"])!=128
                or type(event["event_sha256"]) is not str or len(event["event_sha256"])!=64):
                return False
            for field in ("policy_sha256","previous_state_sha256","payload_sha256","event_sha256"):
                value=event[field]
                if type(value) is not str or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
                    return False
            scope=(event["policy_id"],event["authority_id"],event["witness_id"],event["generation"])
            if scope in seen: return False
            seen.add(scope)
            signed=DOMAIN+canonical({"policy_sha256":event["policy_sha256"],
                "payload_sha256":event["payload_sha256"]})
            authority_public_key.verify(bytes.fromhex(event["signature"]),signed)
            unsigned={k:event[k] for k in required if k!="event_sha256"}
            calculated=hashlib.sha256(canonical(unsigned)).hexdigest()
            if calculated!=event["event_sha256"]: return False
            previous=calculated
        if bundle["head_sha256"]!=previous: return False
        if expected_head_sha256 is not None and expected_head_sha256!=previous: return False
        return True
    except (InvalidSignature,ValueError,TypeError,KeyError,OverflowError,AttributeError):
        return False
