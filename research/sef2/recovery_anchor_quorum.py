"""Independent quorum witnesses for monotonic recovery-ledger checkpoint pins.

Each witness is expected to run under a distinct administrative/storage domain.
Local SQLite persistence is not rollback-resistant; verifiers retain the last
accepted certificate/pin independently. This is a quorum checkpoint protocol,
not general-purpose Byzantine consensus.
"""
import hashlib,sqlite3,os,stat
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from signed_receipt import canonical
from recovery_ledger_anchor import checkpoint_pin,CHECKPOINT_SCHEMA

POLICY_SCHEMA="AML-SEF2-RECOVERY-ANCHOR-POLICY-V1"
PAYLOAD_SCHEMA="AML-SEF2-RECOVERY-ANCHOR-PAYLOAD-V1"
CERT_SCHEMA="AML-SEF2-RECOVERY-ANCHOR-CERTIFICATE-V1"
DOMAIN=b"AML-SEF2-INDEPENDENT-RECOVERY-ANCHOR-V1\x00"
GENESIS_PIN="0"*64

def policy_digest(policy):
    return hashlib.sha256(canonical(policy)).hexdigest()

def validate_anchor_policy(policy):
    try:
        if type(policy) is not dict or set(policy)!={"schema","policy_id","threshold","max_faults","authorities"}:
            return False
        if policy["schema"]!=POLICY_SCHEMA or type(policy["policy_id"]) is not str or not policy["policy_id"]:
            return False
        members=policy["authorities"]; q=policy["threshold"]; f=policy["max_faults"]
        if type(members) is not dict or type(q) is not int or type(f) is not int: return False
        n=len(members)
        if f<0 or n<3*f+1 or q<1 or q>n-f or 2*q-n<=f: return False
        seen=set()
        for name,key_hex in members.items():
            if type(name) is not str or not name or type(key_hex) is not str: return False
            raw=bytes.fromhex(key_hex)
            if len(raw)!=32 or raw in seen: return False
            seen.add(raw)
        return True
    except (ValueError,TypeError,KeyError):
        return False

def valid_checkpoint(checkpoint):
    try:
        if type(checkpoint) is not dict or set(checkpoint)!={"schema","authority_id","authority_key_sha256","sequence","head_hash"}:
            return False
        if (checkpoint["schema"]!=CHECKPOINT_SCHEMA or type(checkpoint["authority_id"]) is not str
            or not checkpoint["authority_id"] or type(checkpoint["sequence"]) is not int
            or checkpoint["sequence"]<0):
            return False
        for field in ("authority_key_sha256","head_hash"):
            value=checkpoint[field]
            if type(value) is not str or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
                return False
        return True
    except (KeyError,TypeError):
        return False

def make_anchor_payload(checkpoint,sequence,previous_pin_sha256,policy):
    if not validate_anchor_policy(policy): raise ValueError("invalid anchor policy")
    if not valid_checkpoint(checkpoint): raise ValueError("invalid recovery ledger checkpoint")
    if type(sequence) is not int or sequence<1: raise ValueError("invalid anchor sequence")
    if type(previous_pin_sha256) is not str or len(previous_pin_sha256)!=64:
        raise ValueError("invalid previous anchor pin")
    if any(c not in "0123456789abcdef" for c in previous_pin_sha256):
        raise ValueError("invalid previous anchor pin")
    return {"schema":PAYLOAD_SCHEMA,"policy_id":policy["policy_id"],
        "target_authority_id":checkpoint["authority_id"],"sequence":sequence,
        "previous_pin_sha256":previous_pin_sha256,"checkpoint":checkpoint,
        "checkpoint_pin_sha256":checkpoint_pin(checkpoint)}

class RecoveryAnchorWitness:
    """One independent anchor identity with a durable local monotonic vote ledger."""
    def __init__(self,anchor_id,private_key,database_path):
        self.anchor_id=anchor_id; self.private_key=private_key; self.database_path=str(database_path)
        flags=os.O_CREAT|os.O_EXCL|os.O_RDWR|getattr(os,"O_NOFOLLOW",0)
        try:
            fd=os.open(self.database_path,flags,0o600); os.close(fd)
        except FileExistsError:
            info=os.stat(self.database_path,follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError("anchor witness database must be a private regular file")
        os.chmod(self.database_path,0o600,follow_symlinks=False)
        with sqlite3.connect(self.database_path,timeout=10) as con:
            con.execute("PRAGMA journal_mode=DELETE"); con.execute("PRAGMA synchronous=FULL")
            con.execute("""CREATE TABLE IF NOT EXISTS anchor_state (
                target_authority_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL,
                pin_sha256 TEXT NOT NULL, policy_id TEXT NOT NULL, policy_sha256 TEXT NOT NULL)""")
            con.execute("""CREATE TABLE IF NOT EXISTS anchor_votes (
                target_authority_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                policy_id TEXT NOT NULL, policy_sha256 TEXT NOT NULL,
                previous_pin_sha256 TEXT NOT NULL, checkpoint_pin_sha256 TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL, signature TEXT NOT NULL,
                PRIMARY KEY(target_authority_id,sequence))""")
    def public_key(self): return self.private_key.public_key()
    def approve(self,payload,policy):
        if not validate_anchor_policy(policy) or self.anchor_id not in policy["authorities"]:
            raise ValueError("anchor witness is not enrolled")
        if self.public_key().public_bytes_raw().hex()!=policy["authorities"][self.anchor_id]:
            raise ValueError("anchor witness key does not match pinned policy")
        if (type(payload) is not dict or set(payload)!={"schema","policy_id","target_authority_id",
            "sequence","previous_pin_sha256","checkpoint","checkpoint_pin_sha256"}
            or payload["schema"]!=PAYLOAD_SCHEMA or payload["policy_id"]!=policy["policy_id"]
            or not valid_checkpoint(payload["checkpoint"])
            or payload["checkpoint"]["authority_id"]!=payload["target_authority_id"]
            or checkpoint_pin(payload["checkpoint"])!=payload["checkpoint_pin_sha256"]):
            raise ValueError("invalid anchor payload")
        pd=policy_digest(policy); digest=hashlib.sha256(canonical(payload)).hexdigest()
        statement=DOMAIN+canonical({"policy_sha256":pd,"payload_sha256":digest})
        signature=self.private_key.sign(statement).hex()
        with sqlite3.connect(self.database_path,timeout=10) as con:
            con.execute("PRAGMA synchronous=FULL"); con.execute("BEGIN IMMEDIATE")
            scope=(payload["target_authority_id"],payload["sequence"])
            prior=con.execute("""SELECT policy_id,policy_sha256,previous_pin_sha256,
                checkpoint_pin_sha256,payload_sha256,signature FROM anchor_votes
                WHERE target_authority_id=? AND sequence=?""",scope).fetchone()
            if prior:
                if tuple(prior[:5])!=(policy["policy_id"],pd,payload["previous_pin_sha256"],
                    payload["checkpoint_pin_sha256"],digest):
                    raise ValueError("anchor witness equivocation refused")
                return prior[5]
            state=con.execute("""SELECT sequence,pin_sha256,policy_id,policy_sha256
                FROM anchor_state WHERE target_authority_id=?""",(payload["target_authority_id"],)).fetchone()
            if state is None:
                expected_sequence=1; expected_pin=GENESIS_PIN
            else:
                expected_sequence=state[0]+1; expected_pin=state[1]
                if state[2]!=policy["policy_id"] or state[3]!=pd:
                    raise ValueError("anchor policy rotation requires explicit re-enrollment")
            if payload["sequence"]!=expected_sequence or payload["previous_pin_sha256"]!=expected_pin:
                raise ValueError("stale or forked anchor checkpoint")
            con.execute("INSERT INTO anchor_votes VALUES (?,?,?,?,?,?,?,?)",
                (payload["target_authority_id"],payload["sequence"],policy["policy_id"],pd,
                 payload["previous_pin_sha256"],payload["checkpoint_pin_sha256"],digest,signature))
            con.execute("""INSERT INTO anchor_state VALUES (?,?,?,?,?)
                ON CONFLICT(target_authority_id) DO UPDATE SET sequence=excluded.sequence,
                pin_sha256=excluded.pin_sha256,policy_id=excluded.policy_id,policy_sha256=excluded.policy_sha256""",
                (payload["target_authority_id"],payload["sequence"],payload["checkpoint_pin_sha256"],
                 policy["policy_id"],pd))
        return signature

def make_anchor_certificate(payload,policy,witnesses):
    if not validate_anchor_policy(policy): raise ValueError("invalid anchor policy")
    if type(witnesses) is not dict or len(witnesses)<policy["threshold"]:
        raise ValueError("insufficient anchor witnesses")
    approvals=[]
    for anchor_id,witness in witnesses.items():
        if not isinstance(witness,RecoveryAnchorWitness) or witness.anchor_id!=anchor_id:
            raise ValueError("invalid anchor witness object")
        approvals.append({"anchor_id":anchor_id,"signature":witness.approve(payload,policy)})
    approvals.sort(key=lambda x:x["anchor_id"])
    return {"schema":CERT_SCHEMA,"policy_sha256":policy_digest(policy),
        "payload_sha256":hashlib.sha256(canonical(payload)).hexdigest(),"approvals":approvals}

def verify_anchor_certificate(payload,certificate,policy,expected_sequence,expected_previous_pin):
    try:
        if not validate_anchor_policy(policy): return False
        if type(payload) is not dict or set(payload)!={"schema","policy_id","target_authority_id",
            "sequence","previous_pin_sha256","checkpoint","checkpoint_pin_sha256"}: return False
        if (payload["schema"]!=PAYLOAD_SCHEMA or payload["policy_id"]!=policy["policy_id"]
            or type(payload["sequence"]) is not int or payload["sequence"]<1
            or type(expected_sequence) is not int or expected_sequence<1 or payload["sequence"]!=expected_sequence
            or type(expected_previous_pin) is not str or len(expected_previous_pin)!=64
            or any(c not in "0123456789abcdef" for c in expected_previous_pin)
            or payload["previous_pin_sha256"]!=expected_previous_pin
            or not valid_checkpoint(payload["checkpoint"])
            or payload["checkpoint"]["authority_id"]!=payload["target_authority_id"]
            or checkpoint_pin(payload["checkpoint"])!=payload["checkpoint_pin_sha256"]):
            return False
        if type(certificate) is not dict or set(certificate)!={"schema","policy_sha256","payload_sha256","approvals"}:
            return False
        digest=hashlib.sha256(canonical(payload)).hexdigest()
        pd=policy_digest(policy)
        if (certificate["schema"]!=CERT_SCHEMA or certificate["policy_sha256"]!=pd
            or certificate["payload_sha256"]!=digest or type(certificate["approvals"]) is not list
            or len(certificate["approvals"])<policy["threshold"]):
            return False
        statement=DOMAIN+canonical({"policy_sha256":pd,"payload_sha256":digest})
        ids=[]
        for approval in certificate["approvals"]:
            if type(approval) is not dict or set(approval)!={"anchor_id","signature"}: return False
            aid=approval["anchor_id"]
            if type(aid) is not str or aid not in policy["authorities"] or aid in ids: return False
            ids.append(aid)
            signature=bytes.fromhex(approval["signature"])
            if len(signature)!=64: return False
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(policy["authorities"][aid])).verify(signature,statement)
        return ids==sorted(ids)
    except (InvalidSignature,ValueError,TypeError,KeyError,OverflowError,AttributeError):
        return False
