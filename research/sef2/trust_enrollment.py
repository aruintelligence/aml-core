"""Research trust enrollment: separately pinned approver, atomic epoch/rotation/revocation.

The approver public key is a caller-held trust root. All state changes require
a valid approver signature and strictly increasing epoch; revoked identities
cannot be reinstated under the same key.
"""
import hashlib
import json
import sqlite3
from cryptography.exceptions import InvalidSignature
from signed_receipt import canonical

DOMAIN=b"AML-SEF2-TRUST-ENROLLMENT-V1\x00"
ROLES=("authority","provider","witness")

def propose(private, epoch, keys, revoked=()):
    payload={"version":1,"epoch":epoch,"public_keys":dict(keys),
             "revoked_key_hex":sorted(revoked)}
    return {"payload":payload,"signature":private.sign(DOMAIN+canonical(payload)).hex()}

def valid(payload):
    if type(payload) is not dict or set(payload)!={"version","epoch","public_keys","revoked_key_hex"}:
        return False
    if type(payload["version"]) is not int or payload["version"]!=1:
        return False
    if type(payload["epoch"]) is not int or not 0<payload["epoch"]<2**63:
        return False
    keys=payload["public_keys"]
    if type(keys) is not dict or set(keys)!=set(ROLES):
        return False
    values=list(keys.values())
    if len(set(values))!=3 or not all(type(x) is str and len(x)==64 and all(c in "0123456789abcdef" for c in x) for x in values):
        return False
    rev=payload["revoked_key_hex"]
    return (type(rev) is list and rev==sorted(set(rev)) and
        all(type(x) is str and len(x)==64 and all(c in "0123456789abcdef" for c in x) for x in rev)
        and not set(values).intersection(rev))

class Enrollment:
    def __init__(self,path,pinned_approver_public_key):
        self.path=path
        self.approver=pinned_approver_public_key
        with sqlite3.connect(path) as con:
            con.execute("CREATE TABLE IF NOT EXISTS epochs (epoch INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
            con.execute("CREATE TABLE IF NOT EXISTS revoked (key_hex TEXT PRIMARY KEY)")

    def accept(self,envelope):
        if type(envelope) is not dict or set(envelope)!={"payload","signature"}:
            return "INVALID"
        payload=envelope["payload"]
        if not valid(payload) or type(envelope["signature"]) is not str or len(envelope["signature"])!=128:
            return "INVALID"
        try:
            self.approver.verify(bytes.fromhex(envelope["signature"]),DOMAIN+canonical(payload))
        except (InvalidSignature,ValueError,TypeError):
            return "UNAUTHORIZED"
        try:
            with sqlite3.connect(self.path,timeout=10) as con:
                con.execute("BEGIN IMMEDIATE")
                last=con.execute("SELECT epoch,payload FROM epochs ORDER BY epoch DESC LIMIT 1").fetchone()
                if last and payload["epoch"]<=last[0]:
                    return "STALE_EPOCH"
                old=json.loads(last[1]) if last else None
                previous=set(old["public_keys"].values()) if old else set()
                incoming=set(payload["public_keys"].values())
                required_revocations=previous-incoming
                declared=set(payload["revoked_key_hex"])
                if not required_revocations.issubset(declared):
                    return "MISSING_REVOCATION"
                prior_revoked={r[0] for r in con.execute("SELECT key_hex FROM revoked")}
                if incoming.intersection(prior_revoked | declared):
                    return "REVOKED_KEY"
                for key in declared:
                    con.execute("INSERT OR IGNORE INTO revoked VALUES (?)",(key,))
                con.execute("INSERT INTO epochs VALUES (?,?)",
                    (payload["epoch"],canonical(payload).decode()))
        except sqlite3.Error:
            return "STORE_ERROR"
        return "ENROLLED"

    def manifest(self):
        with sqlite3.connect(self.path) as con:
            row=con.execute("SELECT payload FROM epochs ORDER BY epoch DESC LIMIT 1").fetchone()
            if not row:
                return None
            return json.loads(row[0])
