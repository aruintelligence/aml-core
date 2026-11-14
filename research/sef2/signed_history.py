"""Append-only signed trust-history research verifier with external checkpoint pin.

A checkpoint is only independently retained if evaluator stores its hash and
highest epoch outside the writable enrollment database.
"""
import hashlib
import json
import sqlite3
from cryptography.exceptions import InvalidSignature
from signed_receipt import canonical
from trust_enrollment import DOMAIN, valid

GENESIS="0"*64
def digest(v):
    return hashlib.sha256(canonical(v)).hexdigest()

class SignedHistory:
    def __init__(self,path,approver_public):
        self.path=path
        self.approver=approver_public
        with sqlite3.connect(path) as con:
            con.execute("CREATE TABLE IF NOT EXISTS signed_epochs (epoch INTEGER PRIMARY KEY, envelope TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL)")

    def append(self,envelope):
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
                rows=con.execute("SELECT epoch,envelope,prev_hash,entry_hash FROM signed_epochs ORDER BY epoch").fetchall()
                if not self._validate(rows):
                    return "CORRUPT_HISTORY"
                if rows and payload["epoch"]<=rows[-1][0]:
                    return "STALE_EPOCH"
                previous=json.loads(rows[-1][1])["payload"] if rows else None
                old=set(previous["public_keys"].values()) if previous else set()
                current=set(payload["public_keys"].values())
                revoked=set(payload["revoked_key_hex"])
                historical=set()
                for _,raw,_,_ in rows:
                    historical.update(json.loads(raw)["payload"]["revoked_key_hex"])
                if not (old-current).issubset(revoked):
                    return "MISSING_REVOCATION"
                if current.intersection(historical|revoked):
                    return "REVOKED_KEY"
                prev=rows[-1][3] if rows else GENESIS
                h=digest({"previous":prev,"envelope":envelope})
                con.execute("INSERT INTO signed_epochs VALUES (?,?,?,?)",
                    (payload["epoch"],canonical(envelope).decode(),prev,h))
            return "ENROLLED"
        except (sqlite3.Error,ValueError,KeyError,TypeError):
            return "STORE_ERROR"

    def _validate(self,rows):
        prev=GENESIS
        last=0
        old=set()
        revoked=set()
        for epoch,raw,stored_prev,entry_hash in rows:
            try:
                envelope=json.loads(raw)
                if type(envelope) is not dict or set(envelope)!={"payload","signature"}:
                    return False
                payload=envelope["payload"]
                if not valid(payload) or payload["epoch"]!=epoch or epoch<=last:
                    return False
                self.approver.verify(bytes.fromhex(envelope["signature"]),DOMAIN+canonical(payload))
                current=set(payload["public_keys"].values())
                new_revoked=set(payload["revoked_key_hex"])
                if not (old-current).issubset(new_revoked) or current.intersection(revoked|new_revoked):
                    return False
                if stored_prev!=prev or entry_hash!=digest({"previous":prev,"envelope":envelope}):
                    return False
                old=current
                revoked.update(new_revoked)
                last=epoch
                prev=entry_hash
            except (ValueError,TypeError,KeyError,InvalidSignature):
                return False
        return True

    def checkpoint(self):
        with sqlite3.connect(self.path) as con:
            rows=con.execute("SELECT epoch,envelope,prev_hash,entry_hash FROM signed_epochs ORDER BY epoch").fetchall()
        if not rows or not self._validate(rows):
            return None
        return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1",
            "epoch":rows[-1][0],"head_hash":rows[-1][3],
            "count":len(rows),"approver_key_id":hashlib.sha256(
                self.approver.public_bytes_raw()).hexdigest()}

    def verify_checkpoint(self,external_checkpoint,expected_sha256):
        if type(external_checkpoint) is not dict or type(expected_sha256) is not str:
            return False
        if digest(external_checkpoint)!=expected_sha256:
            return False
        current=self.checkpoint()
        return current is not None and current==external_checkpoint
