"""Durable independently provisioned synthetic checkpoint witness.

One SQLite file and one private key per witness administration boundary.
The signed response authenticates publication; no network transport is provided.
"""
import json
import pathlib
import sqlite3
from checkpoint_council import publish,valid_checkpoint,DOMAIN
from signed_receipt import canonical
from cryptography.exceptions import InvalidSignature
from signed_history import digest

class DurableWitness:
    def __init__(self,path,witness_id,private_key):
        if type(witness_id) is not str or not witness_id:
            raise ValueError("invalid witness")
        self.path=str(path)
        self.name=witness_id
        self.private=private_key
        with sqlite3.connect(self.path) as con:
            con.execute("CREATE TABLE IF NOT EXISTS checkpoints (epoch INTEGER PRIMARY KEY, head TEXT NOT NULL, payload TEXT NOT NULL, envelope TEXT NOT NULL)")
            con.execute("CREATE TABLE IF NOT EXISTS retained (slot INTEGER PRIMARY KEY CHECK(slot=1), epoch INTEGER NOT NULL, head TEXT NOT NULL)")

    def _checked_latest(self,con):
        retained=con.execute("SELECT epoch,head FROM retained WHERE slot=1").fetchone()
        row=con.execute("SELECT epoch,head,payload,envelope FROM checkpoints ORDER BY epoch DESC LIMIT 1").fetchone()
        if not retained and not row:
            return None
        if not retained or not row:
            raise ValueError("missing retained checkpoint")
        epoch,head,payload_raw,envelope_raw=row
        checkpoint=json.loads(payload_raw)
        envelope=json.loads(envelope_raw)
        if (epoch!=retained[0] or head!=retained[1] or not valid_checkpoint(checkpoint)
            or checkpoint["epoch"]!=epoch or checkpoint["head_hash"]!=head
            or type(envelope) is not dict or set(envelope)!={"payload","signature"}):
            raise ValueError("inconsistent witness checkpoint")
        body=envelope["payload"]
        if (type(body) is not dict or set(body)!={"version","witness_id","checkpoint"}
            or body["version"]!=1 or body["witness_id"]!=self.name
            or body["checkpoint"]!=checkpoint):
            raise ValueError("invalid witness envelope")
        try:
            self.private.public_key().verify(bytes.fromhex(envelope["signature"]),DOMAIN+canonical(body))
        except (InvalidSignature,TypeError,ValueError,KeyError) as error:
            raise ValueError("invalid persisted witness signature") from error
        return envelope

    def publish(self,checkpoint):
        if not valid_checkpoint(checkpoint):
            return "INVALID",None
        with sqlite3.connect(self.path,timeout=10) as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                previous=self._checked_latest(con)
            except (ValueError,TypeError,KeyError):
                return "CORRUPT_STATE",None
            last=con.execute("SELECT epoch,head FROM retained WHERE slot=1").fetchone()
            if last:
                if checkpoint["epoch"]<last[0]:
                    return "STALE_HISTORY",None
                if checkpoint["epoch"]==last[0]:
                    if checkpoint!=previous["payload"]["checkpoint"]:
                        return "FORK_DETECTED",None
                    return "REPLAY",previous
            envelope=publish(self.private,self.name,checkpoint)
            con.execute("INSERT INTO checkpoints VALUES (?,?,?,?)",
                (checkpoint["epoch"],checkpoint["head_hash"],
                 json.dumps(checkpoint,sort_keys=True),json.dumps(envelope,sort_keys=True)))
            con.execute("INSERT INTO retained VALUES (1,?,?) ON CONFLICT(slot) DO UPDATE SET epoch=excluded.epoch,head=excluded.head",
                (checkpoint["epoch"],checkpoint["head_hash"]))
            return "PUBLISHED",envelope

    def latest(self):
        with sqlite3.connect("file:"+pathlib.Path(self.path).resolve().as_posix()+"?mode=ro",uri=True) as con:
            return self._checked_latest(con)
