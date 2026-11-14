"""Durable independently provisioned synthetic checkpoint witness.

One SQLite file and one private key per witness administration boundary.
The signed response authenticates publication; no network transport is provided.
"""
import json
import pathlib
import sqlite3
from checkpoint_council import publish,valid_checkpoint
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

    def publish(self,checkpoint):
        if not valid_checkpoint(checkpoint):
            return "INVALID",None
        with sqlite3.connect(self.path,timeout=10) as con:
            con.execute("BEGIN IMMEDIATE")
            last=con.execute("SELECT epoch,head FROM retained WHERE slot=1").fetchone()
            if last:
                if checkpoint["epoch"]<last[0]:
                    return "STALE_HISTORY",None
                if checkpoint["epoch"]==last[0]:
                    if checkpoint["head_hash"]!=last[1]:
                        return "FORK_DETECTED",None
                    row=con.execute("SELECT envelope FROM checkpoints WHERE epoch=?",(last[0],)).fetchone()
                    if row is None:
                        return "CORRUPT_STATE",None
                    return "REPLAY",json.loads(row[0])
            envelope=publish(self.private,self.name,checkpoint)
            con.execute("INSERT INTO checkpoints VALUES (?,?,?,?)",
                (checkpoint["epoch"],checkpoint["head_hash"],
                 json.dumps(checkpoint,sort_keys=True),json.dumps(envelope,sort_keys=True)))
            con.execute("INSERT INTO retained VALUES (1,?,?) ON CONFLICT(slot) DO UPDATE SET epoch=excluded.epoch,head=excluded.head",
                (checkpoint["epoch"],checkpoint["head_hash"]))
            return "PUBLISHED",envelope

    def latest(self):
        with sqlite3.connect("file:"+pathlib.Path(self.path).resolve().as_posix()+"?mode=ro",uri=True) as con:
            row=con.execute("SELECT envelope FROM checkpoints ORDER BY epoch DESC LIMIT 1").fetchone()
        return json.loads(row[0]) if row else None
