"""Independent evaluator-side durable pin registry for synthetic SEF2.

Keep this database outside the witness rollback domain and provision it with a
separate administrative owner. SQLite transactions persist pin transitions.
A restored copy of *this* registry can still roll back: external monotonic
hardware or independently replicated pins are required for stronger guarantees.
"""
import pathlib
import sqlite3

class PinRegistry:
    def __init__(self,path):
        self.path=str(path)
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE IF NOT EXISTS pins (witness TEXT PRIMARY KEY, active TEXT NOT NULL, pending TEXT, generation INTEGER NOT NULL)")
    def enroll(self,witness,pin):
        if type(witness) is not str or not witness or not _pin(pin):
            raise ValueError("invalid enrollment")
        with sqlite3.connect(self.path,timeout=10) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM pins WHERE witness=?",(witness,)).fetchone():
                raise ValueError("already enrolled")
            db.execute("INSERT INTO pins VALUES (?,?,NULL,0)",(witness,pin))
    def state(self,witness):
        with sqlite3.connect("file:"+pathlib.Path(self.path).resolve().as_posix()+"?mode=ro",uri=True) as db:
            row=db.execute("SELECT active,pending,generation FROM pins WHERE witness=?",(witness,)).fetchone()
        if row is None:
            raise ValueError("unenrolled witness")
        return {"active":row[0],"pending":row[1],"generation":row[2]}
    def prepare(self,witness,old_pin,new_pin):
        if not _pin(old_pin) or not _pin(new_pin) or old_pin==new_pin:
            raise ValueError("invalid pin transition")
        with sqlite3.connect(self.path,timeout=10) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT active,pending FROM pins WHERE witness=?",(witness,)).fetchone()
            if row!=(old_pin,None):
                raise ValueError("stale or concurrent transition")
            db.execute("UPDATE pins SET pending=? WHERE witness=?",(new_pin,witness))
    def commit(self,witness,old_pin,new_pin):
        with sqlite3.connect(self.path,timeout=10) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT active,pending FROM pins WHERE witness=?",(witness,)).fetchone()
            if row!=(old_pin,new_pin):
                raise ValueError("unapproved pin commit")
            db.execute("UPDATE pins SET active=?,pending=NULL,generation=generation+1 WHERE witness=?",(new_pin,witness))

def _pin(value):
    return type(value) is str and len(value)==64 and all(c in "0123456789abcdef" for c in value)
