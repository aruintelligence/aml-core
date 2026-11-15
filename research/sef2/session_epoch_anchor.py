"""Monotonic external epoch anchor for session capability revocation.

Reference SQLite implementation. Security against broker rollback exists only
when this state is retained outside the broker's rollback/administrative domain.
"""
import sqlite3

class SessionEpochAnchor:
    def __init__(self,path,anchor_id="session-epoch-anchor"):
        if type(anchor_id) is not str or not anchor_id: raise ValueError("invalid anchor id")
        self.path=str(path); self.anchor_id=anchor_id
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA journal_mode=DELETE"); db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS session_epoch_anchor (
                audience TEXT PRIMARY KEY, epoch INTEGER NOT NULL CHECK(epoch>=0))""")
            db.commit()
    def initialize(self,audience,epoch=0):
        if type(audience) is not str or not audience or type(epoch) is not int or epoch<0:
            raise ValueError("invalid epoch anchor initialization")
        with sqlite3.connect(self.path,timeout=5,isolation_level=None) as db:
            db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT epoch FROM session_epoch_anchor WHERE audience=?",(audience,)).fetchone()
            if row is None:
                db.execute("INSERT INTO session_epoch_anchor VALUES (?,?)",(audience,epoch)); return epoch
            if row[0]!=epoch: raise ValueError("anchor already initialized at different epoch")
            return row[0]
    def read_epoch(self,audience):
        with sqlite3.connect(self.path) as db:
            row=db.execute("SELECT epoch FROM session_epoch_anchor WHERE audience=?",(audience,)).fetchone()
        if row is None: raise ValueError("anchor audience not initialized")
        return row[0]
    def compare_and_set(self,audience,expected,new):
        if (type(expected) is not int or type(new) is not int or expected<0
            or new!=expected+1):
            return False
        with sqlite3.connect(self.path,timeout=5,isolation_level=None) as db:
            db.execute("PRAGMA synchronous=FULL"); db.execute("BEGIN IMMEDIATE")
            cur=db.execute("UPDATE session_epoch_anchor SET epoch=? WHERE audience=? AND epoch=?",
                (new,audience,expected))
            return cur.rowcount==1
