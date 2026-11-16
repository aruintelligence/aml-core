"""Durable local pinned-checkpoint laboratory.

SQLite transaction commits a monotonic checkpoint. This is not remote,
independent, hardware-backed, or power-loss durability evidence.
"""
import sqlite3
from witness_chain import verify, checkpoint, GENESIS

class DurablePinnedWitness:
    def __init__(self, path):
        self.path = path
        with self._db() as con:
            con.execute("CREATE TABLE IF NOT EXISTS pin (id INTEGER PRIMARY KEY CHECK(id=1), size INTEGER NOT NULL, head TEXT NOT NULL)")

    def _db(self):
        return sqlite3.connect(self.path, timeout=10, isolation_level=None)

    def pinned(self):
        with self._db() as con:
            row = con.execute("SELECT size,head FROM pin WHERE id=1").fetchone()
        return {"size": row[0], "head": row[1]} if row else None

    def observe(self, chain):
        if not verify(chain):
            return "INVALID_CHAIN"
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT size,head FROM pin WHERE id=1").fetchone()
            old = {"size": row[0], "head": row[1]} if row else None
            if old is not None and not verify(chain, old):
                con.execute("ROLLBACK")
                return "ROLLBACK_OR_FORK"
            now = checkpoint(chain)
            if now == old:
                con.execute("COMMIT")
                return "UNCHANGED"
            con.execute("INSERT INTO pin(id,size,head) VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET size=excluded.size, head=excluded.head", (now["size"], now["head"]))
            con.execute("COMMIT")
            return "ADVANCED"
