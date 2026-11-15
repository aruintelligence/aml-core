"""Independent, durable at-most-once reservation fixture.

The reservation database must be protected by a different administrative trust
boundary than the effect database. Reserve BEFORE applying an effect. A crash
between reservation and effect commit may permanently strand an operation;
this deliberately favors safety over availability. Not external effect proof.
"""
import sqlite3
from pathlib import Path

class IndependentEffectReservations:
    def __init__(self, path, authority_id, require_existing=False):
        if type(authority_id) is not str or not authority_id or len(authority_id) > 128:
            raise ValueError("invalid authority identity")
        if type(require_existing) is not bool:
            raise TypeError("require_existing must be bool")
        self.path = str(path)
        self.authority_id = authority_id
        self._existing_uri = Path(self.path).absolute().as_uri() + '?mode=rw'
        if require_existing:
            import os
            if not os.path.isfile(self.path):
                raise ValueError("reservation store missing")
        with sqlite3.connect(self.path, timeout=10, isolation_level=None) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not tables and require_existing:
                db.execute("ROLLBACK")
                raise ValueError("reservation store empty")
            if not tables:
                db.execute("CREATE TABLE reservations (authority_id TEXT NOT NULL, operation_id TEXT NOT NULL, digest TEXT NOT NULL, generation INTEGER NOT NULL, PRIMARY KEY(authority_id, operation_id))")
            elif "reservations" not in tables:
                db.execute("ROLLBACK")
                raise ValueError("reservation security table missing")
            db.execute("COMMIT")

    def reserve(self, operation_id, digest, generation):
        if (type(operation_id) is not str or not 1 <= len(operation_id) <= 128
            or not operation_id.isascii() or not operation_id.isprintable()
            or type(digest) is not str or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
            or type(generation) is not int or generation < 0):
            return False
        try:
            with sqlite3.connect(self._existing_uri, uri=True, timeout=10, isolation_level=None) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO reservations VALUES (?,?,?,?)",
                           (self.authority_id, operation_id, digest, generation))
                db.execute("COMMIT")
            return True
        except sqlite3.Error:
            return False

    def inspect(self, operation_id):
        """Read-only recovery evidence; never grants a retry or clears a reservation.

        Returns a stored digest/generation or None if no reservation exists.
        An unavailable or damaged store raises instead of implying absence.
        """
        if (type(operation_id) is not str or not 1 <= len(operation_id) <= 128
            or not operation_id.isascii() or not operation_id.isprintable()):
            raise ValueError("invalid operation identifier")
        with sqlite3.connect(self._existing_uri, uri=True, timeout=10, isolation_level=None) as db:
            db.execute("BEGIN")
            row = db.execute(
                "SELECT digest,generation FROM reservations WHERE authority_id=? AND operation_id=?",
                (self.authority_id, operation_id)).fetchone()
            db.execute("COMMIT")
        return None if row is None else {"digest": row[0], "generation": row[1]}
