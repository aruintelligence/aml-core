"""Durable checkpoint high-water store for the SEF2 research fixture.

The database must be controlled by a separate trusted principal. This protects
against verifier process restart, NOT coordinated rollback of the store itself.
"""
import sqlite3
import os

class DurableCheckpointHighWater:
    def __init__(self, path, require_existing=False, require_enrolled=False):
        self.path = str(path)
        if type(require_enrolled) is not bool:
            raise TypeError('require_enrolled must be bool')
        self.require_enrolled = require_enrolled
        if type(require_existing) is not bool:
            raise TypeError('require_existing must be bool')
        if require_existing and not os.path.isfile(self.path):
            raise ValueError('checkpoint database absent: explicit bootstrap required')
        with sqlite3.connect(self.path, timeout=10, isolation_level=None) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            existing = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if not existing and require_existing:
                db.execute("ROLLBACK")
                raise ValueError("existing checkpoint database has no security state")
            if not existing:
                db.execute("CREATE TABLE checkpoint_marks (authority_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL CHECK(sequence>=0), generation INTEGER NOT NULL CHECK(generation>=0))")
            elif "checkpoint_marks" not in existing:
                db.execute("ROLLBACK")
                raise ValueError("existing checkpoint database missing security table")
            db.execute("COMMIT")

    def enroll(self, authority_id, sequence, generation):
        """Explicit bootstrap only; never silently replace an enrolled authority."""
        if (type(authority_id) is not str or not authority_id
            or type(sequence) is not int or sequence < 0
            or type(generation) is not int or generation < 0):
            raise ValueError("invalid checkpoint enrollment")
        with sqlite3.connect(self.path, timeout=10, isolation_level=None) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("INSERT INTO checkpoint_marks (authority_id,sequence,generation) VALUES (?,?,?)",
                           (authority_id, sequence, generation))
            except sqlite3.IntegrityError as exc:
                db.execute("ROLLBACK")
                raise ValueError("checkpoint authority already enrolled") from exc
            db.execute("COMMIT")
        return True

    def observe(self, authority_id, sequence, generation):
        if (type(authority_id) is not str or not authority_id
            or type(sequence) is not int or sequence < 0
            or type(generation) is not int or generation < 0):
            raise ValueError("invalid checkpoint observation")
        with sqlite3.connect(self.path, timeout=10, isolation_level=None) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute(
                "SELECT sequence, generation FROM checkpoint_marks WHERE authority_id=?",
                (authority_id,)).fetchone()
            if prior is None and self.require_enrolled:
                db.execute("ROLLBACK")
                raise ValueError("checkpoint authority not enrolled or security row missing")
            if prior is not None:
                old_sequence, old_generation = prior
                if (sequence < old_sequence or generation < old_generation
                    or (sequence == old_sequence and generation != old_generation)):
                    db.execute("ROLLBACK")
                    raise ValueError("checkpoint rollback or equivocation")
            db.execute(
                "INSERT INTO checkpoint_marks (authority_id,sequence,generation) VALUES (?,?,?) "
                "ON CONFLICT(authority_id) DO UPDATE SET sequence=excluded.sequence,generation=excluded.generation",
                (authority_id, sequence, generation))
            db.execute("COMMIT")
        return generation
