"""Opt-in atomic reservation + hash-chain ledger for synthetic SEF2 research.

Do not substitute this fixture for an independently anchored witness. An
attacker restoring this whole database can restore its chain as well.
"""
import sqlite3
import os
import stat
from pathlib import Path
from reservation_receipt_chain import GENESIS, reservation_chain_hash, verify_reservation_chain

class AtomicReceiptReservations:
    def __init__(self, path, authority_id, *, require_existing=False):
        if (type(authority_id) is not str or not 1 <= len(authority_id) <= 128
            or not authority_id.isascii() or not authority_id.isprintable()):
            raise ValueError("invalid authority")
        self.path = str(path)
        self.authority_id = authority_id
        self.uri = Path(path).absolute().as_uri() + "?mode=rw"
        self._identity = None
        # Refuse pre-existing symlinks before SQLite can open their target.
        # This is a preflight check, not a race-free openat2/O_NOFOLLOW boundary.
        if os.path.lexists(self.path) and not stat.S_ISREG(os.lstat(self.path).st_mode):
            raise ValueError("ledger path is not a regular file")
        if require_existing and not Path(path).is_file():
            raise ValueError("missing ledger")
        with sqlite3.connect(self.path, isolation_level=None) as db:
            db.execute("BEGIN IMMEDIATE")
            names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            required = {"receipt_reservations", "receipt_head"}
            if not names and not require_existing:
                db.execute("CREATE TABLE receipt_reservations (sequence INTEGER PRIMARY KEY, authority_id TEXT NOT NULL, operation_id TEXT NOT NULL, digest TEXT NOT NULL, generation INTEGER NOT NULL, chain_hash TEXT NOT NULL, UNIQUE(authority_id, operation_id))")
                db.execute("CREATE TABLE receipt_head (singleton INTEGER PRIMARY KEY CHECK(singleton=1), sequence INTEGER NOT NULL, chain_hash TEXT NOT NULL)")
                db.execute("INSERT INTO receipt_head VALUES (1,0,?)", (GENESIS,))
            elif not required.issubset(names):
                db.execute("ROLLBACK")
                raise ValueError("missing receipt security tables")
            db.execute("COMMIT")
        self._identity = self._file_identity()

    def _file_identity(self):
        info = os.stat(self.path, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("ledger is not a regular file")
        return info.st_dev, info.st_ino

    def _assert_identity(self):
        if self._file_identity() != self._identity:
            raise ValueError("ledger replaced")

    def reserve(self, operation_id, digest, generation):
        try:
            # Validation happens before any storage write.
            reservation_chain_hash(GENESIS, self.authority_id, operation_id, digest, generation)
            self._assert_identity()
            with sqlite3.connect(self.uri, uri=True, timeout=10, isolation_level=None) as db:
                self._assert_identity()
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                heads = db.execute("SELECT sequence,chain_hash FROM receipt_head WHERE singleton=1").fetchall()
                if len(heads) != 1:
                    return False
                sequence, previous = heads[0]
                if type(sequence) is not int or sequence < 0:
                    return False
                rows = db.execute("SELECT sequence,authority_id,operation_id,digest,generation,chain_hash FROM receipt_reservations ORDER BY sequence").fetchall()
                if len(rows) != sequence or any(row[0] != index for index, row in enumerate(rows, 1)):
                    return False
                entries = [row[1:5] for row in rows]
                if not verify_reservation_chain(entries, previous, sequence):
                    return False
                cursor = GENESIS
                for row in rows:
                    cursor = reservation_chain_hash(cursor, *row[1:5])
                    if cursor != row[5]:
                        return False
                chain_hash = reservation_chain_hash(previous, self.authority_id, operation_id, digest, generation)
                db.execute("INSERT INTO receipt_reservations VALUES (?,?,?,?,?,?)",
                           (sequence + 1, self.authority_id, operation_id, digest, generation, chain_hash))
                updated = db.execute("UPDATE receipt_head SET sequence=?,chain_hash=? WHERE singleton=1 AND sequence=? AND chain_hash=?",
                                     (sequence + 1, chain_hash, sequence, previous))
                if updated.rowcount != 1:
                    return False
                db.execute("COMMIT")
                return True
        except (sqlite3.Error, OSError, TypeError, ValueError):
            return False

    def evidence(self):
        """Return local ordered evidence; caller MUST compare to trusted external head."""
        self._assert_identity()
        with sqlite3.connect(self.uri, uri=True, timeout=10) as db:
            self._assert_identity()
            head = db.execute("SELECT sequence,chain_hash FROM receipt_head WHERE singleton=1").fetchone()
            entries = db.execute("SELECT authority_id,operation_id,digest,generation FROM receipt_reservations ORDER BY sequence").fetchall()
        return head, entries
