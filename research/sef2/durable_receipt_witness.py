"""Independent durable monotonic checkpoint witness research fixture.

Deploy under a distinct administrator and filesystem boundary from the
reservation ledger. This is a local witness store, NOT a network-authenticated
witness service. A privileged witness administrator can still roll it back.
"""
import sqlite3
import os
import stat
from pathlib import Path
from reservation_receipt_chain import reservation_chain_hash, GENESIS

def _valid_head(head):
    return (type(head) is str and len(head) == 64
            and all(c in "0123456789abcdef" for c in head))

class DurableReceiptWitness:
    def __init__(self, path, authority_id, *, require_existing=False):
        if (type(authority_id) is not str or not 1 <= len(authority_id) <= 128
            or not authority_id.isascii() or not authority_id.isprintable()):
            raise ValueError("invalid witness authority")
        self.authority_id = authority_id
        self.path = str(path)
        self.uri = Path(path).absolute().as_uri() + "?mode=rw"
        if os.path.lexists(self.path) and not stat.S_ISREG(os.lstat(self.path).st_mode):
            raise ValueError("witness path is not a regular file")
        if require_existing and not Path(path).is_file():
            raise ValueError("witness store missing")
        with sqlite3.connect(self.path, isolation_level=None) as db:
            db.execute("BEGIN IMMEDIATE")
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not tables and not require_existing:
                db.execute("CREATE TABLE witness_heads (authority_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL, head TEXT NOT NULL)")
            elif "witness_heads" not in tables:
                db.execute("ROLLBACK")
                raise ValueError("witness security table missing")
            db.execute("COMMIT")
        self._identity = self._file_identity()

    def _file_identity(self):
        info = os.stat(self.path, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("witness database is not regular")
        return info.st_dev, info.st_ino

    def _assert_identity(self):
        if self._file_identity() != self._identity:
            raise ValueError("witness database replaced")

    def observe(self, sequence, head, previous_sequence, previous_head, entry=None):
        """CAS-advance from exact prior witnessed state, never skip an update.

        The caller must separately establish that the proposed head genuinely
        commits to the claimed reservation history. This fixture alone cannot.
        """
        if (type(sequence) is not int or sequence < 0
            or type(previous_sequence) is not int or previous_sequence < 0
            or not _valid_head(head) or not _valid_head(previous_head)):
            return False
        try:
            self._assert_identity()
            with sqlite3.connect(self.uri, uri=True, timeout=10, isolation_level=None) as db:
                self._assert_identity()
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                current = db.execute("SELECT sequence,head FROM witness_heads WHERE authority_id=?",
                                     (self.authority_id,)).fetchone()
                if current is None:
                    if entry is not None:
                        return False
                    if previous_sequence != 0 or previous_head != "0" * 64 or sequence != 0 or head != "0" * 64:
                        return False
                    db.execute("INSERT INTO witness_heads VALUES (?,?,?)",
                               (self.authority_id, sequence, head))
                else:
                    if current != (previous_sequence, previous_head):
                        return False
                    if sequence != previous_sequence + 1:
                        return False
                    if type(entry) not in (tuple, list) or len(entry) != 4:
                        return False
                    if entry[0] != self.authority_id:
                        return False
                    if reservation_chain_hash(previous_head, *entry) != head:
                        return False
                    db.execute("UPDATE witness_heads SET sequence=?,head=? WHERE authority_id=?",
                               (sequence, head, self.authority_id))
                db.execute("COMMIT")
                return True
        except (sqlite3.Error, OSError, ValueError):
            return False

    def inspect(self):
        self._assert_identity()
        with sqlite3.connect(Path(self.path).absolute().as_uri() + "?mode=ro",
                             uri=True, timeout=10) as db:
            self._assert_identity()
            return db.execute("SELECT sequence,head FROM witness_heads WHERE authority_id=?",
                              (self.authority_id,)).fetchone()
