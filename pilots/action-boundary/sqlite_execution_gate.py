"""Single-machine test execution claim; retained outside provider rollback domain."""
import sqlite3
from sqlite_path import sqlite_file_uri


def initialize(database):
    con = sqlite3.connect(database, timeout=10, isolation_level=None)
    try:
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("BEGIN IMMEDIATE")
        con.execute("CREATE TABLE IF NOT EXISTS meta (version INTEGER NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS claims (operation_id TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL)")
        if con.execute("SELECT count(*) FROM meta").fetchone()[0] == 0:
            con.execute("INSERT INTO meta VALUES (1)")
        con.execute("COMMIT")
    except BaseException:
        if con.in_transaction:
            con.execute("ROLLBACK")
        raise
    finally:
        con.close()


def consume(database, operation_id, request_sha256):
    # Open existing database only: a missing/rolled-back provider-local state
    # must never create a fresh execution authority implicitly.
    con = sqlite3.connect(sqlite_file_uri(database, "rw"), uri=True,
                          timeout=10, isolation_level=None)
    try:
        con.execute("PRAGMA synchronous=FULL")
        con.execute("BEGIN IMMEDIATE")
        if con.execute("SELECT version FROM meta").fetchall() != [(1,)]:
            raise ValueError("execution_gate_uninitialized")
        if con.execute("SELECT 1 FROM claims WHERE operation_id=?", (operation_id,)).fetchone():
            con.execute("ROLLBACK")
            return False
        con.execute("INSERT INTO claims VALUES (?,?)", (operation_id, request_sha256))
        con.execute("COMMIT")  # Linearization point before any provider effect.
        return True
    except BaseException:
        if con.in_transaction:
            con.execute("ROLLBACK")
        raise
    finally:
        con.close()
