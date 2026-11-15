"""Read-only recovery classifier for the SEF2 synthetic effect fixture.

No classifier result authorizes execution or releases a reservation. The
independent reservation ledger is authoritative for replay prevention.
"""
import sqlite3
from pathlib import Path

def classify_recovery(effect_db_path, reservation_store, operation_id):
    """Return COMMITTED, STRANDED, ABSENT, CONFLICT, or UNKNOWN.

    UNKNOWN is the safe result when either evidence source cannot be read.
    ABSENT is informational only; it is NOT authorization to execute.
    """
    try:
        if (type(operation_id) is not str or not 1 <= len(operation_id) <= 128
            or not operation_id.isascii() or not operation_id.isprintable()):
            return "UNKNOWN"
        reserved = reservation_store.inspect(operation_id)
        uri = Path(effect_db_path).absolute().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=5) as db:
            rows = db.execute(
                "SELECT digest,generation FROM effects WHERE operation_id=?",
                (operation_id,)).fetchall()
        if len(rows) > 1:
            return "CONFLICT"
        if not rows:
            return "STRANDED" if reserved is not None else "ABSENT"
        if reserved is None:
            return "CONFLICT"
        digest, generation = rows[0]
        if digest != reserved["digest"] or generation != reserved["generation"]:
            return "CONFLICT"
        return "COMMITTED"
    except (sqlite3.Error, ValueError, TypeError, KeyError, OSError):
        return "UNKNOWN"
