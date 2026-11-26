"""Encode a trusted ordinary filesystem path without SQLite URI reinterpretation."""
from pathlib import Path


def sqlite_file_uri(database, mode):
    # The operator supplies a filename, not a URI/query. Quote #, ?, %, spaces
    # and Unicode before appending our fixed mode; never fall back to creation.
    if mode not in ("ro", "rw"):
        raise ValueError("unsupported_sqlite_open_mode")
    return Path(database).resolve().as_uri() + "?mode=" + mode
