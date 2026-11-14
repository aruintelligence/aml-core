"""Linux broker deployment preflight: reject known-unsafe identity/storage layouts.

This is a configuration guard, not a sandbox. Kernel-enforced UID separation,
filesystem ownership, and actual access-denial tests remain necessary.
"""
import os
import pathlib
import stat

def validate_isolation(db_path,broker_uid,client_uids):
    if (type(broker_uid) is not int or broker_uid<0
        or type(client_uids) is not frozenset or not client_uids
        or any(type(uid) is not int or uid<0 for uid in client_uids)
        or broker_uid in client_uids or os.geteuid()!=broker_uid):
        raise ValueError("broker and clients must have distinct OS identities")
    path=pathlib.Path(db_path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("broker database must be an existing regular file")
    parent=path.parent
    if parent.is_symlink():
        raise ValueError("broker database directory must not be a symlink")
    file_info=path.stat()
    dir_info=parent.stat()
    if (not stat.S_ISREG(file_info.st_mode) or not stat.S_ISDIR(dir_info.st_mode)
        or file_info.st_uid!=broker_uid or dir_info.st_uid!=broker_uid
        or stat.S_IMODE(file_info.st_mode)&0o077
        or stat.S_IMODE(dir_info.st_mode)&0o077):
        raise ValueError("broker storage must be owner-only and broker-owned")
    # Do not accept a group/world-writable parent, even if DB is 0600.
    return True
