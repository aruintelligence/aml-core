"""Disposable Linux cross-UID reservation isolation probe. Run only as root in CI."""
import os
import pathlib
import pwd
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent

def drop(user):
    def apply():
        os.setgroups([])
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)
    return apply

SERVER = r'''
import os,sys
from independent_effect_reservations import IndependentEffectReservations
from reservation_socket import ReservationServer
path,db,uid=sys.argv[1:]
store=IndependentEffectReservations(db,"authority-a")
with ReservationServer(path,allowed_uid=int(uid),store=store) as server:
    os.chmod(path,0o666)
    server.serve_forever(poll_interval=0.05)
'''
CLIENT = r'''
import os,sqlite3,sys
from reservation_socket import reserve_via_socket
path,db=sys.argv[1:]
assert reserve_via_socket(path,"op-1","a"*64,0) is True
assert reserve_via_socket(path,"op-1","a"*64,0) is False
try:
    open(db,"rb").read(1)
except PermissionError:
    pass
else:
    raise AssertionError("effect owner read reservation store")
try:
    sqlite3.connect("file:"+db+"?mode=rw",uri=True).execute("CREATE TABLE bypass(x)")
except sqlite3.OperationalError:
    pass
else:
    raise AssertionError("effect owner wrote reservation store")
print("RESERVATION_UID_BOUNDARY_OK")
'''

def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise SystemExit("requires disposable Linux root CI")
    owner = pwd.getpwnam("aml_witness_test")
    caller = pwd.getpwnam("aml_broker_test")
    assert owner.pw_uid != caller.pw_uid and owner.pw_uid != 0 and caller.pw_uid != 0
    with tempfile.TemporaryDirectory(prefix="aml-reserve-uid-") as tmp:
        root = pathlib.Path(tmp)
        root.chmod(0o755)
        private = root / "private"
        private.mkdir(mode=0o700)
        os.chown(private, owner.pw_uid, owner.pw_gid)
        ipc = root / "ipc"
        ipc.mkdir(mode=0o777)
        ipc.chmod(0o777)
        lib = root / "lib"
        lib.mkdir(mode=0o755)
        for name in ("independent_effect_reservations.py", "reservation_socket.py"):
            dst = lib / name
            shutil.copyfile(HERE / name, dst)
            dst.chmod(0o644)
        db = private / "reservations.sqlite"
        sock = ipc / "reserve.sock"
        env = dict(os.environ, PYTHONPATH=str(lib), PYTHONDONTWRITEBYTECODE="1")
        proc = subprocess.Popen([sys.executable, "-c", SERVER, str(sock), str(db),
                                 str(caller.pw_uid)], preexec_fn=drop(owner), env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            for _ in range(150):
                if sock.exists() and (sock.stat().st_mode & 0o777) == 0o666:
                    break
                if proc.poll() is not None:
                    raise AssertionError("reservation server died: " + proc.stderr.read())
                time.sleep(0.02)
            assert sock.exists() and (sock.stat().st_mode & 0o777) == 0o666, "reservation server not ready"
            outcome = subprocess.run([sys.executable, "-c", CLIENT, str(sock), str(db)],
                                     preexec_fn=drop(caller), env=env,
                                     capture_output=True, text=True, timeout=10)
            assert outcome.returncode == 0, (outcome.stdout, outcome.stderr)
            print(outcome.stdout.strip())
        finally:
            proc.terminate()
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate(timeout=5)

if __name__ == "__main__":
    main()
