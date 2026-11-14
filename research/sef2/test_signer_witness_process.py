"""Real separate-UID signer-to-witness IPC and rollback experiment; disposable Linux root CI only."""
import os,pathlib,pwd,shutil,socket,sqlite3,subprocess,sys,tempfile,time
from test_cross_uid_boundary import drop,HERE

CLIENT=r'''
from signer_witness import RemoteSignerWitness
import sys
socket_path=sys.argv[1]
request={"operation_id":"remote-op","action":"payment:simulate",
         "target":"fixture:merchant-a","amount_cents":100}
w=RemoteSignerWitness(socket_path)
w.consume("x"*48,"remote-op",request)
try:
    w.consume("x"*48,"remote-op",request)
except PermissionError:
    pass
else:
    raise AssertionError("remote witness accepted replay")
try:
    w.consume("y"*48,"remote-op",request)
except PermissionError:
    pass
else:
    raise AssertionError("remote witness accepted second nonce for operation")
print("REMOTE_WITNESS_OK: distinct UID service consumed once and denied nonce/operation replay")
'''

UNTRUSTED=r'''
from signer_witness import RemoteSignerWitness
import sys
try:
    RemoteSignerWitness(sys.argv[1]).consume("z"*48,"unauthorized-op",
      {"operation_id":"unauthorized-op","action":"payment:simulate",
       "target":"fixture:merchant-a","amount_cents":100})
except (PermissionError,OSError):
    print("UNTRUSTED_UID_DENIED")
else:
    raise AssertionError("untrusted UID reached witness")
'''

def main():
    if sys.platform!="linux" or os.geteuid()!=0:
        raise SystemExit("requires disposable Linux root CI")
    witness=pwd.getpwnam("aml_witness_test")
    signer=pwd.getpwnam("aml_signer_test")
    client=pwd.getpwnam("aml_client_test")
    assert len({witness.pw_uid,signer.pw_uid,client.pw_uid})==3
    with tempfile.TemporaryDirectory(prefix="aml-independent-witness-") as tmp:
        root=pathlib.Path(tmp); root.chmod(0o755)
        ipc=root/"ipc"; ipc.mkdir(mode=0o711)
        os.chown(ipc,witness.pw_uid,witness.pw_gid); ipc.chmod(0o711)
        state=root/"state"; state.mkdir(mode=0o700)
        os.chown(state,witness.pw_uid,witness.pw_gid)
        db=state/"witness.sqlite"; sock=ipc/"witness.sock"
        lib=root/"lib"; lib.mkdir(mode=0o755)
        for name in ("signer_witness.py","signer_witness_service.py","gated_action_broker.py",
                     "signed_receipt.py"):
            target=lib/name; shutil.copyfile(HERE/name,target); target.chmod(0o644)
        env=dict(os.environ,PYTHONPATH=str(lib))
        proc=subprocess.Popen([sys.executable,str(lib/"signer_witness_service.py"),
            str(sock),str(db),str(signer.pw_uid),str(signer.pw_gid)],
            preexec_fn=drop(witness.pw_uid,witness.pw_gid),env=env,
            stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
        try:
            for _ in range(200):
                if sock.exists(): break
                if proc.poll() is not None: raise AssertionError("witness service exited: "+proc.stderr.read())
                time.sleep(.02)
            assert sock.exists(),"witness socket startup timeout"
            result=subprocess.run([sys.executable,"-c",CLIENT,str(sock)],
                preexec_fn=drop(signer.pw_uid,signer.pw_gid),env=env,capture_output=True,text=True,timeout=10)
            assert result.returncode==0,(result.stdout,result.stderr)
            print(result.stdout.strip())
            denied=subprocess.run([sys.executable,"-c",UNTRUSTED,str(sock)],
                preexec_fn=drop(client.pw_uid,client.pw_gid),env=env,capture_output=True,text=True,timeout=10)
            assert denied.returncode==0,(denied.stdout,denied.stderr)
            print(denied.stdout.strip())
            with sqlite3.connect(db) as conn:
                assert conn.execute("SELECT COUNT(*) FROM consumed_intents").fetchone()[0]==1
        finally:
            proc.terminate()
            try: proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.communicate(timeout=5)

if __name__=="__main__": main()
