"""Real separate-UID witness IPC, signed receipts and rollback/fork detection."""
import os,pathlib,pwd,shutil,sqlite3,subprocess,sys,tempfile,time
from test_cross_uid_boundary import drop,HERE

CLIENT=r'''
from signer_witness import RemoteSignerWitness
import sys
socket_path,pub,checkpoint=sys.argv[1:4]
w=RemoteSignerWitness(socket_path,pub,checkpoint)
for i in range(2):
    operation="remote-op-%d"%i
    request={"operation_id":operation,"action":"payment:simulate",
             "target":"fixture:merchant-a","amount_cents":100}
    w.consume(("x%047d"%i),operation,request)
print("REMOTE_WITNESS_OK: signed receipts verified and signer checkpoint advanced")
'''

ROLLBACK_CLIENT=r'''
from signer_witness import RemoteSignerWitness
import sys
socket_path,pub,checkpoint=sys.argv[1:4]
w=RemoteSignerWitness(socket_path,pub,checkpoint)
request={"operation_id":"after-rollback","action":"payment:simulate",
         "target":"fixture:merchant-a","amount_cents":100}
try:
    w.consume("z"*48,"after-rollback",request)
except PermissionError:
    print("WITNESS_ROLLBACK_DETECTED: signed but stale witness branch rejected")
else:
    raise AssertionError("signer accepted rolled-back witness history")
'''

UNTRUSTED=r'''
import socket,sys
try:
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(2); conn.connect(sys.argv[1])
except OSError:
    print("UNTRUSTED_UID_DENIED")
else:
    raise AssertionError("untrusted UID connected to witness socket")
'''

def start_service(sock,db,private_key,public_key,lib,witness,signer,env):
    proc=subprocess.Popen([sys.executable,str(lib/"signer_witness_service.py"),
        str(sock),str(db),str(signer.pw_uid),str(signer.pw_gid),str(private_key),str(public_key)],
        preexec_fn=drop(witness.pw_uid,witness.pw_gid,(signer.pw_gid,)),env=env,
        stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
    for _ in range(200):
        if sock.exists() and public_key.exists(): return proc
        if proc.poll() is not None: raise AssertionError("witness service exited: "+proc.stderr.read())
        time.sleep(.02)
    proc.terminate()
    raise AssertionError("witness socket/key startup timeout")

def stop_service(proc):
    proc.terminate()
    try: proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill(); proc.communicate(timeout=5)

def run_as(script,args,account,env):
    result=subprocess.run([sys.executable,"-c",script,*map(str,args)],
        preexec_fn=drop(account.pw_uid,account.pw_gid),env=env,capture_output=True,text=True,timeout=12)
    assert result.returncode==0,(result.stdout,result.stderr)
    return result.stdout.strip()

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
        os.chown(state,witness.pw_uid,witness.pw_gid); state.chmod(0o700)
        signer_state=root/"signer-state"; signer_state.mkdir(mode=0o700)
        os.chown(signer_state,signer.pw_uid,signer.pw_gid); signer_state.chmod(0o700)
        db=state/"witness.sqlite"; sock=ipc/"witness.sock"
        private_key=state/"witness_ed25519.pem"; public_key=state/"witness_ed25519.pub"
        checkpoint=signer_state/"accepted_witness.sqlite"; snapshot=root/"witness-before.sqlite"
        lib=root/"lib"; lib.mkdir(mode=0o755)
        for name in ("signer_witness.py","signer_witness_service.py","signed_receipt.py"):
            target=lib/name; shutil.copyfile(HERE/name,target); target.chmod(0o644)
        env=dict(os.environ,PYTHONPATH=str(lib))
        proc=start_service(sock,db,private_key,public_key,lib,witness,signer,env)
        try:
            # Snapshot the initialized but empty witness state before any append.
            shutil.copy2(db,snapshot)
            pub=public_key.read_text().strip()
            print(run_as(CLIENT,[sock,pub,checkpoint],signer,env))
        finally:
            stop_service(proc)
        # Simulate privileged restoration of witness DB while signer checkpoint and
        # witness signing key remain unchanged. The signer must reject the stale fork.
        shutil.copy2(snapshot,db)
        os.chown(db,witness.pw_uid,witness.pw_gid); db.chmod(0o600)
        proc=start_service(sock,db,private_key,public_key,lib,witness,signer,env)
        try:
            print(run_as(ROLLBACK_CLIENT,[sock,pub,checkpoint],signer,env))
            print(run_as(UNTRUSTED,[sock],client,env))
        finally:
            stop_service(proc)
        with sqlite3.connect(checkpoint) as conn:
            seq=conn.execute("SELECT sequence FROM witness_checkpoint WHERE singleton=1").fetchone()[0]
            assert seq==2

if __name__=="__main__": main()
