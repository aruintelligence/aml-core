"""Real separate-UID session epoch anchor process integration."""
import os,pathlib,pwd,shutil,subprocess,sys,tempfile,time
from session_epoch_anchor import RemoteSessionEpochAnchor
from test_cross_uid_boundary import drop,HERE

ATTACK=r'''
from session_epoch_anchor import RemoteSessionEpochAnchor
import sys
try:
 RemoteSessionEpochAnchor(sys.argv[1]).read_epoch("broker-a")
except (PermissionError,OSError):
 print("UNTRUSTED_EPOCH_ANCHOR_DENIED")
else:
 raise AssertionError("untrusted UID read session epoch anchor")
'''

def main():
    if sys.platform!="linux" or os.geteuid()!=0: raise SystemExit("requires disposable Linux root CI")
    anchor_user=pwd.getpwnam("aml_epoch_anchor_test")
    broker=pwd.getpwnam("aml_broker_test")
    attacker=pwd.getpwnam("aml_client_test")
    assert len({anchor_user.pw_uid,broker.pw_uid,attacker.pw_uid})==3
    with tempfile.TemporaryDirectory(prefix="aml-session-epoch-anchor-") as tmp:
        root=pathlib.Path(tmp); root.chmod(0o755)
        private=root/"private"; private.mkdir(mode=0o700); os.chown(private,anchor_user.pw_uid,anchor_user.pw_gid)
        ipc=root/"ipc"; ipc.mkdir(mode=0o711); os.chown(ipc,anchor_user.pw_uid,anchor_user.pw_gid)
        lib=root/"lib"; lib.mkdir(mode=0o755)
        for name in ("session_epoch_anchor.py","session_epoch_anchor_service.py",
                     "session_capability_broker.py","session_capability.py","gated_action_broker.py",
                     "strict_evaluator.py","pin_replication.py","replica_attestation.py",
                     "pin_registry.py","signed_receipt.py","authenticated_execution_challenge.py"):
            target=lib/name; shutil.copyfile(HERE/name,target); target.chmod(0o644)
        sock=ipc/"epoch.sock"; db=private/"epoch.sqlite"
        env=dict(os.environ,PYTHONPATH=str(lib))
        proc=subprocess.Popen([sys.executable,str(lib/"session_epoch_anchor_service.py"),str(sock),str(db),
            str(broker.pw_uid),str(broker.pw_gid)],
            preexec_fn=drop(anchor_user.pw_uid,anchor_user.pw_gid,(broker.pw_gid,)),env=env,
            stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
        try:
            for _ in range(200):
                if proc.poll() is not None: raise AssertionError("epoch anchor exited: "+proc.stderr.read())
                if sock.exists(): time.sleep(.05); break
                time.sleep(.02)
            else: raise AssertionError("epoch anchor startup timeout")
            broker_state=root/"broker-state"; broker_state.mkdir(mode=0o700); os.chown(broker_state,broker.pw_uid,broker.pw_gid)
            broker_db=broker_state/"broker.sqlite"
            code=r'''
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from session_epoch_anchor import RemoteSessionEpochAnchor
from session_capability_broker import SessionCapabilityBroker
import sys
sock,db=sys.argv[1:3]
anchor=RemoteSessionEpochAnchor(sock)
issuer=Ed25519PrivateKey.generate()
broker=SessionCapabilityBroker(db,None,"north",[],0,{},"authority",
    issuer.public_key().public_bytes_raw().hex(),"broker-a",epoch_anchor=anchor)
assert broker.current_epoch()==0
assert broker.revoke_all()==1
assert anchor.read_epoch("broker-a")==1
restarted=SessionCapabilityBroker(db,None,"north",[],0,{},"authority",
    issuer.public_key().public_bytes_raw().hex(),"broker-a",epoch_anchor=anchor)
assert restarted.current_epoch()==1
print("REMOTE_SESSION_EPOCH_BROKER_OK")
'''
            result=subprocess.run([sys.executable,"-c",code,str(sock),str(broker_db)],preexec_fn=drop(broker.pw_uid,broker.pw_gid),
                env=env,capture_output=True,text=True,timeout=10)
            assert result.returncode==0,(result.stdout,result.stderr)
            assert "REMOTE_SESSION_EPOCH_BROKER_OK" in result.stdout
            denied=subprocess.run([sys.executable,"-c",ATTACK,str(sock)],preexec_fn=drop(attacker.pw_uid,attacker.pw_gid),
                env=env,capture_output=True,text=True,timeout=10)
            assert denied.returncode==0,(denied.stdout,denied.stderr)
            assert "UNTRUSTED_EPOCH_ANCHOR_DENIED" in denied.stdout
            reader=r'''
import pathlib,sys
try: pathlib.Path(sys.argv[1]).read_bytes()
except PermissionError: print("EPOCH_DB_PRIVATE")
else: raise AssertionError("non-anchor UID read epoch DB")
'''
            for account in (broker,attacker):
                check=subprocess.run([sys.executable,"-c",reader,str(db)],preexec_fn=drop(account.pw_uid,account.pw_gid),
                    env=env,capture_output=True,text=True,timeout=10)
                assert check.returncode==0,(check.stdout,check.stderr)
        finally:
            proc.terminate()
            try: proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.communicate(timeout=5)
        print("SESSION_EPOCH_ANCHOR_UID_OK")
if __name__=="__main__": main()
