"""Real separate-UID holder proof service integration; disposable Linux root CI."""
import json,os,pathlib,pwd,shutil,socket,subprocess,sys,tempfile,time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from session_capability import issue_session_capability,verify_holder_proof
from authenticated_execution_challenge import make_execution_challenge
from test_cross_uid_boundary import drop,HERE

RUNTIME=r'''
import json,sys
from holder_proof_client import HolderProofClient
socket_path,cap_path,request_path,envelope_path=sys.argv[1:5]
cap=json.load(open(cap_path)); request=json.load(open(request_path)); envelope=json.load(open(envelope_path))
client=HolderProofClient(socket_path)
client.register(cap,request)
proof=client.prove_authenticated(cap,request,envelope)
print(json.dumps(proof,separators=(",",":")))
'''

ATTACKER=r'''
import json,sys
from holder_proof_client import HolderProofClient
socket_path,cap_path,request_path=sys.argv[1:4]
cap=json.load(open(cap_path)); request=json.load(open(request_path))
try:
 HolderProofClient(socket_path).prove(cap,request,"a"*64)
except (PermissionError,OSError):
 print("UNTRUSTED_HOLDER_PROOF_DENIED")
else:
 raise AssertionError("untrusted model UID obtained holder proof")
'''

def start(sock,state,key_path,pub_path,lib,holder,runtime,env,broker_id,broker_pub,audience,issuer_pub,issuer):
    proc=subprocess.Popen([sys.executable,str(lib/"holder_proof_service.py"),
        str(sock),str(state),str(key_path),str(pub_path),str(runtime.pw_uid),str(runtime.pw_gid),
        broker_id,broker_pub,audience,issuer_pub,issuer],
        preexec_fn=drop(holder.pw_uid,holder.pw_gid,(runtime.pw_gid,)),env=env,
        stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
    for _ in range(200):
        if proc.poll() is not None: raise AssertionError("holder service exited: "+proc.stderr.read())
        if sock.exists() and pub_path.exists():
            time.sleep(.05); return proc
        time.sleep(.02)
    proc.terminate(); raise AssertionError("holder proof service startup timeout")

def stop(proc):
    proc.terminate()
    try: proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill(); proc.communicate(timeout=5)

def main():
    if sys.platform!="linux" or os.geteuid()!=0:
        raise SystemExit("requires disposable Linux root CI")
    holder=pwd.getpwnam("aml_holder_test")
    runtime=pwd.getpwnam("aml_signer_test")
    attacker=pwd.getpwnam("aml_client_test")
    assert len({holder.pw_uid,runtime.pw_uid,attacker.pw_uid})==3
    with tempfile.TemporaryDirectory(prefix="aml-holder-proof-") as tmp:
        root=pathlib.Path(tmp); root.chmod(0o755)
        private=root/"holder-private"; private.mkdir(mode=0o700); os.chown(private,holder.pw_uid,holder.pw_gid)
        ipc=root/"ipc"; ipc.mkdir(mode=0o711); os.chown(ipc,holder.pw_uid,holder.pw_gid)
        lib=root/"lib"; lib.mkdir(mode=0o755)
        for name in ("holder_proof_service.py","holder_proof_client.py","session_capability.py",
                     "signed_receipt.py","gated_action_broker.py","authenticated_execution_challenge.py",
                     "strict_evaluator.py","pin_replication.py","replica_attestation.py","pin_registry.py"):
            target=lib/name; shutil.copyfile(HERE/name,target); target.chmod(0o644)
        sock=ipc/"holder.sock"; state=private/"holder.sqlite"
        key_path=private/"holder_ed25519.pem"; pub_path=ipc/"holder.pub"
        env=dict(os.environ,PYTHONPATH=str(lib))
        broker_key=Ed25519PrivateKey.generate(); broker_id="broker-instance-uid"; audience="broker-a"
        authority=Ed25519PrivateKey.generate(); issuer="authority"
        proc=start(sock,state,key_path,pub_path,lib,holder,runtime,env,broker_id,
            broker_key.public_key().public_bytes_raw().hex(),audience,
            authority.public_key().public_bytes_raw().hex(),issuer)
        try:
            holder_pub=pub_path.read_text().strip()
            request={"operation_id":"isolated-session","action":"payment:simulate",
                     "target":"fixture:merchant-a","amount_cents":100}
            cap=issue_session_capability(authority,"authority","broker-a",request,0,holder_pub)
            cap_path=root/"cap.json"; request_path=root/"request.json"
            cap_path.write_text(json.dumps(cap)); request_path.write_text(json.dumps(request))
            cap_path.chmod(0o644); request_path.chmod(0o644)
            challenge="c"*64
            envelope=make_execution_challenge(broker_key,broker_id,audience,request,cap,0,challenge)
            envelope_path=root/"challenge.json"; envelope_path.write_text(json.dumps(envelope)); envelope_path.chmod(0o644)
            result=subprocess.run([sys.executable,"-c",RUNTIME,str(sock),str(cap_path),str(request_path),str(envelope_path)],
                preexec_fn=drop(runtime.pw_uid,runtime.pw_gid),env=env,capture_output=True,text=True,timeout=10)
            assert result.returncode==0,(result.stdout,result.stderr)
            proof=json.loads(result.stdout.strip())
            assert verify_holder_proof(proof,cap,request,challenge)
            attack=subprocess.run([sys.executable,"-c",ATTACKER,str(sock),str(cap_path),str(request_path)],
                preexec_fn=drop(attacker.pw_uid,attacker.pw_gid),env=env,capture_output=True,text=True,timeout=10)
            assert attack.returncode==0,(attack.stdout,attack.stderr)
            assert "UNTRUSTED_HOLDER_PROOF_DENIED" in attack.stdout
            reader=r'''
import pathlib,sys
for value in sys.argv[1:]:
    try: pathlib.Path(value).read_bytes()
    except PermissionError: continue
    raise AssertionError("non-holder UID read holder-owned private state")
print("HOLDER_PRIVATE_STATE_DENIED")
'''
            for account in (runtime,attacker):
                denied=subprocess.run([sys.executable,"-c",reader,str(key_path),str(state)],
                    preexec_fn=drop(account.pw_uid,account.pw_gid),env=env,
                    capture_output=True,text=True,timeout=10)
                assert denied.returncode==0,(denied.stdout,denied.stderr)
                assert "HOLDER_PRIVATE_STATE_DENIED" in denied.stdout
        finally:
            stop(proc)
        print("HOLDER_PROOF_UID_OK: holder key stayed in separate UID service; untrusted model UID denied")

if __name__=="__main__": main()
