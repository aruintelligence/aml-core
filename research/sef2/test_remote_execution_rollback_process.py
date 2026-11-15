"""Rollback replay test with broker and execution witness under separate UIDs."""
import json,os,pathlib,pwd,shutil,subprocess,sys,tempfile,time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from session_capability import issue_session_capability,make_holder_proof
from replica_attestation import attest
from test_cross_uid_boundary import drop,HERE

PREPARE=r'''
import json,pathlib,sys
from execution_consumption_witness import SignedRemoteExecutionConsumptionWitness
from pin_registry import PinRegistry
from pin_replication import PinReplica
from session_capability_broker import SessionCapabilityBroker
state,config_path,sock,witness_pub,challenge_path=sys.argv[1:6]
root=pathlib.Path(state); config=json.loads(pathlib.Path(config_path).read_text())
registry=PinRegistry(root/"registry.sqlite"); registry.enroll("north","a"*64)
replicas=[PinReplica(root/f"r{i}.sqlite") for i in range(3)]
for replica in replicas: replica.record("north",0,"a"*64)
witness=SignedRemoteExecutionConsumptionWitness(sock,"execution-witness-rollback",
 pathlib.Path(witness_pub).read_text().strip())
broker=SessionCapabilityBroker(root/"broker.sqlite",registry,"north",replicas,2,
 config["enrolled"],"authority",config["issuer_public"],"broker-a",execution_witness=witness)
challenge=broker.issue_execution_challenge(config["request"]["operation_id"])
pathlib.Path(challenge_path).write_text(challenge)
'''

EXECUTE=r'''
import json,pathlib,sys
from execution_consumption_witness import SignedRemoteExecutionConsumptionWitness
from pin_registry import PinRegistry
from pin_replication import PinReplica
from session_capability_broker import SessionCapabilityBroker
state,config_path,sock,witness_pub,challenge_path,proof_path=sys.argv[1:7]
root=pathlib.Path(state); config=json.loads(pathlib.Path(config_path).read_text())
registry=PinRegistry(root/"registry.sqlite")
replicas=[PinReplica(root/f"r{i}.sqlite") for i in range(3)]
witness=SignedRemoteExecutionConsumptionWitness(sock,"execution-witness-rollback",
 pathlib.Path(witness_pub).read_text().strip())
broker=SessionCapabilityBroker(root/"broker.sqlite",registry,"north",replicas,2,
 config["enrolled"],"authority",config["issuer_public"],"broker-a",execution_witness=witness)
challenge=pathlib.Path(challenge_path).read_text()
proof=json.loads(pathlib.Path(proof_path).read_text())
status=broker.execute(config["request"],config["attestations"],config["capability"],proof,challenge)
print(status)
'''

def start_witness(witness,broker,sock,db,key,pub,lib,env):
 proc=subprocess.Popen([sys.executable,str(lib/"execution_consumption_witness_service.py"),
  str(sock),str(db),str(broker.pw_uid),str(broker.pw_gid),"execution-witness-rollback",str(key),str(pub)],
  preexec_fn=drop(witness.pw_uid,witness.pw_gid,(broker.pw_gid,)),env=env,
  stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
 for _ in range(200):
  if proc.poll() is not None: raise AssertionError("witness died: "+proc.stderr.read())
  if sock.exists() and pub.exists(): time.sleep(.05); return proc
  time.sleep(.02)
 proc.terminate(); raise AssertionError("witness startup timeout")

def run_broker(script,args,broker,env):
 result=subprocess.run([sys.executable,"-c",script,*map(str,args)],
  preexec_fn=drop(broker.pw_uid,broker.pw_gid),env=env,capture_output=True,text=True,timeout=12)
 assert result.returncode==0,(result.stdout,result.stderr)
 return result.stdout.strip()

def main():
 if sys.platform!="linux" or os.geteuid()!=0: raise SystemExit("requires disposable Linux root CI")
 witness=pwd.getpwnam("aml_execution_witness_test"); broker=pwd.getpwnam("aml_broker_test")
 assert witness.pw_uid!=broker.pw_uid and witness.pw_uid!=0 and broker.pw_uid!=0
 with tempfile.TemporaryDirectory(prefix="aml-remote-exec-rollback-") as tmp:
  root=pathlib.Path(tmp); root.chmod(0o755)
  wstate=root/"witness"; wstate.mkdir(mode=0o700); os.chown(wstate,witness.pw_uid,witness.pw_gid)
  bstate=root/"broker"; bstate.mkdir(mode=0o700); os.chown(bstate,broker.pw_uid,broker.pw_gid)
  ipc=root/"ipc"; ipc.mkdir(mode=0o711); os.chown(ipc,witness.pw_uid,witness.pw_gid)
  shared=root/"shared"; shared.mkdir(mode=0o755)
  lib=root/"lib"; lib.mkdir(mode=0o755)
  names=("execution_consumption_witness","execution_consumption_witness_service","session_capability",
   "session_capability_broker","gated_action_broker","strict_evaluator","pin_registry",
   "pin_replication","replica_attestation","signed_receipt")
  for name in names:
   src=HERE/(name+".py"); dst=lib/(name+".py"); shutil.copyfile(src,dst); dst.chmod(0o644)
  env=dict(os.environ,PYTHONPATH=str(lib))
  issuer=Ed25519PrivateKey.generate(); holder=Ed25519PrivateKey.generate()
  replica_keys=[Ed25519PrivateKey.generate() for _ in range(3)]
  request={"operation_id":"remote-rollback-op","action":"payment:simulate",
   "target":"fixture:merchant-a","amount_cents":100}
  cap=issue_session_capability(issuer,"authority","broker-a",request,0,
   holder.public_key().public_bytes_raw().hex())
  # Attestations match the durable replica fixture initialized by PREPARE.
  class ReplicaView:
   def __init__(self,i): self.i=i
   def read(self,witness_id): return (0,"a"*64)
  attestations=[attest(ReplicaView(i),f"r{i}","north",replica_keys[i]) for i in range(3)]
  config={"issuer_public":issuer.public_key().public_bytes_raw().hex(),
   "enrolled":{f"r{i}":k.public_key().public_bytes_raw().hex() for i,k in enumerate(replica_keys)},
   "request":request,"capability":cap,"attestations":attestations}
  config_path=shared/"config.json"; config_path.write_text(json.dumps(config)); config_path.chmod(0o644)
  challenge_path=shared/"challenge.txt"; proof_path=shared/"proof.json"
  sock=ipc/"execution.sock"; db=wstate/"execution.sqlite"; key=wstate/"execution.pem"; pub=shared/"execution.pub"
  proc=start_witness(witness,broker,sock,db,key,pub,lib,env)
  try:
   run_broker(PREPARE,[bstate,config_path,sock,pub,challenge_path],broker,env)
   snapshot=shared/"broker-before-effect.sqlite"; shutil.copy2(bstate/"broker.sqlite",snapshot)
   challenge=challenge_path.read_text()
   proof=make_holder_proof(holder,cap,request,challenge)
   proof_path.write_text(json.dumps(proof)); proof_path.chmod(0o644)
   first=run_broker(EXECUTE,[bstate,config_path,sock,pub,challenge_path,proof_path],broker,env)
   assert first=="APPLIED",first
   # Restore only the broker DB. Independent witness state remains at the consumed operation.
   shutil.copy2(snapshot,bstate/"broker.sqlite"); os.chown(bstate/"broker.sqlite",broker.pw_uid,broker.pw_gid)
   second=run_broker(EXECUTE,[bstate,config_path,sock,pub,challenge_path,proof_path],broker,env)
   assert second=="DENIED",second
   print("REMOTE_EXECUTION_ROLLBACK_DENIED: independent witness survived broker DB rollback")
  finally:
   proc.terminate()
   try: proc.communicate(timeout=5)
   except subprocess.TimeoutExpired:
    proc.kill(); proc.communicate(timeout=5)
if __name__=="__main__": main()
