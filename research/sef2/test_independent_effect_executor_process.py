"""Five-service/UID independent effect execution and rollback experiment."""
import json,os,pathlib,pwd,shutil,sqlite3,subprocess,sys,tempfile,time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authenticated_execution_challenge import make_execution_challenge
from execution_gate_receipt import evaluate_and_issue
from pin_registry import PinRegistry
from pin_replication import PinReplica
from replica_attestation import attest
from session_capability import issue_session_capability,make_holder_proof
from test_cross_uid_boundary import drop,HERE

BROKER_CLIENT=r'''
import json,pathlib,sys
from independent_effect_executor_client import request_effect
sock,evidence_path=sys.argv[1:3]
e=json.loads(pathlib.Path(evidence_path).read_text())
print(request_effect(sock,e["request"],e["capability"],e["execution_challenge"],
 e["holder_proof"],e["evaluator_authorization"]))
'''

ATTACKER=r'''
import json,pathlib,sys
from independent_effect_executor_client import request_effect
sock,evidence_path=sys.argv[1:3]
e=json.loads(pathlib.Path(evidence_path).read_text())
try:
 status=request_effect(sock,e["request"],e["capability"],e["execution_challenge"],
  e["holder_proof"],e["evaluator_authorization"])
except PermissionError:
 print("UNTRUSTED_EFFECT_SUBMITTER_DENIED")
else:
 if status!="DENIED": raise AssertionError("untrusted UID reached effect executor")
 print("UNTRUSTED_EFFECT_SUBMITTER_DENIED")
'''

def start_epoch(user,executor,sock,db,lib,env):
 proc=subprocess.Popen([sys.executable,str(lib/"session_epoch_anchor_service.py"),
  str(sock),str(db),str(executor.pw_uid),str(executor.pw_gid)],
  preexec_fn=drop(user.pw_uid,user.pw_gid,(executor.pw_gid,)),env=env,
  stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
 return ready(proc,sock,"epoch anchor")

def start_witness(user,executor,sock,db,key,pub,lib,env):
 proc=subprocess.Popen([sys.executable,str(lib/"execution_consumption_witness_service.py"),
  str(sock),str(db),str(executor.pw_uid),str(executor.pw_gid),
  "effect-execution-witness",str(key),str(pub)],
  preexec_fn=drop(user.pw_uid,user.pw_gid,(executor.pw_gid,)),env=env,
  stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
 return ready(proc,sock,"execution witness",pub)

def start_receipt_anchor(user,executor,sock,db,witness_pub,lib,env):
 proc=subprocess.Popen([sys.executable,str(lib/"execution_receipt_anchor_service.py"),
  str(sock),str(db),str(executor.pw_uid),str(executor.pw_gid),
  "effect-execution-witness",pathlib.Path(witness_pub).read_text().strip()],
  preexec_fn=drop(user.pw_uid,user.pw_gid,(executor.pw_gid,)),env=env,
  stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
 return ready(proc,sock,"receipt anchor")

def start_executor(user,broker,sock,db,config,epoch_sock,witness_sock,witness_pub,anchor_sock,lib,env):
 c=json.loads(pathlib.Path(config).read_text())
 args=[str(sock),str(db),str(broker.pw_uid),str(broker.pw_gid),
  "authority",c["authority_public"],"broker-a","broker-instance-effect",c["broker_public"],
  "evaluator-effect",c["evaluator_public"],"north",str(epoch_sock),
  str(witness_sock),"effect-execution-witness",pathlib.Path(witness_pub).read_text().strip(),str(anchor_sock)]
 proc=subprocess.Popen([sys.executable,str(lib/"independent_effect_executor_service.py"),*args],
  preexec_fn=drop(user.pw_uid,user.pw_gid,(broker.pw_gid,)),env=env,
  stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
 return ready(proc,sock,"effect executor")

def ready(proc,sock,label,extra=None):
 for _ in range(250):
  if proc.poll() is not None: raise AssertionError(label+" died: "+proc.stderr.read())
  if sock.exists() and (extra is None or pathlib.Path(extra).exists()):
   time.sleep(.05); return proc
  time.sleep(.02)
 proc.terminate(); raise AssertionError(label+" startup timeout")

def stop(proc):
 proc.terminate()
 try: proc.communicate(timeout=5)
 except subprocess.TimeoutExpired:
  proc.kill(); proc.communicate(timeout=5)

def run(script,args,user,env,groups=()):
 r=subprocess.run([sys.executable,"-c",script,*map(str,args)],
  preexec_fn=drop(user.pw_uid,user.pw_gid,groups),env=env,capture_output=True,text=True,timeout=12)
 assert r.returncode==0,(r.stdout,r.stderr)
 return r.stdout.strip()

def main():
 if sys.platform!="linux" or os.geteuid()!=0: raise SystemExit("requires disposable Linux root CI")
 executor=pwd.getpwnam("aml_effect_executor_test")
 broker=pwd.getpwnam("aml_broker_test")
 attacker=pwd.getpwnam("aml_client_test")
 epoch_user=pwd.getpwnam("aml_epoch_anchor_test")
 witness_user=pwd.getpwnam("aml_execution_witness_test")
 receipt_user=pwd.getpwnam("aml_execution_anchor_test")
 assert len({a.pw_uid for a in (executor,broker,attacker,epoch_user,witness_user,receipt_user)})==6
 with tempfile.TemporaryDirectory(prefix="aml-independent-effect-process-") as tmp:
  root=pathlib.Path(tmp); root.chmod(0o755)
  def private(name,user):
   p=root/name; p.mkdir(mode=0o700); os.chown(p,user.pw_uid,user.pw_gid); return p
  estate=private("executor",executor); epstate=private("epoch",epoch_user)
  wstate=private("witness",witness_user); astate=private("anchor",receipt_user)
  def ipc(name,user):
   p=root/name; p.mkdir(mode=0o711); os.chown(p,user.pw_uid,user.pw_gid); return p
  eipc=ipc("eipc",executor); epipc=ipc("epipc",epoch_user)
  wipc=ipc("wipc",witness_user); aip=ipc("aipc",receipt_user)
  shared=root/"shared"; shared.mkdir(mode=0o755)
  lib=root/"lib"; lib.mkdir(mode=0o755)
  names=("independent_effect_executor","independent_effect_executor_service",
   "independent_effect_executor_client","session_epoch_anchor","session_epoch_anchor_service",
   "execution_consumption_witness","authorized_execution_consumption",
   "execution_consumption_witness_service","execution_receipt_anchor",
   "execution_receipt_anchor_service","execution_gate_receipt",
   "authenticated_execution_challenge","session_capability","gated_action_broker",
   "strict_evaluator","pin_registry","pin_replication","replica_attestation","signed_receipt")
  for name in names:
   src=HERE/(name+".py"); dst=lib/(name+".py"); shutil.copyfile(src,dst); dst.chmod(0o644)
  env=dict(os.environ,PYTHONPATH=str(lib))
  # Build public authorization evidence.
  authority=Ed25519PrivateKey.generate(); broker_key=Ed25519PrivateKey.generate()
  holder=Ed25519PrivateKey.generate(); evaluator=Ed25519PrivateKey.generate()
  registry=PinRegistry(shared/"registry.sqlite"); registry.enroll("north","a"*64)
  replicas=[PinReplica(shared/f"r{i}.sqlite") for i in range(3)]
  replica_keys=[Ed25519PrivateKey.generate() for _ in range(3)]
  enrolled={f"r{i}":k.public_key().public_bytes_raw().hex() for i,k in enumerate(replica_keys)}
  for r in replicas: r.record("north",0,"a"*64)
  request={"operation_id":"separate-effect-op","action":"payment:simulate",
   "target":"fixture:merchant-a","amount_cents":100}
  cap=issue_session_capability(authority,"authority","broker-a",request,0,
   holder.public_key().public_bytes_raw().hex())
  challenge=make_execution_challenge(broker_key,"broker-instance-effect","broker-a",
   request,cap,0,"c"*64)
  proof=make_holder_proof(holder,cap,request,"c"*64)
  attestations=[attest(r,f"r{i}","north",replica_keys[i]) for i,r in enumerate(replicas)]
  eval_auth=evaluate_and_issue(registry,"north",replicas,2,attestations,enrolled,
   evaluator,"evaluator-effect","broker-a",request,cap,challenge,0)
  config={"authority_public":authority.public_key().public_bytes_raw().hex(),
   "broker_public":broker_key.public_key().public_bytes_raw().hex(),
   "evaluator_public":evaluator.public_key().public_bytes_raw().hex()}
  config_path=shared/"config.json"; config_path.write_text(json.dumps(config)); config_path.chmod(0o644)
  evidence={"request":request,"capability":cap,"execution_challenge":challenge,
   "holder_proof":proof,"evaluator_authorization":eval_auth}
  evidence_path=shared/"evidence.json"; evidence_path.write_text(json.dumps(evidence)); evidence_path.chmod(0o644)
  # Start independently owned monotonic services.
  epoch_sock=epipc/"epoch.sock"; epoch_db=epstate/"epoch.sqlite"
  ep=start_epoch(epoch_user,executor,epoch_sock,epoch_db,lib,env)
  init=r'''from session_epoch_anchor import RemoteSessionEpochAnchor
import sys
assert RemoteSessionEpochAnchor(sys.argv[1]).initialize("broker-a",0)==0
'''
  run(init,[epoch_sock],executor,env)
  witness_sock=wipc/"witness.sock"; witness_db=wstate/"witness.sqlite"
  witness_key=wstate/"witness.pem"; witness_pub=shared/"witness.pub"
  wp=start_witness(witness_user,executor,witness_sock,witness_db,witness_key,witness_pub,lib,env)
  anchor_sock=aip/"anchor.sock"; anchor_db=astate/"anchor.sqlite"
  ap=start_receipt_anchor(receipt_user,executor,anchor_sock,anchor_db,witness_pub,lib,env)
  effect_sock=eipc/"effect.sock"; effect_db=estate/"effect.sqlite"
  xp=start_executor(executor,broker,effect_sock,effect_db,config_path,epoch_sock,
   witness_sock,witness_pub,anchor_sock,lib,env)
  try:
   snapshot=shared/"effect-before.sqlite"; shutil.copy2(effect_db,snapshot)
   first=run(BROKER_CLIENT,[effect_sock,evidence_path],broker,env)
   assert first=="APPLIED",first
   with sqlite3.connect(witness_db) as db:
    assert db.execute("SELECT COUNT(*) FROM authorized_execution_consumption").fetchone()[0]==1
    assert db.execute("SELECT COUNT(*) FROM execution_consumption").fetchone()[0]==0
   with sqlite3.connect(anchor_db) as db:
    seq=db.execute("""SELECT sequence FROM authorized_execution_receipt_anchor
     WHERE witness_id='effect-execution-witness'""").fetchone()[0]
    assert seq==1
    legacy=db.execute("""SELECT sequence FROM execution_receipt_anchor
     WHERE witness_id='effect-execution-witness'""").fetchone()[0]
    assert legacy==0
   print("FULL_AUTHORIZATION_V3_CONSUMPTION_ANCHORED")
   second=run(BROKER_CLIENT,[effect_sock,evidence_path],broker,env)
   assert second=="ALREADY_APPLIED",second
   denied=run(ATTACKER,[effect_sock,evidence_path],attacker,env,(broker.pw_gid,))
   assert "UNTRUSTED_EFFECT_SUBMITTER_DENIED" in denied
   stop(xp)
   # Restore only effect DB; witness + receipt anchor survive.
   shutil.copy2(snapshot,effect_db); os.chown(effect_db,executor.pw_uid,executor.pw_gid)
   xp=start_executor(executor,broker,effect_sock,effect_db,config_path,epoch_sock,
    witness_sock,witness_pub,anchor_sock,lib,env)
   replay=run(BROKER_CLIENT,[effect_sock,evidence_path],broker,env)
   assert replay=="DENIED",replay
   reader=r'''import pathlib,sys
for value in sys.argv[1:]:
 try: pathlib.Path(value).read_bytes()
 except PermissionError: continue
 raise AssertionError("broker read protected effect state: "+value)
print("PROTECTED_EFFECT_STATE_PRIVATE")
'''
   check=run(reader,[effect_db,witness_db,anchor_db,epoch_db],broker,env)
   assert "PROTECTED_EFFECT_STATE_PRIVATE" in check
   print("INDEPENDENT_EFFECT_APPLIED_ONCE"); print("EFFECT_EXECUTOR_ROLLBACK_REPLAY_DENIED"); print(check)
  finally:
   for proc in (xp,ap,wp,ep):
    if proc.poll() is None: stop(proc)
if __name__=="__main__": main()
