"""Durable dual-consent recovery-policy succession registry.

The local SQLite transaction serializes rotations and atomically commits the
active policy plus its signed, hash-chained succession event. The database is
rollbackable as a whole; an independently retained external checkpoint is
required for anti-rollback.
"""
import json,sqlite3,hashlib
from signed_receipt import canonical
from threshold_recovery import policy_digest,validate_policy
from recovery_policy_rotation import verify_policy_rotation

EVENT_DOMAIN=b"AML-SEF2-RECOVERY-POLICY-EVENT-V2\x00"

class RecoveryPolicyRegistry:
 def __init__(self,path):
  self.path=str(path)
  with sqlite3.connect(self.path,timeout=10) as con:
   con.execute("PRAGMA journal_mode=DELETE")
   con.execute("PRAGMA synchronous=FULL")
   con.execute("""CREATE TABLE IF NOT EXISTS recovery_policy_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation INTEGER NOT NULL,
    policy_sha256 TEXT NOT NULL,policy_json TEXT NOT NULL)""")
   con.execute("""CREATE TABLE IF NOT EXISTS recovery_policy_events (
    generation INTEGER PRIMARY KEY,previous_policy_sha256 TEXT NOT NULL,
    next_policy_sha256 TEXT NOT NULL,previous_policy_json TEXT NOT NULL,
    next_policy_json TEXT NOT NULL,rotation_json TEXT NOT NULL,
    previous_event_sha256 TEXT NOT NULL,event_sha256 TEXT NOT NULL UNIQUE)""")
 def initialize(self,policy):
  if not validate_policy(policy): raise ValueError("invalid initial recovery policy")
  encoded=canonical(policy).decode()
  with sqlite3.connect(self.path,timeout=10) as con:
   con.execute("BEGIN IMMEDIATE")
   row=con.execute("SELECT generation,policy_sha256,policy_json FROM recovery_policy_state WHERE singleton=1").fetchone()
   if row:
    if row[0]!=1 or row[1]!=policy_digest(policy) or row[2]!=encoded:
     raise ValueError("recovery policy registry already initialized differently")
    return {"generation":row[0],"policy_sha256":row[1],"policy":json.loads(row[2])}
   con.execute("INSERT INTO recovery_policy_state VALUES (1,1,?,?)",(policy_digest(policy),encoded))
   return {"generation":1,"policy_sha256":policy_digest(policy),"policy":policy}
 def state(self):
  with sqlite3.connect(self.path,timeout=10) as con:
   row=con.execute("SELECT generation,policy_sha256,policy_json FROM recovery_policy_state WHERE singleton=1").fetchone()
  if not row: raise ValueError("recovery policy registry is uninitialized")
  policy=json.loads(row[2])
  if not validate_policy(policy) or policy_digest(policy)!=row[1] or type(row[0]) is not int or row[0]<1:
   raise ValueError("recovery policy registry state is corrupt")
  return {"generation":row[0],"policy_sha256":row[1],"policy":policy}
 def rotate(self,next_policy,rotation):
  try:
   with sqlite3.connect(self.path,timeout=10) as con:
    con.execute("BEGIN IMMEDIATE")
    row=con.execute("SELECT generation,policy_sha256,policy_json FROM recovery_policy_state WHERE singleton=1").fetchone()
    if not row: return "UNINITIALIZED"
    generation,pd,encoded=row
    current=json.loads(encoded)
    if not validate_policy(current) or policy_digest(current)!=pd: return "CORRUPT_STATE"
    if not verify_policy_rotation(current,next_policy,rotation,generation+1): return "INVALID_ROTATION"
    next_digest=policy_digest(next_policy)
    previous_event=con.execute("SELECT event_sha256 FROM recovery_policy_events ORDER BY generation DESC LIMIT 1").fetchone()
    previous_event=previous_event[0] if previous_event else "0"*64
    event={"generation":generation+1,"previous_policy_sha256":pd,
      "next_policy_sha256":next_digest,"previous_policy":current,
      "next_policy":next_policy,"rotation":rotation,"previous_event_sha256":previous_event}
    event_hash=hashlib.sha256(EVENT_DOMAIN+canonical(event)).hexdigest()
    con.execute("INSERT INTO recovery_policy_events VALUES (?,?,?,?,?,?,?,?)",
      (generation+1,pd,next_digest,canonical(current).decode(),
       canonical(next_policy).decode(),canonical(rotation).decode(),previous_event,event_hash))
    con.execute("UPDATE recovery_policy_state SET generation=?,policy_sha256=?,policy_json=? WHERE singleton=1",
      (generation+1,next_digest,canonical(next_policy).decode()))
    return "ROTATED"
  except (sqlite3.Error,ValueError,TypeError,KeyError,OverflowError):
   return "STORE_OR_STATE_ERROR"
 def verify_history(self):
  try:
   with sqlite3.connect(self.path,timeout=10) as con:
    rows=con.execute("""SELECT generation,previous_policy_sha256,next_policy_sha256,
      previous_policy_json,next_policy_json,rotation_json,previous_event_sha256,event_sha256
      FROM recovery_policy_events ORDER BY generation""").fetchall()
   prior_digest=None; prior_event="0"*64; last_generation=1
   for row in rows:
    generation,previous,next_digest,previous_json,next_json,rotation_json,previous_event,event_hash=row
    old_policy=json.loads(previous_json); new_policy=json.loads(next_json); rotation=json.loads(rotation_json)
    if (type(generation) is not int or generation!=last_generation+1
        or previous_event!=prior_event or not validate_policy(old_policy)
        or not validate_policy(new_policy) or policy_digest(old_policy)!=previous
        or policy_digest(new_policy)!=next_digest
        or (prior_digest is not None and prior_digest!=previous)):
     return False
    if not verify_policy_rotation(old_policy,new_policy,rotation,generation): return False
    event={"generation":generation,"previous_policy_sha256":previous,
      "next_policy_sha256":next_digest,"previous_policy":old_policy,
      "next_policy":new_policy,"rotation":rotation,"previous_event_sha256":previous_event}
    calculated=hashlib.sha256(EVENT_DOMAIN+canonical(event)).hexdigest()
    if calculated!=event_hash: return False
    prior_digest=next_digest; prior_event=event_hash; last_generation=generation
   current=self.state()
   if current["generation"]!=last_generation: return False
   if rows and (current["policy_sha256"]!=prior_digest
       or current["policy"]!=json.loads(rows[-1][4])): return False
   return True
  except (sqlite3.Error,ValueError,TypeError,KeyError,OverflowError):
   return False
