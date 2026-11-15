"""Externally anchored witness recovery coordinator.

Wraps WitnessRecoveryEnrollment and pins each accepted transition hash in an
independent compare-and-set anchor. The anchor must live outside the trust and
recovery database rollback domain.
"""
import hashlib,json,sqlite3
from signed_receipt import canonical

GENESIS="0"*64

class AnchoredWitnessRecovery:
    def __init__(self,coordinator,head_anchor):
        self.coordinator=coordinator
        self.head_anchor=head_anchor
        if head_anchor is None:
            raise ValueError("independent recovery head anchor required")

    def initialize(self,witness_id,checkpoint):
        state=self.coordinator.initialize(witness_id,checkpoint)
        try:
            anchored=self.head_anchor.read_head()
        except (OSError,RuntimeError,ValueError) as exc:
            raise RuntimeError("recovery head anchor unavailable during initialization") from exc
        if anchored!=state["transition_sha256"]:
            raise RuntimeError("recovery state differs from independent anchor")
        return state

    def state(self,witness_id):
        state=self.coordinator.state(witness_id)
        try:
            anchored=self.head_anchor.read_head()
        except (OSError,RuntimeError,ValueError) as exc:
            raise RuntimeError("recovery head anchor unavailable") from exc
        if anchored!=state["transition_sha256"]:
            raise RuntimeError("recovery state differs from independent anchor")
        return state

    def recover(self,witness_id,envelope):
        try:
            current=self.coordinator.state(witness_id)
            anchored=self.head_anchor.read_head()
        except (ValueError,OSError,RuntimeError):
            return "ANCHOR_UNAVAILABLE"
        if anchored!=current["transition_sha256"]:
            return "ANCHOR_MISMATCH"
        result=self.coordinator.recover(witness_id,envelope)
        if result!="RECOVERED":
            return result
        next_state=self.coordinator.state(witness_id)
        if not self.head_anchor.compare_and_set(current["transition_sha256"],
                                                next_state["transition_sha256"]):
            return "ANCHOR_UPDATE_FAILED"
        return "RECOVERED"

    def _local_recovery_chain(self,witness_id):
        with sqlite3.connect(self.coordinator.recovery_state_path) as con:
            state_row=con.execute("SELECT state FROM witness_recovery_state WHERE witness_id=?",
                (witness_id,)).fetchone()
            events=con.execute("""SELECT generation,event FROM witness_recovery_events
                WHERE witness_id=? ORDER BY generation""",(witness_id,)).fetchall()
        if state_row is None:
            raise ValueError("uninitialized witness recovery state")
        state=json.loads(state_row[0])
        if state["generation"]!=len(events):
            raise ValueError("recovery generation/event count mismatch")
        previous=GENESIS
        for expected,(generation,raw) in enumerate(events,1):
            if generation!=expected:
                raise ValueError("recovery event generation gap")
            envelope=json.loads(raw)
            digest=hashlib.sha256(canonical(envelope)).hexdigest()
            if expected==len(events) and digest!=state["transition_sha256"]:
                raise ValueError("recovery state head does not match last event")
            previous=digest
        if not events and state["transition_sha256"]!=GENESIS:
            raise ValueError("non-genesis head without recovery events")
        predecessor=GENESIS
        if len(events)>1:
            predecessor=hashlib.sha256(canonical(json.loads(events[-2][1]))).hexdigest()
        return state,predecessor

    def reconcile_anchor(self,witness_id,expected_predecessor=None):
        state,predecessor=self._local_recovery_chain(witness_id)
        local_head=state["transition_sha256"]
        try:
            anchored=self.head_anchor.read_head()
        except (OSError,RuntimeError,ValueError):
            if expected_predecessor is None:
                raise RuntimeError("anchor unreadable; externally retained predecessor pin required")
            anchored=expected_predecessor
        if anchored==local_head:
            return local_head
        if anchored!=predecessor:
            raise RuntimeError("EXPECTED_PREDECESSOR_MISMATCH")
        if not self.head_anchor.compare_and_set(predecessor,local_head):
            raise RuntimeError("recovery head anchor reconciliation CAS failed")
        return local_head
