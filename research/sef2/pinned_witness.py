"""Independent-checkpoint pinning simulation for SEF/2.

A separately retained checkpoint can detect history rewrite/truncation.
The caller must actually protect this state outside the producer's trust domain.
"""
from witness_chain import verify, checkpoint

class PinnedWitness:
    def __init__(self):
        self._pinned = None

    def observe(self, chain):
        if not verify(chain):
            return "INVALID_CHAIN"
        if self._pinned is not None and not verify(chain, self._pinned):
            return "ROLLBACK_OR_FORK"
        current = checkpoint(chain)
        if self._pinned == current:
            return "UNCHANGED"
        self._pinned = current
        return "ADVANCED"

    def pinned(self):
        return dict(self._pinned) if self._pinned is not None else None
