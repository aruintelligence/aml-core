"""Bounded exploration checks for synthetic broker atomicity assumptions."""
import unittest
from broker_state_model import explore,successors

class BrokerModelTests(unittest.TestCase):
    def test_exhaustive_bounded_state_graph(self):
        states,edges=explore()
        self.assertGreaterEqual(states,4)
        self.assertGreaterEqual(edges,4)
    def test_revoked_capability_cannot_commit(self):
        self.assertFalse(any(event=="commit" for event,_ in successors((1,0,False))))
    def test_consumed_operation_cannot_commit_twice(self):
        self.assertFalse(any(event=="commit" for event,_ in successors((0,0,True))))
