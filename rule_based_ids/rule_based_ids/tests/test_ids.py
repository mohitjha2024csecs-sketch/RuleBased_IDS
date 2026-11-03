import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ids.engine import Prover, forward_chain
from ids.logs import generate, load_facts
from ids.rules import RULES

DERIVED = ["brute_force", "account_compromised", "port_scan",
           "privilege_escalation", "is_intrusion"]


class IDSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = os.path.join(tempfile.mkdtemp(), "logs.csv")
        generate(cls.path)
        cls.facts = load_facts(cls.path)
        cls.fwd = forward_chain(cls.facts, RULES)
        cls.prover = Prover(cls.facts, RULES)
        cls.derived = {(f.pred, f.args) for _, _, f, _ in cls.fwd.derived}

    def test_detects_all_attacks(self):
        expected = {("brute_force", ("198.51.100.23",)), ("brute_force", ("203.0.113.9",)),
                    ("account_compromised", ("carol",)), ("port_scan", ("203.0.113.77",)),
                    ("privilege_escalation", ("dave",)),
                    ("is_intrusion", ("carol",)), ("is_intrusion", ("dave",))}
        self.assertEqual(self.derived, expected)

    def test_no_false_positives_on_near_misses(self):
        for user in ("alice", "bob", "erin", "admin"):
            self.assertNotIn(("is_intrusion", (user,)), self.derived)
        self.assertNotIn(("brute_force", ("192.0.2.50",)), self.derived)   # failures too slow
        self.assertNotIn(("port_scan", ("10.0.0.30",)), self.derived)      # below threshold

    def test_backward_yes_and_no(self):
        self.assertTrue(self.prover.ask("is_intrusion", ("carol",)))
        self.assertFalse(self.prover.ask("is_intrusion", ("admin",)))
        self.assertFalse(self.prover.ask("is_intrusion", ("alice",)))

    def test_forward_and_backward_agree(self):
        for pred in DERIVED:
            back = {a for a, _ in self.prover.ask(pred, (None,))}
            fwd = {a for p, a in self.derived if p == pred}
            self.assertEqual(back, fwd, pred)

    def test_proof_trace_reaches_log_facts(self):
        _, node = self.prover.ask("is_intrusion", ("carol",))[0]
        self.assertEqual(node.rule, "R5a")
        kinds, stack = set(), [node]
        while stack:
            n = stack.pop()
            kinds.add(n.kind)
            stack.extend(n.children)
        self.assertEqual(kinds, {"derived", "aggregate", "fact"})

    def test_temporal_window_on_privilege_escalation(self):
        # same user/role but 6s apart must NOT fire R4 (limit is 5s)
        from ids.engine import Fact
        facts = [Fact("login", ("x",), 0), Fact("privilege_change", ("x", "admin"), 6)]
        self.assertFalse(Prover(facts, RULES).ask("privilege_escalation", (None,)))
        facts[1] = Fact("privilege_change", ("x", "admin"), 5)
        self.assertTrue(Prover(facts, RULES).ask("privilege_escalation", (None,)))


if __name__ == "__main__":
    unittest.main()
