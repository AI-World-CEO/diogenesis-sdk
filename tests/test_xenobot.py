import time
import unittest

from diogenesis_sdk.agents.xenobot import XenobotAgent, Investigation, _pattern_hash


def _trigger(etype="import", classification="SUSPICIOUS", caller="evil.py", detail=None):
    return {
        "type": etype,
        "classification": classification,
        "caller_file": caller,
        "caller_line": 1,
        "caller_func": "hack",
        "detail": detail or {},
        "timestamp": time.time(),
    }


def _context(voltage=0.4, drops=None):
    return {
        "recent_events": [],
        "voltage_state": {
            "field_coherence": 0.6,
            "modules": {"evil": {"voltage": voltage, "event_count": 10, "has_baseline": True}},
            "drops": drops or [],
            "critical": [],
        },
        "baseline": {"status": "ACCUMULATING"},
        "connection_graph": {},
        "alerts": [],
    }


class TestXenobotAgent(unittest.TestCase):

    def test_5_phase_cycle(self):
        agent = XenobotAgent("test_agent")
        inv = agent.investigate(_trigger(), _context())
        self.assertIsInstance(inv, Investigation)
        self.assertTrue(len(inv.observation) > 0)
        self.assertTrue(len(inv.hypothesis) > 0)
        self.assertIsInstance(inv.evidence, list)
        self.assertIn(inv.verdict, ("THREAT", "SUSPICIOUS", "BENIGN"))
        self.assertGreaterEqual(inv.confidence, 0.0)
        self.assertIn(inv.recommended_action, ("ESCALATE", "WATCH", "DISMISS"))

    def test_observe_extracts_facts(self):
        agent = XenobotAgent("test_agent")
        inv = agent.investigate(_trigger("import", "SUSPICIOUS", "evil.py"), _context())
        self.assertIn("import", inv.observation)
        self.assertIn("evil", inv.observation)
        self.assertIn("SUSPICIOUS", inv.observation)

    def test_question_generates_hypothesis(self):
        agent = XenobotAgent("test_agent")
        inv = agent.investigate(_trigger("import", "SUSPICIOUS"), _context())
        self.assertTrue(len(inv.hypothesis) > 10)

    def test_search_gathers_evidence(self):
        agent = XenobotAgent("test_agent")
        ctx = _context()
        ctx["recent_events"] = [_trigger("import", "KNOWN", "evil.py")] * 5
        ctx["connection_graph"] = {"evil": ["lib"]}
        inv = agent.investigate(_trigger("import", "SUSPICIOUS", "evil.py"), ctx)
        self.assertGreater(len(inv.evidence), 0)

    def test_synthesize_scores_threat(self):
        agent = XenobotAgent("test_agent")
        # SUSPICIOUS + low voltage + novel pattern -> high score
        inv = agent.investigate(
            _trigger("import", "SUSPICIOUS"),
            _context(voltage=0.3, drops=["evil"])
        )
        self.assertIn(inv.verdict, ("THREAT", "SUSPICIOUS"))

    def test_synthesize_scores_benign(self):
        agent = XenobotAgent("test_agent")
        # First investigate to mark pattern BENIGN
        trigger = _trigger("import", "KNOWN", "safe.py")
        agent.behavioral_model[_pattern_hash(trigger)] = {
            "count": 5, "first_seen": time.time() - 1000,
            "last_seen": time.time(), "verdict": "BENIGN"
        }
        inv = agent.investigate(trigger, _context(voltage=0.9))
        self.assertEqual(inv.verdict, "BENIGN")

    def test_crystallize_records(self):
        agent = XenobotAgent("test_agent")
        inv = agent.investigate(_trigger(), _context())
        self.assertEqual(len(agent.findings), 1)
        self.assertGreater(agent.stats["findings"], 0)
        d = inv.to_dict()
        self.assertIn("verdict", d)
        self.assertIn("confidence", d)

    def test_behavioral_model_learns(self):
        agent = XenobotAgent("test_agent")
        trigger = _trigger("import", "KNOWN", "safe.py")
        # First time — novel
        inv1 = agent.investigate(trigger, _context(voltage=0.9))
        phash = _pattern_hash(trigger)
        self.assertIn(phash, agent.behavioral_model)
        # Reset cooldown
        agent.cooldown.clear()
        # Second time — known, should get lower score
        inv2 = agent.investigate(trigger, _context(voltage=0.9))
        self.assertLessEqual(inv2.confidence, inv1.confidence)

    def test_cooldown(self):
        agent = XenobotAgent("test_agent")
        inv1 = agent.investigate(_trigger(), _context())
        inv2 = agent.investigate(_trigger(), _context())
        # Second investigation should be dismissed due to cooldown
        self.assertEqual(inv2.verdict, "BENIGN")
        self.assertIn("Cooldown", inv2.reasoning)

    def test_custom_reasoning_fn(self):
        called = {"question": False, "synthesize": False}

        def my_reasoning(phase, trigger, context, evidence=None):
            called[phase] = True
            if phase == "question":
                return "Custom hypothesis"
            if phase == "synthesize":
                return ("THREAT", 0.99, "Custom reasoning says threat")

        agent = XenobotAgent("custom", reasoning_fn=my_reasoning)
        inv = agent.investigate(_trigger(), _context())
        self.assertTrue(called["question"])
        self.assertTrue(called["synthesize"])
        self.assertEqual(inv.hypothesis, "Custom hypothesis")
        self.assertEqual(inv.verdict, "THREAT")
        self.assertEqual(inv.confidence, 0.99)

    def test_domain_specialization(self):
        agent = XenobotAgent("import_only", domain="import")
        # Import event — should investigate
        inv1 = agent.investigate(_trigger("import", "SUSPICIOUS"), _context())
        self.assertNotEqual(inv1.reasoning, "")
        self.assertNotIn("Outside domain", inv1.reasoning)

        # File event — should dismiss
        agent.cooldown.clear()
        inv2 = agent.investigate(_trigger("file", "SUSPICIOUS"), _context())
        self.assertEqual(inv2.verdict, "BENIGN")
        self.assertIn("Outside domain", inv2.reasoning)


if __name__ == "__main__":
    unittest.main()
