import time
import unittest

from diogenesis_sdk.policy.engine import PolicyEngine
from diogenesis_sdk.policy.pattern import BehavioralPattern, DEFAULT_PATTERNS


def _make_event(etype, classification="KNOWN", detail=None, ts=None):
    return {
        "type": etype,
        "timestamp": ts or time.time(),
        "caller_file": "test.py",
        "caller_line": 1,
        "caller_func": "test",
        "detail": detail or {},
        "classification": classification,
    }


class TestPolicyEngine(unittest.TestCase):

    def test_default_patterns_loaded(self):
        pe = PolicyEngine()
        self.assertEqual(pe.pattern_count, 5)

    def test_evaluate_finds_exfiltration(self):
        pe = PolicyEngine()
        now = time.time()
        events = [
            _make_event("file", "UNEXPECTED", {"mode": "r", "path": "/secret"}, ts=now),
            _make_event("network", "UNEXPECTED", {"url": "http://evil.com", "method": "POST"}, ts=now + 2),
        ]
        new_alerts = pe.evaluate(events)
        critical = [a for a in new_alerts if a["severity"] == "CRITICAL"]
        self.assertGreater(len(critical), 0)
        self.assertEqual(critical[0]["pattern_name"], "data_exfiltration")

    def test_evaluate_no_false_positive(self):
        pe = PolicyEngine()
        now = time.time()
        events = [
            _make_event("import", "KNOWN", ts=now),
            _make_event("file", "KNOWN", {"mode": "r"}, ts=now + 1),
            _make_event("import", "KNOWN", ts=now + 2),
        ]
        new_alerts = pe.evaluate(events)
        self.assertEqual(len(new_alerts), 0)

    def test_add_remove_pattern(self):
        pe = PolicyEngine(patterns=[])
        custom = BehavioralPattern(
            name="custom_test",
            description="test pattern",
            event_sequence=[{"type": "import", "classification": "UNEXPECTED"}],
            window_seconds=60,
        )
        pe.add_pattern(custom)
        self.assertEqual(pe.pattern_count, 1)

        now = time.time()
        events = [_make_event("import", "UNEXPECTED", ts=now)]
        alerts = pe.evaluate(events)
        self.assertEqual(len(alerts), 1)

        pe.remove_pattern("custom_test")
        self.assertEqual(pe.pattern_count, 0)

        # Re-evaluate — no pattern to match
        alerts2 = pe.evaluate(events)
        self.assertEqual(len(alerts2), 0)

    def test_alert_summary(self):
        pe = PolicyEngine(patterns=[])
        custom = BehavioralPattern(
            name="test_pat", description="t",
            event_sequence=[{"type": "file", "classification": "UNEXPECTED"}],
            window_seconds=60,
        )
        pe.add_pattern(custom)

        now = time.time()
        events = [
            _make_event("file", "UNEXPECTED", ts=now),
            _make_event("file", "UNEXPECTED", ts=now + 1),
        ]
        pe.evaluate(events)
        summary = pe.get_alert_summary()
        self.assertEqual(summary.get("test_pat", 0), 2)


if __name__ == "__main__":
    unittest.main()
