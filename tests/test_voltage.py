import time
import unittest

from diogenesis_sdk.field.voltage import ModuleVoltage, VoltageField


def _evt(caller="app.py", etype="import", classification="KNOWN", detail=None, ts=None):
    return {
        "type": etype,
        "timestamp": ts or time.time(),
        "caller_file": caller,
        "caller_line": 1,
        "caller_func": "test",
        "detail": detail or {},
        "classification": classification,
    }


class TestModuleVoltage(unittest.TestCase):

    def test_initial_voltage(self):
        mv = ModuleVoltage("test")
        self.assertEqual(mv.voltage, 1.0)

    def test_known_event_maintains_voltage(self):
        mv = ModuleVoltage("test")
        baseline = {"event_types": {"import"}, "classifications": {"KNOWN": 100}}
        mv.record_event(_evt(classification="KNOWN"), baseline)
        self.assertGreaterEqual(mv.voltage, 1.0)

    def test_unexpected_drops_voltage(self):
        mv = ModuleVoltage("test")
        baseline = {"event_types": {"import"}, "classifications": {"KNOWN": 100}}
        mv.record_event(_evt(classification="UNEXPECTED"), baseline)
        self.assertAlmostEqual(mv.voltage, 1.0 - ModuleVoltage.UNEXPECTED_DROP)

    def test_suspicious_drops_more(self):
        mv = ModuleVoltage("test")
        baseline = {"event_types": {"import"}, "classifications": {"KNOWN": 100}}
        mv.record_event(_evt(classification="SUSPICIOUS"), baseline)
        self.assertAlmostEqual(mv.voltage, 1.0 - ModuleVoltage.SUSPICIOUS_DROP)

    def test_recovery(self):
        mv = ModuleVoltage("test")
        baseline = {"event_types": {"import"}, "classifications": {"KNOWN": 100}}
        mv.record_event(_evt(classification="UNEXPECTED"), baseline)
        dropped = mv.voltage
        # Send known events to recover
        for _ in range(5):
            mv.record_event(_evt(classification="KNOWN"), baseline)
        self.assertGreater(mv.voltage, dropped)

    def test_decay_on_silence(self):
        mv = ModuleVoltage("test")
        mv.last_seen = time.time() - 120  # 2 minutes ago
        baseline = {"event_types": {"import"}, "classifications": {}}
        mv.record_event(_evt(classification="KNOWN"), baseline)
        old_v = mv.voltage
        # Simulate silence
        mv.last_seen = time.time() - 120
        mv.apply_decay(time.time())
        self.assertLess(mv.voltage, old_v)


class TestVoltageField(unittest.TestCase):

    def test_multiple_modules_independent(self):
        vf = VoltageField()
        baseline_a = {"event_types": {"import"}, "classifications": {"KNOWN": 100}}
        baseline_b = {"event_types": {"file"}, "classifications": {"KNOWN": 100}}
        vf.set_baseline("app", baseline_a)
        vf.set_baseline("lib", baseline_b)

        events = [
            _evt("app.py", "import", "KNOWN"),
            _evt("lib.py", "file", "SUSPICIOUS"),
        ]
        vf.update(events)
        self.assertGreater(vf.get_module_voltage("app"), vf.get_module_voltage("lib"))

    def test_field_coherence(self):
        vf = VoltageField()
        baseline = {"event_types": {"import"}, "classifications": {"KNOWN": 100}}
        vf.set_baseline("a", baseline)
        vf.set_baseline("b", baseline)
        events = [
            _evt("a.py", "import", "KNOWN"),
            _evt("b.py", "import", "SUSPICIOUS"),
        ]
        vf.update(events)
        # Field coherence should be mean of two module voltages
        va = vf.get_module_voltage("a")
        vb = vf.get_module_voltage("b")
        expected = (va + vb) / 2
        self.assertAlmostEqual(vf.field_coherence, expected, places=3)

    def test_auto_baseline(self):
        vf = VoltageField()
        now = time.time()
        events = [_evt("app.py", "import", "KNOWN", ts=now + i * 0.01) for i in range(600)]
        generated = vf.auto_baseline(events, min_events=500)
        self.assertIn("app", generated)
        self.assertIn("event_types", generated["app"])
        self.assertIn("import", generated["app"]["event_types"])

    def test_voltage_history(self):
        vf = VoltageField()
        events = [_evt("app.py", "import", "KNOWN")]
        vf.update(events)
        history = vf.get_voltage_history(10)
        self.assertGreater(len(history), 0)
        self.assertIn("timestamp", history[0])
        self.assertIn("coherence", history[0])


if __name__ == "__main__":
    unittest.main()
