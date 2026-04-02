import json
import os
import tempfile
import unittest

import diogenesis_sdk
from diogenesis_sdk.engine import DiogenesisEngine


class TestEngine(unittest.TestCase):

    def setUp(self):
        self.engine = DiogenesisEngine()

    def tearDown(self):
        if self.engine._active:
            self.engine.deactivate()

    def test_full_lifecycle(self):
        result = self.engine.activate()
        self.assertEqual(result["status"], "activated")
        self.assertGreater(result["interceptors"], 0)

        # Trigger some events
        import json as j2  # noqa: F401
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        with open(path, "w") as f:
            f.write("lifecycle test")
        os.unlink(path)

        # Check log
        events = self.engine.log(50)
        self.assertGreater(len(events), 0)

        # Check status
        status = self.engine.status()
        self.assertTrue(status["active"])
        self.assertGreater(status["total_events"], 0)
        self.assertIn("counts", status)
        self.assertIn("classification_summary", status)

        # Deactivate
        result = self.engine.deactivate()
        self.assertEqual(result["status"], "deactivated")

        # Verify originals restored
        with open(os.devnull, "w") as f:
            f.write("still works")

    def test_config_from_dict(self):
        result = self.engine.activate({
            "buffer_size": 500,
            "interceptors": {"import": True, "file": False, "subprocess": False, "network": False},
        })
        self.assertEqual(result["status"], "activated")
        self.assertEqual(result["buffer_capacity"], 500)
        self.assertEqual(result["interceptors"], 1)

    def test_config_from_file(self):
        config = {"enabled": True, "buffer_size": 2000}
        config_path = os.path.join(os.getcwd(), "diogenesis_sdk.json")
        try:
            with open(config_path, "w") as f:
                json.dump(config, f)
            result = self.engine.activate()
            self.assertEqual(result["status"], "activated")
            self.assertEqual(result["buffer_capacity"], 2000)
        finally:
            if os.path.exists(config_path):
                os.unlink(config_path)
            self.engine.deactivate()

    def test_default_config(self):
        result = self.engine.activate()
        self.assertEqual(result["status"], "activated")
        self.assertEqual(result["buffer_capacity"], 10000)

    def test_singleton_no_double_activate(self):
        self.engine.activate()
        result = self.engine.activate()
        self.assertEqual(result["status"], "already_active")

    def test_baseline_requires_events(self):
        self.engine.activate()
        bl = self.engine.baseline()
        self.assertEqual(bl["status"], "ACCUMULATING")
        self.assertIn("needed", bl)

    def test_status_schema(self):
        self.engine.activate()
        status = self.engine.status()
        required_keys = ["active", "interceptors", "counts", "total_events",
                         "buffer_size", "buffer_capacity", "uptime_seconds",
                         "classification_summary"]
        for key in required_keys:
            self.assertIn(key, status, f"Missing key: {key}")

    def test_module_api(self):
        """Test the top-level diogenesis_sdk.activate() etc."""
        result = diogenesis_sdk.activate({"interceptors": {"import": True, "file": False,
                                                            "subprocess": False, "network": False}})
        self.assertEqual(result["status"], "activated")
        status = diogenesis_sdk.status()
        self.assertTrue(status["active"])
        diogenesis_sdk.deactivate()

    def test_policy_integration(self):
        """Policy alerts appear in status after suspicious events."""
        import time
        from diogenesis_sdk.policy.pattern import BehavioralPattern
        engine = DiogenesisEngine()
        engine.activate({"interceptors": {"import": False, "file": False,
                                          "subprocess": False, "network": False}})
        try:
            # Inject synthetic suspicious events directly into the buffer
            now = time.time()
            engine._buffer.append({
                "type": "file", "timestamp": now, "caller_file": "evil.py",
                "caller_line": 1, "caller_func": "steal",
                "detail": {"mode": "r", "path": "/etc/passwd"},
                "classification": "UNEXPECTED",
            })
            engine._buffer.append({
                "type": "network", "timestamp": now + 1, "caller_file": "evil.py",
                "caller_line": 2, "caller_func": "send",
                "detail": {"url": "http://evil.com", "method": "POST"},
                "classification": "UNEXPECTED",
            })
            alerts = engine.evaluate_policies()
            self.assertGreater(len(alerts), 0)
            status = engine.status()
            self.assertGreater(status["policy_alerts"], 0)
        finally:
            engine.deactivate()

    def test_auto_evaluate(self):
        """Auto-evaluation triggers when buffer grows by 100+ events."""
        import time
        engine = DiogenesisEngine()
        engine.activate({"interceptors": {"import": False, "file": False,
                                          "subprocess": False, "network": False},
                         "auto_evaluate": True})
        try:
            now = time.time()
            # Inject 101 events (100 normal + 1 suspicious pair)
            for i in range(99):
                engine._buffer.append({
                    "type": "import", "timestamp": now + i * 0.01,
                    "caller_file": "app.py", "caller_line": 1,
                    "caller_func": "run", "detail": {"module": "os"},
                    "classification": "KNOWN",
                })
            # Add exfiltration pair
            engine._buffer.append({
                "type": "file", "timestamp": now + 1, "caller_file": "app.py",
                "caller_line": 10, "caller_func": "read",
                "detail": {"mode": "r", "path": "/secret"},
                "classification": "UNEXPECTED",
            })
            engine._buffer.append({
                "type": "network", "timestamp": now + 2, "caller_file": "app.py",
                "caller_line": 11, "caller_func": "post",
                "detail": {"url": "http://evil.com", "method": "POST"},
                "classification": "UNEXPECTED",
            })
            # Status triggers auto-evaluate (101 events > 100 threshold)
            status = engine.status()
            self.assertGreater(status["policy_alerts"], 0)
        finally:
            engine.deactivate()

    def test_voltage_integration(self):
        """Field state tracks modules after events are injected."""
        import time
        engine = DiogenesisEngine()
        engine.activate({"interceptors": {"import": False, "file": False,
                                          "subprocess": False, "network": False}})
        try:
            now = time.time()
            for i in range(60):
                engine._buffer.append({
                    "type": "import", "timestamp": now + i * 0.01,
                    "caller_file": "myapp.py", "caller_line": 1,
                    "caller_func": "run", "detail": {"module": "os"},
                    "classification": "KNOWN",
                })
            # Trigger voltage update via status (auto-evaluate at 50 events)
            status = engine.status()
            fs = engine.field_state()
            self.assertGreater(fs["module_count"], 0)
            self.assertIn("myapp", fs["modules"])
        finally:
            engine.deactivate()

    def test_voltage_drops_on_suspicious(self):
        """Suspicious events drop module voltage below 1.0."""
        import time
        engine = DiogenesisEngine()
        engine.activate({"interceptors": {"import": False, "file": False,
                                          "subprocess": False, "network": False}})
        try:
            now = time.time()
            # Set a baseline so voltage tracking activates
            engine._voltage_field.set_baseline("evil", {
                "event_types": {"import"}, "classifications": {"KNOWN": 100}
            })
            for i in range(55):
                engine._buffer.append({
                    "type": "import", "timestamp": now + i * 0.01,
                    "caller_file": "evil.py", "caller_line": 1,
                    "caller_func": "hack", "detail": {"module": "ctypes"},
                    "classification": "SUSPICIOUS",
                })
            # Trigger update
            engine.status()
            v = engine.module_voltage("evil")
            self.assertLess(v, 1.0)
        finally:
            engine.deactivate()

    def test_create_scheduler(self):
        """create_scheduler returns a working scheduler."""
        engine = DiogenesisEngine()
        engine.activate({"interceptors": {"import": False, "file": False,
                                          "subprocess": False, "network": False}})
        try:
            sched = engine.create_scheduler()
            self.assertIsNotNone(sched)
            self.assertEqual(len(sched.clock.agents), 5)
            result = sched.tick()
            self.assertEqual(result["cycle"], 1)
            self.assertIs(engine.get_scheduler(), sched)
        finally:
            engine.deactivate()

    def test_swarm_integration(self):
        """Xenobot investigations triggered by policy alerts."""
        import time
        engine = DiogenesisEngine()
        engine.activate({"interceptors": {"import": False, "file": False,
                                          "subprocess": False, "network": False}})
        try:
            now = time.time()
            # Inject exfiltration pattern
            engine._buffer.append({
                "type": "file", "timestamp": now, "caller_file": "evil.py",
                "caller_line": 1, "caller_func": "steal",
                "detail": {"mode": "r", "path": "/etc/passwd"},
                "classification": "UNEXPECTED",
            })
            engine._buffer.append({
                "type": "network", "timestamp": now + 1, "caller_file": "evil.py",
                "caller_line": 2, "caller_func": "send",
                "detail": {"url": "http://evil.com", "method": "POST"},
                "classification": "UNEXPECTED",
            })
            engine.evaluate_policies()
            findings = engine.investigations(50)
            self.assertGreater(len(findings), 0)
        finally:
            engine.deactivate()

    def test_voltage_triggers_investigation(self):
        """Critical voltage drop triggers xenobot investigation."""
        import time
        engine = DiogenesisEngine()
        engine.activate({"interceptors": {"import": False, "file": False,
                                          "subprocess": False, "network": False}})
        try:
            now = time.time()
            engine._voltage_field.set_baseline("bad", {
                "event_types": {"import"}, "classifications": {"KNOWN": 100}
            })
            # Inject enough suspicious events to cross auto-evaluate threshold
            for i in range(55):
                engine._buffer.append({
                    "type": "import", "timestamp": now + i * 0.01,
                    "caller_file": "bad.py", "caller_line": 1,
                    "caller_func": "hack", "detail": {"module": "ctypes"},
                    "classification": "SUSPICIOUS",
                })
            # Trigger update — voltage should drop, potentially triggering investigation
            engine._update_voltage_field()
            v = engine.module_voltage("bad")
            self.assertLess(v, 1.0)
            summary = engine.threat_summary()
            self.assertIn("total_investigations", summary)
        finally:
            engine.deactivate()


if __name__ == "__main__":
    unittest.main()
