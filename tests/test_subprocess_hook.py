import subprocess
import unittest

from diogenesis_sdk.core.event_buffer import EventBuffer
from diogenesis_sdk.core.classifier import Classifier
from diogenesis_sdk.core.config import DEFAULT_CONFIG
from diogenesis_sdk.interceptors.subprocess_hook import SubprocessHook


class TestSubprocessHook(unittest.TestCase):

    def setUp(self):
        self.buffer = EventBuffer(maxlen=1000)
        self.classifier = Classifier(DEFAULT_CONFIG)
        self.hook = SubprocessHook(self.buffer, self.classifier)
        self.original_run = subprocess.run

    def tearDown(self):
        if self.hook.is_active:
            self.hook.deactivate()

    def test_activate_deactivate(self):
        self.hook.activate()
        self.assertTrue(self.hook.is_active)
        self.hook.deactivate()
        self.assertFalse(self.hook.is_active)
        self.assertIs(subprocess.run, self.original_run)

    def test_logging(self):
        self.hook.activate()
        subprocess.run(["echo", "test"], capture_output=True)
        events = [e for e in self.buffer.get_recent(50) if e["type"] == "subprocess"]
        self.assertGreater(len(events), 0)
        self.assertIn("command", events[0].get("detail", {}))

    def test_classification_suspicious(self):
        config = dict(DEFAULT_CONFIG)
        config["suspicious_patterns"] = {"imports": [], "file_paths": [],
                                         "network_hosts": [],
                                         "subprocess_commands": ["rm -rf"]}
        classifier = Classifier(config)
        hook = SubprocessHook(self.buffer, classifier)
        hook.activate()
        try:
            # Just test classification — don't actually run rm -rf
            hook._log_command("rm -rf /tmp/test", "test")
            events = [e for e in self.buffer.get_recent(50)
                      if e["type"] == "subprocess" and e["classification"] == "SUSPICIOUS"]
            self.assertGreater(len(events), 0)
        finally:
            hook.deactivate()

    def test_failure_passthrough(self):
        self.hook.activate()
        result = subprocess.run(["echo", "hello"], capture_output=True, text=True)
        self.assertIn("hello", result.stdout)


if __name__ == "__main__":
    unittest.main()
