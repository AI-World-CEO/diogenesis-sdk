import os
import tempfile
import unittest
import builtins

from diogenesis_sdk.core.event_buffer import EventBuffer
from diogenesis_sdk.core.classifier import Classifier
from diogenesis_sdk.core.config import DEFAULT_CONFIG
from diogenesis_sdk.interceptors.file_hook import FileHook


class TestFileHook(unittest.TestCase):

    def setUp(self):
        self.buffer = EventBuffer(maxlen=1000)
        self.classifier = Classifier(DEFAULT_CONFIG)
        self.hook = FileHook(self.buffer, self.classifier)
        self.original_open = builtins.open

    def tearDown(self):
        if self.hook.is_active:
            self.hook.deactivate()
        builtins.open = self.original_open

    def test_activate_deactivate(self):
        self.hook.activate()
        self.assertTrue(self.hook.is_active)
        self.hook.deactivate()
        self.assertFalse(self.hook.is_active)
        self.assertIs(builtins.open, self.original_open)

    def test_logging(self):
        self.hook.activate()
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        try:
            with open(path, "w") as f:
                f.write("test")
            events = self.buffer.get_recent(50)
            file_events = [e for e in events if e["type"] == "file"]
            self.assertGreater(len(file_events), 0)
            evt = file_events[-1]
            self.assertIn("path", evt.get("detail", {}))
            self.assertEqual(evt["detail"]["mode"], "w")
        finally:
            os.unlink(path)

    def test_classification(self):
        config = dict(DEFAULT_CONFIG)
        config["whitelist"] = {"file_paths": [tempfile.gettempdir().replace("\\", "/")],
                               "import_modules": [], "network_hosts": [], "subprocess_commands": []}
        classifier = Classifier(config)
        hook = FileHook(self.buffer, classifier)
        hook.activate()
        try:
            fd, path = tempfile.mkstemp(suffix=".txt")
            os.close(fd)
            with open(path, "r") as f:
                _ = f.read()
            events = [e for e in self.buffer.get_recent(50) if e["type"] == "file"]
            self.assertTrue(any(e["classification"] == "KNOWN" for e in events))
            os.unlink(path)
        finally:
            hook.deactivate()

    def test_failure_passthrough(self):
        self.hook.activate()
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        try:
            with open(path, "w") as f:
                f.write("passthrough works")
            with open(path, "r") as f:
                content = f.read()
            self.assertEqual(content, "passthrough works")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
