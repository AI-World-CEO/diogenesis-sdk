import unittest
import builtins

from diogenesis_sdk.core.event_buffer import EventBuffer
from diogenesis_sdk.core.classifier import Classifier
from diogenesis_sdk.core.config import DEFAULT_CONFIG
from diogenesis_sdk.interceptors.import_hook import ImportHook


class TestImportHook(unittest.TestCase):

    def setUp(self):
        self.buffer = EventBuffer(maxlen=1000)
        self.classifier = Classifier(DEFAULT_CONFIG)
        self.hook = ImportHook(self.buffer, self.classifier)
        self.original_import = builtins.__import__

    def tearDown(self):
        if self.hook.is_active:
            self.hook.deactivate()
        builtins.__import__ = self.original_import

    def test_activate_deactivate(self):
        self.hook.activate()
        self.assertTrue(self.hook.is_active)
        self.assertIsNot(builtins.__import__, self.original_import)
        self.hook.deactivate()
        self.assertFalse(self.hook.is_active)
        self.assertIs(builtins.__import__, self.original_import)

    def test_logging(self):
        self.hook.activate()
        import json  # noqa: F401 — triggers the hook
        events = self.buffer.get_recent(50)
        json_events = [e for e in events if e.get("detail", {}).get("module") == "json"]
        self.assertGreater(len(json_events), 0)
        evt = json_events[0]
        self.assertEqual(evt["type"], "import")
        self.assertIn("timestamp", evt)
        self.assertIn("classification", evt)

    def test_classification_stdlib(self):
        self.hook.activate()
        import os  # noqa: F401
        events = self.buffer.get_recent(50)
        os_events = [e for e in events if e.get("detail", {}).get("module") == "os"]
        if os_events:
            self.assertEqual(os_events[0]["classification"], "KNOWN")

    def test_reentrance(self):
        self.hook.activate()
        # Importing a module that itself imports many things should not infinite loop
        import collections  # noqa: F401
        self.assertLess(len(self.buffer), 1000)

    def test_failure_passthrough(self):
        self.hook.activate()
        # A normal import should still work even with hooks active
        import tempfile  # noqa: F401
        self.assertIsNotNone(tempfile.gettempdir())


if __name__ == "__main__":
    unittest.main()
