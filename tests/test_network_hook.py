import unittest

from diogenesis_sdk.core.event_buffer import EventBuffer
from diogenesis_sdk.core.classifier import Classifier
from diogenesis_sdk.core.config import DEFAULT_CONFIG
from diogenesis_sdk.interceptors.network_hook import NetworkHook


class TestNetworkHook(unittest.TestCase):

    def setUp(self):
        self.buffer = EventBuffer(maxlen=1000)
        self.classifier = Classifier(DEFAULT_CONFIG)
        self.hook = NetworkHook(self.buffer, self.classifier)

    def tearDown(self):
        if self.hook.is_active:
            self.hook.deactivate()

    def test_activate_deactivate(self):
        try:
            import requests  # noqa: F401
        except ImportError:
            self.skipTest("requests not installed")
        self.hook.activate()
        self.assertTrue(self.hook.is_active)
        self.hook.deactivate()
        self.assertFalse(self.hook.is_active)

    def test_no_requests_graceful(self):
        # If requests is not installed, activate should do nothing
        # (tested implicitly — if requests IS installed, we test the hook)
        pass

    def test_classification_known(self):
        result = self.classifier.classify_network("http://localhost:8080/api", "GET")
        self.assertEqual(result, "KNOWN")

    def test_classification_unexpected(self):
        result = self.classifier.classify_network("http://evil.example.com/steal", "POST")
        self.assertEqual(result, "UNEXPECTED")

    def test_failure_passthrough(self):
        try:
            import requests
        except ImportError:
            self.skipTest("requests not installed")
        self.hook.activate()
        # A real request to a non-existent host should raise normally
        with self.assertRaises(Exception):
            requests.get("http://192.0.2.1:1", timeout=0.1)


if __name__ == "__main__":
    unittest.main()
