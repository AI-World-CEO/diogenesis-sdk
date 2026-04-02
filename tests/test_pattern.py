import time
import unittest

from diogenesis_sdk.policy.pattern import BehavioralPattern


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


class TestPattern(unittest.TestCase):

    def test_simple_match(self):
        pattern = BehavioralPattern(
            name="test", description="test",
            event_sequence=[
                {"type": "file", "classification": "UNEXPECTED"},
                {"type": "network", "classification": "UNEXPECTED"},
            ],
            window_seconds=60,
        )
        now = time.time()
        events = [
            _make_event("file", "UNEXPECTED", ts=now),
            _make_event("network", "UNEXPECTED", ts=now + 1),
        ]
        matches = pattern.matches(events)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["pattern_name"], "test")

    def test_window_expired(self):
        pattern = BehavioralPattern(
            name="test", description="test",
            event_sequence=[
                {"type": "file", "classification": "UNEXPECTED"},
                {"type": "network", "classification": "UNEXPECTED"},
            ],
            window_seconds=5,
        )
        now = time.time()
        events = [
            _make_event("file", "UNEXPECTED", ts=now),
            _make_event("network", "UNEXPECTED", ts=now + 10),
        ]
        matches = pattern.matches(events)
        self.assertEqual(len(matches), 0)

    def test_order_matters(self):
        pattern = BehavioralPattern(
            name="test", description="test",
            event_sequence=[
                {"type": "file"},
                {"type": "network"},
            ],
            window_seconds=60,
        )
        now = time.time()
        # Wrong order: network before file
        events = [
            _make_event("network", ts=now),
            _make_event("file", ts=now + 1),
        ]
        # The pattern starts scanning from "file" events — the file at now+1
        # won't find a network after it
        file_first_matches = pattern.matches(events)
        # file is at index 1, no network after it
        self.assertEqual(len(file_first_matches), 0)

    def test_non_consecutive(self):
        pattern = BehavioralPattern(
            name="test", description="test",
            event_sequence=[
                {"type": "file", "classification": "UNEXPECTED"},
                {"type": "network", "classification": "UNEXPECTED"},
            ],
            window_seconds=60,
        )
        now = time.time()
        events = [
            _make_event("file", "UNEXPECTED", ts=now),
            _make_event("import", "KNOWN", ts=now + 1),
            _make_event("import", "KNOWN", ts=now + 2),
            _make_event("network", "UNEXPECTED", ts=now + 3),
        ]
        matches = pattern.matches(events)
        self.assertEqual(len(matches), 1)

    def test_no_match(self):
        pattern = BehavioralPattern(
            name="test", description="test",
            event_sequence=[
                {"type": "file", "classification": "SUSPICIOUS"},
                {"type": "subprocess"},
            ],
            window_seconds=60,
        )
        now = time.time()
        events = [
            _make_event("file", "KNOWN", ts=now),
            _make_event("import", "KNOWN", ts=now + 1),
        ]
        matches = pattern.matches(events)
        self.assertEqual(len(matches), 0)

    def test_detail_contains(self):
        pattern = BehavioralPattern(
            name="test", description="test",
            event_sequence=[
                {"type": "file", "detail_contains": {"mode": "w"}},
            ],
            window_seconds=60,
        )
        now = time.time()
        events = [
            _make_event("file", detail={"mode": "w", "path": "/tmp/x"}, ts=now),
            _make_event("file", detail={"mode": "r", "path": "/tmp/y"}, ts=now + 1),
        ]
        matches = pattern.matches(events)
        self.assertEqual(len(matches), 1)

    def test_multiple_matches(self):
        pattern = BehavioralPattern(
            name="test", description="test",
            event_sequence=[
                {"type": "network", "classification": "UNEXPECTED"},
            ],
            window_seconds=60,
        )
        now = time.time()
        events = [
            _make_event("network", "UNEXPECTED", ts=now),
            _make_event("network", "UNEXPECTED", ts=now + 1),
            _make_event("network", "UNEXPECTED", ts=now + 2),
        ]
        matches = pattern.matches(events)
        self.assertEqual(len(matches), 3)


if __name__ == "__main__":
    unittest.main()
