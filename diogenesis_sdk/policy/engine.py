"""Policy evaluation engine — runs patterns against event buffer."""

from collections import deque, Counter

from .pattern import DEFAULT_PATTERNS


class PolicyEngine:
    """Evaluates behavioral patterns against intercepted events."""

    def __init__(self, patterns=None):
        self._patterns = list(DEFAULT_PATTERNS) if patterns is None else list(patterns)
        self._alerts = deque(maxlen=1000)
        self._alert_counts = Counter()
        self._last_eval_total = 0

    def evaluate(self, events) -> list:
        """Run all patterns against the event list. Return new alerts."""
        new_alerts = []
        for pattern in self._patterns:
            matches = pattern.matches(events)
            for match in matches:
                # Deduplicate: skip if we already have an alert with same
                # pattern + same final timestamp
                ts = match.get("timestamp", 0)
                dup_key = (match["pattern_name"], ts)
                already_seen = any(
                    (a["pattern_name"], a.get("timestamp", 0)) == dup_key
                    for a in self._alerts
                )
                if not already_seen:
                    self._alerts.append(match)
                    self._alert_counts[match["pattern_name"]] += 1
                    new_alerts.append(match)
        return new_alerts

    def get_alerts(self, n=50) -> list:
        """Return last n alerts."""
        items = list(self._alerts)
        return items[-n:]

    def get_alert_summary(self) -> dict:
        """Return {pattern_name: count} for all triggered patterns."""
        return dict(self._alert_counts)

    def add_pattern(self, pattern) -> None:
        """Add a custom pattern at runtime."""
        self._patterns.append(pattern)

    def remove_pattern(self, name) -> bool:
        """Remove a pattern by name. Returns True if found and removed."""
        before = len(self._patterns)
        self._patterns = [p for p in self._patterns if p.name != name]
        return len(self._patterns) < before

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)
