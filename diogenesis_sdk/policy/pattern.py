"""Behavioral pattern definitions — multi-event sequence detection."""


class BehavioralPattern:
    """A sequence of events that together indicate something.

    Usage:
        pattern = BehavioralPattern(
            name="data_exfiltration",
            description="File read followed by network send",
            event_sequence=[
                {"type": "file", "classification": "UNEXPECTED"},
                {"type": "network", "classification": "UNEXPECTED"},
            ],
            window_seconds=30,
            severity="CRITICAL",
        )
        matches = pattern.matches(event_list)
    """

    def __init__(self, name, description, event_sequence, window_seconds=60, severity="WARNING"):
        self.name = name
        self.description = description
        self.event_sequence = event_sequence
        self.window_seconds = window_seconds
        self.severity = severity

    def _event_matches_spec(self, event, spec):
        """Check if a single event matches a spec dict."""
        for key, value in spec.items():
            if key == "detail_contains":
                detail = event.get("detail", {})
                for dk, dv in value.items():
                    if str(detail.get(dk, "")) != str(dv) and str(dv) not in str(detail.get(dk, "")):
                        return False
            else:
                if event.get(key) != value:
                    return False
        return True

    def matches(self, events):
        """Scan events for this pattern. Return list of match dicts.

        Uses a sliding scan: for each event matching the first spec,
        try to complete the full sequence within window_seconds.
        Events must appear in order but need not be consecutive.
        """
        results = []
        n_specs = len(self.event_sequence)
        if n_specs == 0:
            return results

        seen_match_keys = set()

        for i, event in enumerate(events):
            if not self._event_matches_spec(event, self.event_sequence[0]):
                continue

            # Try to build full sequence starting from event i
            matched = [event]
            spec_idx = 1
            start_time = event.get("timestamp", 0)

            for j in range(i + 1, len(events)):
                if spec_idx >= n_specs:
                    break

                candidate = events[j]
                elapsed = candidate.get("timestamp", 0) - start_time
                if elapsed > self.window_seconds:
                    break

                if self._event_matches_spec(candidate, self.event_sequence[spec_idx]):
                    matched.append(candidate)
                    spec_idx += 1

            if spec_idx >= n_specs:
                # Deduplicate by using timestamps of matched events as key
                match_key = tuple(e.get("timestamp", 0) for e in matched)
                if match_key not in seen_match_keys:
                    seen_match_keys.add(match_key)
                    results.append({
                        "pattern_name": self.name,
                        "severity": self.severity,
                        "description": self.description,
                        "matched_events": matched,
                        "timestamp": matched[-1].get("timestamp", 0),
                        "window_actual": matched[-1].get("timestamp", 0) - start_time,
                    })

        return results


# ═══════════════════════════════════════════════════════════
# BUILT-IN PATTERNS
# ═══════════════════════════════════════════════════════════

EXFILTRATION = BehavioralPattern(
    name="data_exfiltration",
    description="File read from unexpected path followed by network send to unexpected host",
    event_sequence=[
        {"type": "file", "classification": "UNEXPECTED", "detail_contains": {"mode": "r"}},
        {"type": "network", "classification": "UNEXPECTED"},
    ],
    window_seconds=30,
    severity="CRITICAL",
)

SUSPICIOUS_IMPORT_CHAIN = BehavioralPattern(
    name="suspicious_import_chain",
    description="Suspicious import followed by subprocess execution",
    event_sequence=[
        {"type": "import", "classification": "SUSPICIOUS"},
        {"type": "subprocess"},
    ],
    window_seconds=10,
    severity="CRITICAL",
)

UNUSUAL_WRITE_BURST = BehavioralPattern(
    name="unusual_write_burst",
    description="5+ file writes to unexpected paths within 10 seconds",
    event_sequence=[
        {"type": "file", "classification": "UNEXPECTED", "detail_contains": {"mode": "w"}},
        {"type": "file", "classification": "UNEXPECTED", "detail_contains": {"mode": "w"}},
        {"type": "file", "classification": "UNEXPECTED", "detail_contains": {"mode": "w"}},
        {"type": "file", "classification": "UNEXPECTED", "detail_contains": {"mode": "w"}},
        {"type": "file", "classification": "UNEXPECTED", "detail_contains": {"mode": "w"}},
    ],
    window_seconds=10,
    severity="WARNING",
)

NETWORK_SCAN = BehavioralPattern(
    name="network_scan",
    description="3+ network calls to different unexpected hosts within 5 seconds",
    event_sequence=[
        {"type": "network", "classification": "UNEXPECTED"},
        {"type": "network", "classification": "UNEXPECTED"},
        {"type": "network", "classification": "UNEXPECTED"},
    ],
    window_seconds=5,
    severity="WARNING",
)

SHADOW_IMPORT = BehavioralPattern(
    name="shadow_import",
    description="Import of suspicious module followed by file access to sensitive path",
    event_sequence=[
        {"type": "import", "classification": "SUSPICIOUS"},
        {"type": "file", "classification": "SUSPICIOUS"},
    ],
    window_seconds=15,
    severity="CRITICAL",
)

DEFAULT_PATTERNS = [EXFILTRATION, SUSPICIOUS_IMPORT_CHAIN, UNUSUAL_WRITE_BURST, NETWORK_SCAN, SHADOW_IMPORT]
