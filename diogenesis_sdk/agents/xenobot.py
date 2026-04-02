"""Autonomous security agent using 5-phase investigation cycle.

Inspired by Levin's xenobots: not programmed rules, but self-organizing
response to behavioral anomalies. Each agent specializes in a domain
and learns from past investigations.

Before the sound listen, before the image see.
Not with ears or eyes, but with the silence that listens to itself.

5 Phases:
  1. OBSERVE  — extract facts from trigger event
  2. QUESTION — generate investigation hypothesis
  3. SEARCH   — gather evidence from context
  4. SYNTHESIZE — form verdict with confidence score
  5. CRYSTALLIZE — record finding, update behavioral model
"""

import hashlib
import time
from collections import deque


class Investigation:
    """Result of a 5-phase xenobot investigation."""

    def __init__(self):
        self.timestamp = time.time()
        self.agent_name = ""
        self.trigger = {}
        self.observation = ""
        self.hypothesis = ""
        self.evidence = []
        self.verdict = "BENIGN"       # THREAT | SUSPICIOUS | BENIGN
        self.confidence = 0.0
        self.recommended_action = "DISMISS"  # ESCALATE | WATCH | DISMISS
        self.reasoning = ""

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "agent": self.agent_name,
            "trigger_type": self.trigger.get("type", "unknown"),
            "trigger_classification": self.trigger.get("classification", "UNKNOWN"),
            "observation": self.observation,
            "hypothesis": self.hypothesis,
            "evidence_count": len(self.evidence),
            "verdict": self.verdict,
            "confidence": round(self.confidence, 3),
            "action": self.recommended_action,
            "reasoning": self.reasoning,
        }


def _pattern_hash(trigger):
    """Create a stable hash for a trigger pattern (type + classification + caller)."""
    key = f"{trigger.get('type', '')}:{trigger.get('classification', '')}:{trigger.get('caller_file', '')}"
    return hashlib.md5(key.encode()).hexdigest()[:12]


# ═══════════════════════════════════════════════════════════
# BUILT-IN RULE-BASED REASONING
# ═══════════════════════════════════════════════════════════

_HYPOTHESES = {
    ("import", "SUSPICIOUS"):    "Possible malicious package injection",
    ("import", "UNEXPECTED"):    "Unrecognized module loaded — may indicate dependency drift or injection",
    ("file", "SUSPICIOUS"):      "Access to sensitive system path — possible credential theft or config tampering",
    ("file", "UNEXPECTED"):      "Unexpected file access — possible code drop or data staging",
    ("network", "UNEXPECTED"):   "Outbound connection to unknown host — possible C2 communication or exfiltration",
    ("network", "SUSPICIOUS"):   "Connection to suspicious host — possible command-and-control",
    ("subprocess", "UNEXPECTED"): "Unexpected process execution — possible shell injection or lateral movement",
    ("subprocess", "SUSPICIOUS"): "Dangerous command pattern detected — possible destructive action",
}

_COMBO_HYPOTHESES = [
    ({"import", "subprocess"}, "Suspicious import followed by process execution — possible code execution chain"),
    ({"file", "network"},      "File access followed by network activity — possible data exfiltration"),
    ({"import", "file"},       "Import of suspicious module followed by file access — possible payload drop"),
]


class XenobotAgent:
    """Autonomous security agent using 5-phase investigation cycle."""

    COOLDOWN_SECONDS = 60.0

    def __init__(self, name, domain=None, reasoning_fn=None):
        self.name = name
        self.domain = domain
        self.reasoning_fn = reasoning_fn
        self.findings = deque(maxlen=500)
        self.behavioral_model = {}   # pattern_hash -> {count, first_seen, last_seen, verdict}
        self.cooldown = {}           # trigger_type -> last_investigated_time
        self.stats = {"investigations": 0, "findings": 0,
                      "false_positives_marked": 0, "model_updates": 0}

    def investigate(self, trigger, context) -> Investigation:
        """Run the full 5-phase cycle on a trigger event."""
        inv = Investigation()
        inv.agent_name = self.name
        inv.trigger = trigger

        # Domain filter
        if self.domain and trigger.get("type") != self.domain:
            inv.verdict = "BENIGN"
            inv.confidence = 0.0
            inv.reasoning = f"Outside domain ({self.domain})"
            inv.recommended_action = "DISMISS"
            return inv

        # Cooldown check
        trigger_key = f"{trigger.get('type', '')}:{trigger.get('classification', '')}"
        now = time.time()
        last = self.cooldown.get(trigger_key, 0)
        if now - last < self.COOLDOWN_SECONDS:
            inv.verdict = "BENIGN"
            inv.confidence = 0.0
            inv.reasoning = "Cooldown active — recently investigated same trigger type"
            inv.recommended_action = "DISMISS"
            return inv
        self.cooldown[trigger_key] = now

        # Phase 1: OBSERVE
        inv.observation = self._observe(trigger, context)

        # Phase 2: QUESTION
        inv.hypothesis = self._question(trigger, context)

        # Phase 3: SEARCH
        inv.evidence = self._search(trigger, context)

        # Phase 4: SYNTHESIZE
        inv.verdict, inv.confidence, inv.reasoning = self._synthesize(trigger, context, inv.evidence)

        # Phase 5: CRYSTALLIZE
        inv.recommended_action = self._crystallize(inv, trigger)

        self.stats["investigations"] += 1
        return inv

    def _observe(self, trigger, context):
        """Phase 1: Extract key facts."""
        etype = trigger.get("type", "unknown")
        classification = trigger.get("classification", "UNKNOWN")
        caller = trigger.get("caller_file", "unknown")
        detail = trigger.get("detail", {})

        # Get module voltage if available
        voltage_state = context.get("voltage_state", {})
        modules = voltage_state.get("modules", {})
        import os
        mod_name = os.path.splitext(os.path.basename(caller))[0] if caller != "unknown" else "unknown"
        mod_info = modules.get(mod_name, {})
        voltage = mod_info.get("voltage", 1.0)

        # Check behavioral model
        phash = _pattern_hash(trigger)
        known = phash in self.behavioral_model

        parts = [
            f"{etype} event from {mod_name}",
            f"classified as {classification}",
            f"module voltage: {voltage:.2f}",
        ]
        if detail:
            detail_str = ", ".join(f"{k}={v}" for k, v in list(detail.items())[:3])
            parts.append(f"detail: {detail_str}")
        if known:
            prev = self.behavioral_model[phash]
            parts.append(f"pattern seen {prev['count']}x before (verdict: {prev['verdict']})")
        else:
            parts.append("novel pattern — not in behavioral model")

        return "; ".join(parts)

    def _question(self, trigger, context):
        """Phase 2: Generate investigation hypothesis."""
        if self.reasoning_fn:
            try:
                return self.reasoning_fn("question", trigger, context)
            except Exception:
                pass

        etype = trigger.get("type", "")
        classification = trigger.get("classification", "")

        # Check for known pattern marked BENIGN
        phash = _pattern_hash(trigger)
        if phash in self.behavioral_model and self.behavioral_model[phash]["verdict"] == "BENIGN":
            return "Known pattern previously marked BENIGN — likely false positive"

        # Direct type+classification match
        hyp = _HYPOTHESES.get((etype, classification))
        if hyp:
            return hyp

        # Check voltage context
        voltage_state = context.get("voltage_state", {})
        drops = voltage_state.get("drops", [])
        if drops:
            return f"Behavioral anomaly with voltage drops in {len(drops)} module(s) — possible cascading compromise"

        return f"Unexpected {etype} event with {classification} classification — needs investigation"

    def _search(self, trigger, context):
        """Phase 3: Gather evidence from context."""
        evidence = []
        caller = trigger.get("caller_file", "unknown")
        import os
        mod_name = os.path.splitext(os.path.basename(caller))[0] if caller != "unknown" else "unknown"

        # Recent events from same module
        recent = context.get("recent_events", [])
        same_module = [e for e in recent if mod_name in str(e.get("caller_file", ""))][-10:]
        if same_module:
            evidence.append({
                "type": "recent_module_events",
                "count": len(same_module),
                "classifications": _count_field(same_module, "classification"),
            })

        # Voltage history
        voltage_state = context.get("voltage_state", {})
        mod_info = voltage_state.get("modules", {}).get(mod_name, {})
        if mod_info:
            evidence.append({
                "type": "module_voltage",
                "voltage": mod_info.get("voltage", 1.0),
                "event_count": mod_info.get("event_count", 0),
                "has_baseline": mod_info.get("has_baseline", False),
            })

        # Connections
        graph = context.get("connection_graph", {})
        connected = graph.get(mod_name, [])
        if connected:
            evidence.append({
                "type": "connections",
                "connected_modules": connected[:10],
            })

        # Existing alerts
        alerts = context.get("alerts", [])
        related = [a for a in alerts if mod_name in str(a)]
        if related:
            evidence.append({
                "type": "existing_alerts",
                "count": len(related),
            })

        # Behavioral model entry
        phash = _pattern_hash(trigger)
        if phash in self.behavioral_model:
            entry = self.behavioral_model[phash]
            evidence.append({
                "type": "behavioral_model",
                "pattern_hash": phash,
                "seen_count": entry["count"],
                "previous_verdict": entry["verdict"],
            })

        return evidence

    def _synthesize(self, trigger, context, evidence):
        """Phase 4: Form verdict with confidence score."""
        if self.reasoning_fn:
            try:
                result = self.reasoning_fn("synthesize", trigger, context, evidence)
                if isinstance(result, tuple) and len(result) == 3:
                    return result
            except Exception:
                pass

        score = 0.0
        reasons = []

        classification = trigger.get("classification", "UNKNOWN")
        if classification == "SUSPICIOUS":
            score += 0.3
            reasons.append("+0.3 suspicious classification")
        elif classification == "UNEXPECTED":
            score += 0.2
            reasons.append("+0.2 unexpected classification")

        # Voltage check
        voltage_state = context.get("voltage_state", {})
        caller = trigger.get("caller_file", "unknown")
        import os
        mod_name = os.path.splitext(os.path.basename(caller))[0] if caller != "unknown" else "unknown"
        mod_info = voltage_state.get("modules", {}).get(mod_name, {})
        voltage = mod_info.get("voltage", 1.0)

        if voltage < 0.5:
            score += 0.2
            reasons.append(f"+0.2 low voltage ({voltage:.2f})")
        elif voltage > 0.8:
            score -= 0.2
            reasons.append(f"-0.2 healthy module ({voltage:.2f})")

        # Connected module voltage drops
        drops = voltage_state.get("drops", [])
        if drops:
            score += 0.1
            reasons.append(f"+0.1 voltage drops in {len(drops)} connected module(s)")

        # Novelty
        phash = _pattern_hash(trigger)
        if phash not in self.behavioral_model:
            score += 0.1
            reasons.append("+0.1 novel pattern")
        elif self.behavioral_model[phash]["verdict"] == "BENIGN":
            score -= 0.3
            reasons.append("-0.3 previously marked BENIGN")

        score = max(0.0, min(1.0, score))

        if score > 0.5:
            verdict = "THREAT"
        elif score > 0.3:
            verdict = "SUSPICIOUS"
        else:
            verdict = "BENIGN"

        reasoning = f"Score {score:.2f}: " + "; ".join(reasons)
        return verdict, score, reasoning

    def _crystallize(self, inv, trigger):
        """Phase 5: Record finding and update model."""
        self.findings.append(inv)
        self.stats["findings"] += 1

        # Update behavioral model
        phash = _pattern_hash(trigger)
        if phash in self.behavioral_model:
            entry = self.behavioral_model[phash]
            entry["count"] += 1
            entry["last_seen"] = time.time()
            entry["verdict"] = inv.verdict
        else:
            self.behavioral_model[phash] = {
                "count": 1,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "verdict": inv.verdict,
            }
        self.stats["model_updates"] += 1

        if inv.verdict == "BENIGN":
            self.stats["false_positives_marked"] += 1

        # Determine action
        if inv.verdict == "THREAT":
            return "ESCALATE"
        elif inv.verdict == "SUSPICIOUS":
            return "WATCH"
        else:
            return "DISMISS"


def _count_field(events, field):
    """Count occurrences of each value for a field across events."""
    counts = {}
    for e in events:
        v = e.get(field, "UNKNOWN")
        counts[v] = counts.get(v, 0) + 1
    return counts
