"""Per-module behavioral coherence field.

Inspired by Levin bioelectrics: each module has a voltage representing
behavioral health. Deviation from baseline = voltage drop. Silence is
suspicious too — modules that go quiet start decaying.
"""

import os
import time
from collections import Counter, deque


class ModuleVoltage:
    """Track behavioral voltage for a single module."""

    UNEXPECTED_DROP = 0.05
    SUSPICIOUS_DROP = 0.15
    NOVEL_TYPE_DROP = 0.10
    RECOVERY_RATE = 0.02
    DECAY_RATE = 0.01
    SILENCE_THRESHOLD = 60.0  # seconds before decay starts

    def __init__(self, name: str):
        self.name = name
        self.voltage = 1.0
        self.event_count = 0
        self.event_profile = Counter()       # event type -> count
        self.classification_profile = Counter()  # classification -> count
        self.last_seen = time.time()
        self.voltage_history = deque(maxlen=100)
        self._has_baseline = False

    def record_event(self, event: dict, baseline_profile: dict = None) -> float:
        """Record event, adjust voltage, return new voltage."""
        self.event_count += 1
        self.last_seen = time.time()

        etype = event.get("type", "unknown")
        classification = event.get("classification", "UNKNOWN")
        self.event_profile[etype] += 1
        self.classification_profile[classification] += 1

        if baseline_profile is not None:
            self._has_baseline = True
            baseline_types = baseline_profile.get("event_types", set())
            baseline_classes = baseline_profile.get("classifications", {})

            if classification == "SUSPICIOUS":
                self.voltage = max(0.0, self.voltage - self.SUSPICIOUS_DROP)
            elif classification == "UNEXPECTED":
                self.voltage = max(0.0, self.voltage - self.UNEXPECTED_DROP)
            elif etype not in baseline_types and baseline_types:
                self.voltage = max(0.0, self.voltage - self.NOVEL_TYPE_DROP)
            else:
                # Normal event — recover toward 1.0
                self.voltage = min(1.0, self.voltage + self.RECOVERY_RATE)
        # No baseline yet (learning phase): voltage stays at 1.0, just record

        self.voltage_history.append((time.time(), self.voltage))
        return self.voltage

    def apply_decay(self, current_time: float) -> float:
        """Decay voltage if module has been silent too long."""
        silence = current_time - self.last_seen
        if silence > self.SILENCE_THRESHOLD:
            decay_cycles = (silence - self.SILENCE_THRESHOLD) / self.SILENCE_THRESHOLD
            decay = min(self.DECAY_RATE * decay_cycles, 0.5)  # Cap decay at 0.5
            self.voltage = max(0.0, self.voltage - decay)
            self.voltage_history.append((current_time, self.voltage))
        return self.voltage

    def drop_voltage(self, amount: float) -> float:
        """External voltage drop (e.g., from propagation)."""
        self.voltage = max(0.0, self.voltage - amount)
        self.voltage_history.append((time.time(), self.voltage))
        return self.voltage

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "voltage": round(self.voltage, 4),
            "event_count": self.event_count,
            "last_seen": self.last_seen,
            "has_baseline": self._has_baseline,
        }


class VoltageField:
    """Per-module behavioral coherence field.

    Every monitored module gets a voltage (0.0-1.0). Deviations from
    baseline behavior drop voltage. Consistent behavior recovers it.
    Field coherence = mean of all module voltages.
    """

    def __init__(self):
        self.modules: dict = {}                  # name -> ModuleVoltage
        self.baseline_profiles: dict = {}        # name -> profile dict
        self.field_coherence: float = 1.0
        self.history: deque = deque(maxlen=1000)  # (timestamp, coherence)

    @staticmethod
    def _module_name(caller_file: str) -> str:
        """Extract module name from caller file path."""
        if not caller_file or caller_file == "unknown":
            return "unknown"
        base = os.path.basename(caller_file)
        name, _ = os.path.splitext(base)
        return name

    def update(self, events: list) -> dict:
        """Process events and update all module voltages."""
        updated = set()
        drops = []
        recoveries = []

        for event in events:
            mod_name = self._module_name(event.get("caller_file", "unknown"))
            if mod_name not in self.modules:
                self.modules[mod_name] = ModuleVoltage(mod_name)

            mv = self.modules[mod_name]
            old_v = mv.voltage
            baseline = self.baseline_profiles.get(mod_name)
            new_v = mv.record_event(event, baseline)
            updated.add(mod_name)

            if new_v < old_v - 0.001:
                drops.append({"module": mod_name, "from": round(old_v, 4),
                              "to": round(new_v, 4), "drop": round(old_v - new_v, 4)})
            elif new_v > old_v + 0.001:
                recoveries.append({"module": mod_name, "from": round(old_v, 4),
                                   "to": round(new_v, 4)})

        # Apply decay to modules not seen in this batch
        now = time.time()
        for name, mv in self.modules.items():
            if name not in updated:
                mv.apply_decay(now)

        # Recalculate field coherence
        if self.modules:
            self.field_coherence = sum(mv.voltage for mv in self.modules.values()) / len(self.modules)
        else:
            self.field_coherence = 1.0

        self.history.append((now, self.field_coherence))

        return {
            "field_coherence": round(self.field_coherence, 4),
            "modules_updated": len(updated),
            "voltage_drops": drops,
            "voltage_recoveries": recoveries,
        }

    def get_module_voltage(self, module_name: str) -> float:
        """Get current voltage for a specific module."""
        mv = self.modules.get(module_name)
        return mv.voltage if mv else -1.0

    def get_field_state(self) -> dict:
        """Return complete field state."""
        modules_data = {}
        drops = []
        critical = []

        for name, mv in self.modules.items():
            modules_data[name] = mv.to_dict()
            if mv.voltage < 0.7:
                drops.append(name)
            if mv.voltage < 0.4:
                critical.append(name)

        return {
            "field_coherence": round(self.field_coherence, 4),
            "module_count": len(self.modules),
            "modules": modules_data,
            "drops": drops,
            "critical": critical,
        }

    def get_voltage_history(self, n: int = 100) -> list:
        """Return last n field coherence readings."""
        items = list(self.history)
        return [{"timestamp": t, "coherence": round(c, 4)} for t, c in items[-n:]]

    def set_baseline(self, module_name: str, profile: dict) -> None:
        """Manually set baseline for a module."""
        self.baseline_profiles[module_name] = profile

    def auto_baseline(self, events: list, min_events: int = 500) -> dict:
        """Generate baselines from event history for modules with enough data.

        Profile per module:
        - event_types: set of normal event types
        - classifications: Counter of classification distribution
        - event_rate: events per minute
        """
        # Group events by module
        by_module = {}
        for e in events:
            mod = self._module_name(e.get("caller_file", "unknown"))
            by_module.setdefault(mod, []).append(e)

        generated = {}
        for mod, mod_events in by_module.items():
            if len(mod_events) < min_events:
                continue

            types = set(e.get("type", "unknown") for e in mod_events)
            classifications = Counter(e.get("classification", "UNKNOWN") for e in mod_events)

            timestamps = sorted(e.get("timestamp", 0) for e in mod_events)
            duration = max(0.001, timestamps[-1] - timestamps[0])
            rate = len(mod_events) / (duration / 60.0)

            profile = {
                "event_types": types,
                "classifications": dict(classifications),
                "event_rate_per_minute": round(rate, 2),
                "sample_size": len(mod_events),
            }
            self.baseline_profiles[mod] = profile
            generated[mod] = profile

        return generated
