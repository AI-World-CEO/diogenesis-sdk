"""Diogenesis engine — singleton orchestrator for all interceptors."""

import time

from .core.event_buffer import EventBuffer
from .core.classifier import Classifier
from .core.config import load_config
from .baseline import generate_baseline
from .interceptors.import_hook import ImportHook
from .interceptors.file_hook import FileHook
from .interceptors.subprocess_hook import SubprocessHook
from .interceptors.network_hook import NetworkHook
from .policy.engine import PolicyEngine
from .policy.response import GraduatedResponse
from .field.voltage import VoltageField
from .field.propagation import VoltagePropagation
from .agents.swarm import XenobotSwarm


class DiogenesisEngine:
    """Main engine that manages all interceptors, policy, voltage field, and xenobot swarm."""

    def __init__(self):
        self._active = False
        self._config = None
        self._buffer = None
        self._classifier = None
        self._hooks = []
        self._start_time = None
        self._policy = PolicyEngine()
        self._response = GraduatedResponse()
        self._voltage_field = VoltageField()
        self._propagation = VoltagePropagation()
        self._swarm = XenobotSwarm()
        self._last_auto_eval_total = 0
        self._last_voltage_update_total = 0

    def activate(self, config=None) -> dict:
        """Activate all enabled interceptors."""
        if self._active:
            return {"status": "already_active", "interceptors": len(self._hooks)}

        self._config = load_config(config_dict=config)

        if not self._config.get("enabled", True):
            return {"status": "disabled_by_config"}

        self._buffer = EventBuffer(maxlen=self._config.get("buffer_size", 10000))
        self._classifier = Classifier(self._config)
        self._hooks = []
        self._start_time = time.time()
        self._policy = PolicyEngine()
        self._response = GraduatedResponse()
        self._voltage_field = VoltageField()
        self._propagation = VoltagePropagation()
        self._swarm = XenobotSwarm()
        self._swarm.create_default_swarm()
        self._last_auto_eval_total = 0
        self._last_voltage_update_total = 0

        interceptor_config = self._config.get("interceptors", {})

        if interceptor_config.get("import", True):
            hook = ImportHook(self._buffer, self._classifier)
            hook.activate()
            self._hooks.append(hook)

        if interceptor_config.get("file", True):
            hook = FileHook(self._buffer, self._classifier)
            hook.activate()
            self._hooks.append(hook)

        if interceptor_config.get("subprocess", True):
            hook = SubprocessHook(self._buffer, self._classifier)
            hook.activate()
            self._hooks.append(hook)

        if interceptor_config.get("network", True):
            hook = NetworkHook(self._buffer, self._classifier)
            hook.activate()
            self._hooks.append(hook)

        self._active = True
        return {
            "status": "activated",
            "interceptors": len(self._hooks),
            "buffer_capacity": self._buffer.capacity,
        }

    def deactivate(self) -> dict:
        """Deactivate all interceptors and restore originals."""
        if not self._active:
            return {"status": "not_active"}

        for hook in reversed(self._hooks):
            try:
                hook.deactivate()
            except Exception:
                pass

        self._active = False
        count = len(self._hooks)
        self._hooks = []
        return {"status": "deactivated", "interceptors_removed": count}

    def _maybe_auto_evaluate(self):
        """Run policy + voltage evaluation if buffer grew enough."""
        if not self._config:
            return
        current_total = self._buffer.total

        # Policy evaluation every 100 events
        if self._config.get("auto_evaluate", True):
            if current_total - self._last_auto_eval_total >= 100:
                self._run_policy_eval()
                self._last_auto_eval_total = current_total

        # Voltage field update every 50 events
        if current_total - self._last_voltage_update_total >= 50:
            self._update_voltage_field()
            self._last_voltage_update_total = current_total

    def _build_context(self):
        """Build investigation context dict for xenobot agents."""
        return {
            "recent_events": self._buffer.get_recent(200) if self._buffer else [],
            "voltage_state": self._voltage_field.get_field_state(),
            "baseline": self.baseline(),
            "connection_graph": self._propagation.get_connection_graph(),
            "alerts": self._policy.get_alerts(50),
        }

    def _run_policy_eval(self):
        """Evaluate policies against recent buffer."""
        events = self._buffer.get_recent(500)
        new_alerts = self._policy.evaluate(events)
        for alert in new_alerts:
            matched = alert.get("matched_events", [])
            source = matched[0].get("caller_file", "unknown") if matched else "unknown"
            self._response.record_violation(source, alert)
            # Drop voltage on source module
            mod_name = VoltageField._module_name(source)
            mv = self._voltage_field.modules.get(mod_name)
            if mv:
                drop = 0.20 if alert.get("severity") == "CRITICAL" else 0.10
                mv.drop_voltage(drop)
                self._propagation.propagate(self._voltage_field, mod_name, drop)
            # Dispatch xenobot swarm to investigate
            try:
                context = self._build_context()
                self._swarm.respond_to_alert(alert, context)
            except Exception:
                pass

    def _update_voltage_field(self):
        """Feed recent events to the voltage field."""
        events = self._buffer.get_recent(200)
        if events:
            result = self._voltage_field.update(events)
            # Propagate any drops
            for drop_info in result.get("voltage_drops", []):
                self._propagation.propagate(
                    self._voltage_field, drop_info["module"], drop_info["drop"])
            # Learn connections from events
            self._propagation.learn_connections(events)
            # Investigate modules with critically low voltage
            try:
                fs = self._voltage_field.get_field_state()
                for mod_name in fs.get("critical", []):
                    mod = self._voltage_field.modules.get(mod_name)
                    if mod:
                        context = self._build_context()
                        self._swarm.respond_to_voltage_drop(mod_name, mod.voltage, context)
            except Exception:
                pass

    def status(self) -> dict:
        """Return current engine status and event counts."""
        if not self._active or self._buffer is None:
            return {
                "active": False,
                "interceptors": 0,
                "counts": {},
                "total_events": 0,
                "buffer_size": 0,
                "buffer_capacity": 0,
                "uptime_seconds": 0,
                "policy_alerts": 0,
                "escalations": 0,
                "field_coherence": 1.0,
                "modules_tracked": 0,
                "voltage_drops_active": 0,
            }

        self._maybe_auto_evaluate()

        counts = self._buffer.counts
        total = self._buffer.total
        uptime = time.time() - self._start_time if self._start_time else 0

        recent = self._buffer.get_recent(1000)
        class_counts = {}
        for e in recent:
            c = e.get("classification", "UNKNOWN")
            class_counts[c] = class_counts.get(c, 0) + 1

        fs = self._voltage_field.get_field_state()

        return {
            "active": True,
            "interceptors": len(self._hooks),
            "interceptor_names": [h.name for h in self._hooks],
            "counts": counts,
            "total_events": total,
            "buffer_size": len(self._buffer),
            "buffer_capacity": self._buffer.capacity,
            "uptime_seconds": round(uptime, 1),
            "classification_summary": class_counts,
            "policy_alerts": len(self._policy.get_alerts(1000)),
            "escalations": len(self._response.get_escalations()),
            "field_coherence": fs["field_coherence"],
            "modules_tracked": fs["module_count"],
            "voltage_drops_active": len(fs["drops"]),
        }

    def log(self, n: int = 100) -> list:
        """Return last n events."""
        if self._buffer is None:
            return []
        return self._buffer.get_recent(n)

    def baseline(self) -> dict:
        """Generate behavioral baseline from accumulated events."""
        if self._buffer is None:
            return {"status": "NOT_ACTIVE"}
        return generate_baseline(self._buffer.get_all())

    def configure(self, config_dict: dict) -> dict:
        """Update configuration."""
        self._config = load_config(config_dict=config_dict)
        if self._classifier:
            self._classifier = Classifier(self._config)
        return {"status": "configured", "config": self._config}

    def alerts(self, n: int = 50) -> list:
        """Return last n policy alerts."""
        return self._policy.get_alerts(n)

    def alert_summary(self) -> dict:
        """Return pattern trigger counts."""
        return self._policy.get_alert_summary()

    def escalations(self) -> list:
        """Return all escalated sources (level >= 2)."""
        return self._response.get_escalations()

    def add_pattern(self, pattern) -> None:
        """Add a custom behavioral pattern."""
        self._policy.add_pattern(pattern)

    def evaluate_policies(self) -> list:
        """Manually trigger policy evaluation against current buffer."""
        if self._buffer is None:
            return []
        self._run_policy_eval()
        return self._policy.get_alerts(50)

    def field_state(self) -> dict:
        """Return complete voltage field state."""
        return self._voltage_field.get_field_state()

    def module_voltage(self, name: str) -> float:
        """Get voltage for a specific module."""
        return self._voltage_field.get_module_voltage(name)

    def voltage_history(self, n: int = 100) -> list:
        """Return field coherence history."""
        return self._voltage_field.get_voltage_history(n)

    def connection_graph(self) -> dict:
        """Return module connection map."""
        return self._propagation.get_connection_graph()

    def create_scheduler(self):
        """Create a DiogenesisScheduler wired to this engine.

        Returns a scheduler with 5 default agents on Fibonacci timing.
        Call scheduler.tick() in your loop or scheduler.run_continuous().
        """
        from .timing.scheduler import DiogenesisScheduler
        self._scheduler = DiogenesisScheduler(self)
        return self._scheduler

    def get_scheduler(self):
        """Return existing scheduler or None."""
        return getattr(self, "_scheduler", None)

    def investigations(self, n: int = 50) -> list:
        """Return recent xenobot investigations."""
        return self._swarm.get_findings(n)

    def threat_summary(self) -> dict:
        """Return swarm threat summary."""
        return self._swarm.get_threat_summary()

    def add_agent(self, agent) -> None:
        """Add a custom xenobot agent to the swarm."""
        self._swarm.add_agent(agent)
