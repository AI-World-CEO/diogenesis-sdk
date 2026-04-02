"""High-level scheduler integrating Fibonacci clock with Diogenesis engine."""

import time
import threading

from .fibonacci import FibonacciClock


class DiogenesisScheduler:
    """Runs Diogenesis evaluations on Fibonacci-timed intervals.

    Default agents:
      policy_eval (every 3) — fast policy pattern check
      voltage_update (every 5) — field coherence update
      baseline_check (every 8) — compare to established baseline
      deep_scan (every 13) — full pattern + propagation evaluation
      field_decay (every 21) — apply silence decay to all modules
    """

    def __init__(self, engine, clock=None):
        self.engine = engine
        self.clock = clock or FibonacciClock()
        self._running = False
        self._total_actions = 0
        self._resonance_scans = 0

        # Register default agents
        self.clock.register_agent("policy_eval", 0)      # every 3
        self.clock.register_agent("voltage_update", 1)    # every 5
        self.clock.register_agent("baseline_check", 2)    # every 8
        self.clock.register_agent("deep_scan", 3)         # every 13
        self.clock.register_agent("field_decay", 4)       # every 21

    def tick(self):
        """Advance one cycle and run scheduled agents."""
        result = self.clock.tick()
        actions = []

        for agent_name in result["fires"]:
            action = self._run_agent(agent_name)
            if action:
                actions.append(action)
                self._total_actions += 1

        # Resonance triggers combined deep analysis
        if result["resonance"]:
            self._resonance_scans += 1
            resonance_action = self._run_resonance_scan(result["resonance"])
            if resonance_action:
                actions.append(resonance_action)

        return {
            "cycle": result["cycle"],
            "actions_taken": actions,
            "resonance": result["resonance"],
        }

    def _run_agent(self, name):
        """Execute a single agent's task. Returns action summary or None."""
        try:
            if name == "policy_eval":
                alerts = self.engine.evaluate_policies()
                return {"agent": name, "action": "policy_eval",
                        "new_alerts": len(alerts)}

            elif name == "voltage_update":
                self.engine._update_voltage_field()
                fs = self.engine._voltage_field.get_field_state()
                return {"agent": name, "action": "voltage_update",
                        "field_coherence": fs["field_coherence"],
                        "drops": len(fs["drops"])}

            elif name == "baseline_check":
                bl = self.engine.baseline()
                return {"agent": name, "action": "baseline_check",
                        "status": bl.get("status", "UNKNOWN")}

            elif name == "deep_scan":
                alerts = self.engine.evaluate_policies()
                self.engine._update_voltage_field()
                events = self.engine.log(500)
                if events:
                    self.engine._propagation.learn_connections(events)
                return {"agent": name, "action": "deep_scan",
                        "alerts": len(alerts),
                        "connections": len(self.engine._propagation.connections)}

            elif name == "field_decay":
                now = time.time()
                for mv in self.engine._voltage_field.modules.values():
                    mv.apply_decay(now)
                return {"agent": name, "action": "field_decay",
                        "modules_decayed": len(self.engine._voltage_field.modules)}

        except Exception:
            return {"agent": name, "action": "error"}
        return None

    def _run_resonance_scan(self, resonance):
        """Deep combined analysis on resonance events."""
        try:
            # Full evaluation: policies + voltage + propagation + escalation check
            alerts = self.engine.evaluate_policies()
            self.engine._update_voltage_field()
            escalations = self.engine.escalations()
            fs = self.engine._voltage_field.get_field_state()
            return {
                "agent": "resonance_scan",
                "action": "combined_deep_analysis",
                "resonance_type": resonance["type"],
                "alerts": len(alerts),
                "escalations": len(escalations),
                "field_coherence": fs["field_coherence"],
                "critical_modules": fs["critical"],
            }
        except Exception:
            return {"agent": "resonance_scan", "action": "error"}

    def run_continuous(self, interval_seconds=1.0, max_cycles=None):
        """Run the scheduler in a loop.

        Args:
            interval_seconds: time between ticks
            max_cycles: stop after N cycles (None = run until stopped)
        """
        self._running = True
        cycles_run = 0
        try:
            while self._running:
                self.tick()
                cycles_run += 1
                if max_cycles is not None and cycles_run >= max_cycles:
                    break
                time.sleep(interval_seconds)
        finally:
            self._running = False

    def stop(self):
        """Signal the continuous loop to stop."""
        self._running = False

    def get_status(self):
        """Return scheduler status."""
        schedule = self.clock.get_schedule()
        return {
            "running": self._running,
            "cycle": self.clock.cycle,
            "agents_registered": len(self.clock.agents),
            "total_actions": self._total_actions,
            "resonance_scans": self._resonance_scans,
            "next_3way": schedule.get("next_3way"),
            "next_5way": schedule.get("next_5way"),
            "phase_coherence": self.clock.phase_coherence(),
        }
