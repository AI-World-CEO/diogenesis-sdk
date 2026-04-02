"""Xenobot swarm — coordinate multiple autonomous investigation agents."""

import os
from collections import deque

from .xenobot import XenobotAgent, Investigation


class XenobotSwarm:
    """Coordinate multiple xenobot agents. Each specializes in a domain."""

    def __init__(self):
        self.agents = {}
        self.investigation_log = deque(maxlen=2000)
        self.shared_model = {}

    def create_default_swarm(self):
        """Create the standard 4-agent swarm."""
        self.agents = {
            "import_guardian": XenobotAgent("import_guardian", domain="import"),
            "file_sentinel": XenobotAgent("file_sentinel", domain="file"),
            "network_watcher": XenobotAgent("network_watcher", domain="network"),
            "subprocess_monitor": XenobotAgent("subprocess_monitor", domain="subprocess"),
        }

    def add_agent(self, agent):
        """Add a custom agent to the swarm."""
        self.agents[agent.name] = agent

    def remove_agent(self, name):
        """Remove an agent by name."""
        self.agents.pop(name, None)

    def respond_to_alert(self, alert, context) -> list:
        """Dispatch appropriate agent(s) to investigate an alert."""
        results = []
        matched_events = alert.get("matched_events", [])
        event_types = set()
        for evt in matched_events:
            event_types.add(evt.get("type", "unknown"))

        # Find agents whose domain matches any event type in the alert
        dispatched = set()
        for etype in event_types:
            for name, agent in self.agents.items():
                if agent.domain == etype and name not in dispatched:
                    dispatched.add(name)
                    # Use the first event of this agent's domain as trigger
                    trigger = next((e for e in matched_events if e.get("type") == etype), matched_events[0])
                    inv = agent.investigate(trigger, context)
                    self.investigation_log.append(inv)
                    results.append(inv)

        # If no domain-specific agent matched, use first available agent
        if not results and self.agents and matched_events:
            agent = next(iter(self.agents.values()))
            inv = agent.investigate(matched_events[0], context)
            self.investigation_log.append(inv)
            results.append(inv)

        return results

    def respond_to_voltage_drop(self, module_name, voltage, context) -> Investigation:
        """Investigate a module with dangerously low voltage."""
        # Determine the module's primary event type from recent events
        recent = context.get("recent_events", [])
        module_events = [e for e in recent if module_name in str(e.get("caller_file", ""))]

        # Count event types for this module
        type_counts = {}
        for e in module_events[-50:]:
            t = e.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        primary_type = max(type_counts, key=type_counts.get) if type_counts else "unknown"

        # Find the right agent
        agent = None
        for a in self.agents.values():
            if a.domain == primary_type:
                agent = a
                break
        if agent is None and self.agents:
            agent = next(iter(self.agents.values()))
        if agent is None:
            inv = Investigation()
            inv.agent_name = "none"
            inv.verdict = "SUSPICIOUS"
            inv.reasoning = "No agents available"
            return inv

        # Create a synthetic trigger for the voltage drop
        trigger = {
            "type": primary_type,
            "classification": "UNEXPECTED",
            "caller_file": f"{module_name}.py",
            "detail": {"voltage_drop": True, "voltage": voltage, "module": module_name},
        }
        inv = agent.investigate(trigger, context)
        self.investigation_log.append(inv)
        return inv

    def get_findings(self, n=50, verdict=None) -> list:
        """Return recent findings, optionally filtered by verdict."""
        items = list(self.investigation_log)
        if verdict:
            items = [i for i in items if i.verdict == verdict]
        return [i.to_dict() if hasattr(i, "to_dict") else i for i in items[-n:]]

    def get_threat_summary(self) -> dict:
        """Count of threats, suspicious, benign across the swarm."""
        items = list(self.investigation_log)
        counts = {"THREAT": 0, "SUSPICIOUS": 0, "BENIGN": 0}
        for inv in items:
            v = inv.verdict if hasattr(inv, "verdict") else "UNKNOWN"
            counts[v] = counts.get(v, 0) + 1

        agent_stats = {}
        for name, agent in self.agents.items():
            agent_stats[name] = dict(agent.stats)

        return {
            "threats": counts.get("THREAT", 0),
            "suspicious": counts.get("SUSPICIOUS", 0),
            "benign": counts.get("BENIGN", 0),
            "total_investigations": len(items),
            "agents": agent_stats,
        }

    def share_learning(self):
        """Sync behavioral models across all agents.

        When one agent learns a pattern is BENIGN, all agents learn it.
        When one agent identifies a THREAT pattern, all agents watch for it.
        """
        # Merge all agent models into shared model
        for agent in self.agents.values():
            for phash, entry in agent.behavioral_model.items():
                existing = self.shared_model.get(phash)
                if existing is None or entry["last_seen"] > existing["last_seen"]:
                    self.shared_model[phash] = dict(entry)

        # Distribute shared model back to all agents
        for agent in self.agents.values():
            for phash, entry in self.shared_model.items():
                if phash not in agent.behavioral_model:
                    agent.behavioral_model[phash] = dict(entry)
                else:
                    existing = agent.behavioral_model[phash]
                    if entry["last_seen"] > existing["last_seen"]:
                        existing["verdict"] = entry["verdict"]
                        existing["last_seen"] = entry["last_seen"]
