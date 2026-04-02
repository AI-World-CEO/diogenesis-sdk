import time
import unittest

from diogenesis_sdk.agents.xenobot import XenobotAgent
from diogenesis_sdk.agents.swarm import XenobotSwarm


def _alert(event_types=None):
    """Create a synthetic policy alert."""
    events = []
    for etype in (event_types or ["import"]):
        events.append({
            "type": etype, "classification": "SUSPICIOUS",
            "caller_file": "evil.py", "caller_line": 1,
            "caller_func": "hack", "detail": {}, "timestamp": time.time(),
        })
    return {
        "pattern_name": "test_alert",
        "severity": "CRITICAL",
        "matched_events": events,
        "timestamp": time.time(),
    }


def _context():
    return {
        "recent_events": [],
        "voltage_state": {"field_coherence": 0.5, "modules": {}, "drops": [], "critical": []},
        "baseline": {"status": "ACCUMULATING"},
        "connection_graph": {},
        "alerts": [],
    }


class TestSwarm(unittest.TestCase):

    def test_default_swarm(self):
        swarm = XenobotSwarm()
        swarm.create_default_swarm()
        self.assertEqual(len(swarm.agents), 4)
        domains = {a.domain for a in swarm.agents.values()}
        self.assertEqual(domains, {"import", "file", "network", "subprocess"})

    def test_respond_to_alert(self):
        swarm = XenobotSwarm()
        swarm.create_default_swarm()
        results = swarm.respond_to_alert(_alert(["import"]), _context())
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0].agent_name, "import_guardian")

    def test_respond_to_voltage_drop(self):
        swarm = XenobotSwarm()
        swarm.create_default_swarm()
        ctx = _context()
        ctx["recent_events"] = [
            {"type": "file", "caller_file": "bad.py", "classification": "UNEXPECTED",
             "timestamp": time.time(), "detail": {}}
        ] * 10
        inv = swarm.respond_to_voltage_drop("bad", 0.3, ctx)
        self.assertIsNotNone(inv)
        self.assertEqual(inv.agent_name, "file_sentinel")

    def test_multi_agent_dispatch(self):
        swarm = XenobotSwarm()
        swarm.create_default_swarm()
        results = swarm.respond_to_alert(_alert(["import", "network"]), _context())
        agents = {r.agent_name for r in results}
        self.assertIn("import_guardian", agents)
        self.assertIn("network_watcher", agents)

    def test_share_learning(self):
        swarm = XenobotSwarm()
        swarm.create_default_swarm()
        # One agent learns a pattern
        ig = swarm.agents["import_guardian"]
        ig.behavioral_model["abc123"] = {
            "count": 3, "first_seen": time.time() - 100,
            "last_seen": time.time(), "verdict": "BENIGN"
        }
        swarm.share_learning()
        # All agents should now have it
        for agent in swarm.agents.values():
            self.assertIn("abc123", agent.behavioral_model)
            self.assertEqual(agent.behavioral_model["abc123"]["verdict"], "BENIGN")

    def test_threat_summary(self):
        swarm = XenobotSwarm()
        swarm.create_default_swarm()
        swarm.respond_to_alert(_alert(["import"]), _context())
        summary = swarm.get_threat_summary()
        self.assertIn("threats", summary)
        self.assertIn("suspicious", summary)
        self.assertIn("benign", summary)
        self.assertGreater(summary["total_investigations"], 0)

    def test_findings_filter(self):
        swarm = XenobotSwarm()
        swarm.create_default_swarm()
        swarm.respond_to_alert(_alert(["import"]), _context())
        all_findings = swarm.get_findings(50)
        self.assertGreater(len(all_findings), 0)
        # Filter by a specific verdict
        threats = swarm.get_findings(50, verdict="THREAT")
        benign = swarm.get_findings(50, verdict="BENIGN")
        # At least one category should have results
        self.assertEqual(len(threats) + len(benign) + len(swarm.get_findings(50, verdict="SUSPICIOUS")),
                         len(all_findings))

    def test_add_remove_agent(self):
        swarm = XenobotSwarm()
        custom = XenobotAgent("custom_agent", domain="network")
        swarm.add_agent(custom)
        self.assertIn("custom_agent", swarm.agents)
        swarm.remove_agent("custom_agent")
        self.assertNotIn("custom_agent", swarm.agents)


if __name__ == "__main__":
    unittest.main()
