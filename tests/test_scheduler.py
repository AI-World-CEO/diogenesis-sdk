import unittest

from diogenesis_sdk.engine import DiogenesisEngine
from diogenesis_sdk.timing.scheduler import DiogenesisScheduler


class TestScheduler(unittest.TestCase):

    def setUp(self):
        self.engine = DiogenesisEngine()
        self.engine.activate({"interceptors": {"import": False, "file": False,
                                               "subprocess": False, "network": False}})

    def tearDown(self):
        if self.engine._active:
            self.engine.deactivate()

    def test_default_agents(self):
        sched = DiogenesisScheduler(self.engine)
        self.assertEqual(len(sched.clock.agents), 5)
        names = set(sched.clock.agents.keys())
        self.assertEqual(names, {"policy_eval", "voltage_update", "baseline_check",
                                  "deep_scan", "field_decay"})

    def test_tick_runs_agents(self):
        sched = DiogenesisScheduler(self.engine)
        # Run 3 ticks — policy_eval fires at cycle 3
        for _ in range(3):
            result = sched.tick()
        self.assertGreater(len(result["actions_taken"]), 0)
        agent_names = [a["agent"] for a in result["actions_taken"]]
        self.assertIn("policy_eval", agent_names)

    def test_policy_eval_on_fast_cycle(self):
        sched = DiogenesisScheduler(self.engine)
        policy_cycles = []
        for _ in range(15):
            result = sched.tick()
            agents = [a["agent"] for a in result["actions_taken"]]
            if "policy_eval" in agents:
                policy_cycles.append(result["cycle"])
        # policy_eval fires at 3, 6, 9, 12, 15
        self.assertEqual(policy_cycles, [3, 6, 9, 12, 15])

    def test_deep_scan_on_slow_cycle(self):
        sched = DiogenesisScheduler(self.engine)
        deep_cycles = []
        for _ in range(26):
            result = sched.tick()
            agents = [a["agent"] for a in result["actions_taken"]]
            if "deep_scan" in agents:
                deep_cycles.append(result["cycle"])
        # deep_scan fires at 13, 26
        self.assertEqual(deep_cycles, [13, 26])

    def test_resonance_triggers_deep(self):
        sched = DiogenesisScheduler(self.engine)
        resonance_found = False
        for _ in range(120):
            result = sched.tick()
            if result["resonance"]:
                resonance_found = True
                # Should have a resonance_scan action
                agents = [a["agent"] for a in result["actions_taken"]]
                self.assertIn("resonance_scan", agents)
                break
        self.assertTrue(resonance_found, "No resonance detected in 120 cycles")

    def test_run_continuous_max_cycles(self):
        sched = DiogenesisScheduler(self.engine)
        sched.run_continuous(interval_seconds=0, max_cycles=10)
        self.assertEqual(sched.clock.cycle, 10)
        self.assertFalse(sched._running)

    def test_scheduler_status(self):
        sched = DiogenesisScheduler(self.engine)
        for _ in range(5):
            sched.tick()
        status = sched.get_status()
        self.assertEqual(status["cycle"], 5)
        self.assertEqual(status["agents_registered"], 5)
        self.assertIn("total_actions", status)
        self.assertIn("phase_coherence", status)
        self.assertIn("next_3way", status)


if __name__ == "__main__":
    unittest.main()
