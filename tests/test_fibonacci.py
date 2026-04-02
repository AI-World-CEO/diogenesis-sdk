import unittest

from diogenesis_sdk.timing.fibonacci import (
    FibonacciClock, AgentSchedule, FIBONACCI_PERIODS,
    RESONANCE_3WAY, RESONANCE_5WAY,
)


class TestFibonacciClock(unittest.TestCase):

    def test_frequencies(self):
        clock = FibonacciClock()
        self.assertEqual(clock.frequencies, [3, 5, 8, 13, 21])

    def test_tick_fires_agent(self):
        clock = FibonacciClock()
        clock.register_agent("fast", 0)  # period 3
        fires = []
        for _ in range(9):
            r = clock.tick()
            if "fast" in r["fires"]:
                fires.append(r["cycle"])
        # Should fire at cycles 3, 6, 9
        self.assertEqual(fires, [3, 6, 9])

    def test_multiple_agents_different_periods(self):
        clock = FibonacciClock()
        clock.register_agent("a", 0)  # 3
        clock.register_agent("b", 1)  # 5
        # Run 15 cycles
        a_fires = []
        b_fires = []
        for _ in range(15):
            r = clock.tick()
            if "a" in r["fires"]:
                a_fires.append(r["cycle"])
            if "b" in r["fires"]:
                b_fires.append(r["cycle"])
        self.assertEqual(a_fires, [3, 6, 9, 12, 15])
        self.assertEqual(b_fires, [5, 10, 15])

    def test_3way_resonance(self):
        clock = FibonacciClock()
        clock.register_agent("a", 0)  # 3
        clock.register_agent("b", 1)  # 5
        clock.register_agent("c", 2)  # 8
        # LCM(3,5,8) = 120 — but 3-way is any 3+ firing, not necessarily all 3
        # First time all 3 fire: LCM(3,5) = 15 (a+b), but c fires at 8,16,24...
        # Actually need cycle divisible by 3 AND 5 AND 8 → LCM = 120
        # But 3-way just needs 3+ agents firing, and we have exactly 3 agents
        resonances = []
        for _ in range(120):
            r = clock.tick()
            if r["resonance"] and r["resonance"]["type"] in ("3-way", "4-way", "5-way"):
                resonances.append(r["cycle"])
        self.assertGreater(len(resonances), 0)
        self.assertIn(120, resonances)  # All 3 fire at LCM

    def test_5way_resonance(self):
        clock = FibonacciClock()
        for i in range(5):
            clock.register_agent(f"agent_{i}", i)
        # LCM(3,5,8,13,21) = 10920 — too many cycles to test
        # Instead verify it would fire at that cycle
        self.assertEqual(RESONANCE_5WAY, 10920)
        # Test that at cycle 10920, all 5 would fire
        for i, period in enumerate(FIBONACCI_PERIODS):
            self.assertEqual(10920 % period, 0, f"Period {period} should divide 10920")

    def test_phase_coherence(self):
        clock = FibonacciClock()
        for i in range(5):
            clock.register_agent(f"a{i}", i)
        # At cycle 0, coherence should be 0 (nothing fired yet)
        self.assertEqual(clock.phase_coherence(), 0.0)
        # Run to cycle 3 — only fastest agent fires
        for _ in range(3):
            clock.tick()
        coh = clock.phase_coherence()
        # 1 of 5 recently fired → (1-1)/(5-1) = 0.0
        self.assertLessEqual(coh, 0.25)

    def test_register_unregister(self):
        clock = FibonacciClock()
        clock.register_agent("x", 0)
        self.assertIn("x", clock.agents)
        clock.unregister_agent("x")
        self.assertNotIn("x", clock.agents)

    def test_get_schedule(self):
        clock = FibonacciClock()
        clock.register_agent("fast", 0)
        clock.register_agent("slow", 4)
        schedule = clock.get_schedule()
        self.assertIn("agents", schedule)
        self.assertIn("fast", schedule["agents"])
        self.assertIn("slow", schedule["agents"])
        self.assertEqual(schedule["agents"]["fast"]["period"], 3)
        self.assertEqual(schedule["agents"]["slow"]["period"], 21)

    def test_resonance_history(self):
        clock = FibonacciClock()
        clock.register_agent("a", 0)
        clock.register_agent("b", 1)
        clock.register_agent("c", 2)
        for _ in range(120):
            clock.tick()
        history = clock.get_resonance_history()
        self.assertGreater(len(history), 0)
        self.assertIn("type", history[0])
        self.assertIn("cycle", history[0])

    def test_callback(self):
        fired_cycles = []

        def on_fire(cycle, name):
            fired_cycles.append((cycle, name))

        clock = FibonacciClock()
        clock.register_agent("cb_agent", 0, callback=on_fire)
        for _ in range(6):
            clock.tick()
        # Should fire at 3 and 6
        self.assertEqual(len(fired_cycles), 2)
        self.assertEqual(fired_cycles[0], (3, "cb_agent"))
        self.assertEqual(fired_cycles[1], (6, "cb_agent"))


if __name__ == "__main__":
    unittest.main()
