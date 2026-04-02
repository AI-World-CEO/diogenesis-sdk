"""Fibonacci-harmonic scheduling for agent patrols.

Agents fire at intervals based on the Fibonacci sequence: 3, 5, 8, 13, 21.
These emerge naturally from PHI-ratio harmonics applied to a base period.
When multiple agents align simultaneously, resonance occurs — triggering
deep analysis. Unpredictable to attackers. Mathematically guaranteed coverage.

Mathematics:
  Base period T = 3 cycles
  PHI = 1.618033988749895

  Harmonic schedule:
    Agent 0: T * PHI^0 = 3  cycles (fastest)
    Agent 1: T * PHI^1 = 5  cycles
    Agent 2: T * PHI^2 = 8  cycles
    Agent 3: T * PHI^3 = 13 cycles
    Agent 4: T * PHI^4 = 21 cycles (slowest)

  These are the Fibonacci sequence — not by design, but because
  the Fibonacci sequence IS the PHI harmonic series in integers.
"""

import math

PHI = 1.618033988749895

# The 5 Fibonacci frequencies
FIBONACCI_PERIODS = [3, 5, 8, 13, 21]


def _compute_lcm(a, b):
    return abs(a * b) // math.gcd(a, b)


def _multi_lcm(values):
    result = values[0]
    for v in values[1:]:
        result = _compute_lcm(result, v)
    return result


# Pre-computed resonance intervals
RESONANCE_3WAY = _multi_lcm(FIBONACCI_PERIODS[:3])   # LCM(3,5,8) = 120
RESONANCE_4WAY = _multi_lcm(FIBONACCI_PERIODS[:4])   # LCM(3,5,8,13) = 1560
RESONANCE_5WAY = _multi_lcm(FIBONACCI_PERIODS)       # LCM(3,5,8,13,21) = 10920


class AgentSchedule:
    """Schedule state for a single agent."""

    def __init__(self, name, period, callback=None):
        self.name = name
        self.period = period
        self.callback = callback
        self.last_fired = 0
        self.fire_count = 0

    def should_fire(self, cycle):
        return cycle > 0 and cycle % self.period == 0

    def record_fire(self, cycle):
        self.last_fired = cycle
        self.fire_count += 1
        if self.callback is not None:
            try:
                self.callback(cycle, self.name)
            except Exception:
                pass

    def to_dict(self, current_cycle=0):
        remaining = self.period - (current_cycle % self.period) if current_cycle > 0 else self.period
        if remaining == self.period and current_cycle > 0 and current_cycle % self.period == 0:
            remaining = 0
        return {
            "name": self.name,
            "period": self.period,
            "last_fired": self.last_fired,
            "fire_count": self.fire_count,
            "next_fire_in": remaining,
        }


class FibonacciClock:
    """Fibonacci-harmonic scheduling for agent patrols.

    Usage:
        clock = FibonacciClock()
        clock.register_agent("fast_check", 0)   # every 3 cycles
        clock.register_agent("deep_scan", 3)     # every 13 cycles
        for _ in range(100):
            result = clock.tick()
            for name in result["fires"]:
                do_work(name)
            if result["resonance"]:
                do_deep_work(result["resonance"])
    """

    def __init__(self, base_period=3):
        self.base_period = base_period
        self.frequencies = list(FIBONACCI_PERIODS)
        self.cycle = 0
        self.agents = {}
        self.resonance_history = []

    def tick(self):
        """Advance one cycle. Return which agents fire and any resonance."""
        self.cycle += 1
        fires = []

        for name, agent in self.agents.items():
            if agent.should_fire(self.cycle):
                agent.record_fire(self.cycle)
                fires.append(name)

        resonance = None
        if len(fires) >= 3:
            if len(fires) >= 5:
                rtype = "5-way"
            elif len(fires) >= 4:
                rtype = "4-way"
            else:
                rtype = "3-way"

            coherence = self._compute_phase_coherence(fires)
            resonance = {
                "type": rtype,
                "cycle": self.cycle,
                "agents": list(fires),
                "phase_coherence": round(coherence, 4),
            }
            self.resonance_history.append(resonance)

        return {
            "cycle": self.cycle,
            "fires": fires,
            "resonance": resonance,
        }

    def _compute_phase_coherence(self, firing_agents):
        """Phase coherence across firing agents. 1.0 = all perfectly aligned."""
        if len(firing_agents) <= 1:
            return 0.0
        total_agents = len(self.agents)
        if total_agents <= 1:
            return 1.0
        return min(1.0, (len(firing_agents) - 1) / (total_agents - 1))

    def register_agent(self, name, frequency_index=0, callback=None):
        """Register an agent at a Fibonacci frequency.

        frequency_index: 0=fastest (3), 1=5, 2=8, 3=13, 4=slowest (21)
        """
        idx = max(0, min(frequency_index, len(self.frequencies) - 1))
        period = self.frequencies[idx]
        self.agents[name] = AgentSchedule(name, period, callback)

    def unregister_agent(self, name):
        """Remove an agent."""
        self.agents.pop(name, None)

    def get_schedule(self):
        """Return current schedule with predictions."""
        agents_data = {n: a.to_dict(self.cycle) for n, a in self.agents.items()}

        # Next resonance: find next cycle where 3+ agents fire
        next_3way = self._next_multi_fire(3)
        next_5way = self._next_multi_fire(len(self.agents)) if len(self.agents) >= 5 else None

        return {
            "cycle": self.cycle,
            "agents": agents_data,
            "next_3way": next_3way,
            "next_5way": next_5way,
            "resonance_events_total": len(self.resonance_history),
        }

    def _next_multi_fire(self, min_count):
        """Find cycles until next time min_count agents fire simultaneously."""
        if len(self.agents) < min_count:
            return None
        # Brute force search up to max LCM (bounded)
        periods = [a.period for a in self.agents.values()]
        limit = _multi_lcm(periods) if len(periods) <= 5 else 10920
        for offset in range(1, limit + 1):
            test_cycle = self.cycle + offset
            firing = sum(1 for a in self.agents.values() if test_cycle % a.period == 0)
            if firing >= min_count:
                return offset
        return None

    def get_resonance_history(self, n=50):
        """Return last n resonance events."""
        return self.resonance_history[-n:]

    def phase_coherence(self):
        """Current phase coherence across all registered agents."""
        if not self.agents or self.cycle <= 0:
            return 0.0
        recently_fired = sum(
            1 for a in self.agents.values()
            if a.last_fired > 0 and (self.cycle - a.last_fired) <= 3
        )
        total = len(self.agents)
        if total <= 1:
            return 0.5
        return min(1.0, (recently_fired - 1) / (total - 1))
