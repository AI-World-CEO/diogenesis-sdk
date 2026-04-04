# Diogenesis SDK

**Behavioral immune system for AI applications.**

Diogenesis monitors what your AI does at runtime — every import, file write, network connection, and subprocess — and detects when behavior deviates from the expected baseline. No external dependencies. Pure Python. One command to install.

```bash
pip install diogenesis-sdk
```

## Why Diogenesis?

AI agents are increasingly autonomous. They write code, execute commands, access files, and make network requests without human approval for each action. Traditional security tools can't monitor this:

- **Firewalls** block known threats. They can't detect an AI agent gradually escalating permissions.
- **Antivirus** scans for known signatures. An AI acting outside scope looks nothing like malware.
- **Monitoring tools** track CPU and memory. They can't tell you your AI just imported `subprocess` for the first time.

Diogenesis fills this gap.

## Quick Start

```python
import diogenesis_sdk

# Start behavioral monitoring
diogenesis_sdk.activate()

# Your AI application runs normally...
import os  # This import is now tracked
with open("data.json") as f:  # This file access is tracked
    data = f.read()

# Check system health
print(diogenesis_sdk.status())        # Interceptor counts + field coherence
print(diogenesis_sdk.field_state())   # Per-module behavioral voltage
print(diogenesis_sdk.alerts())        # Policy alerts
print(diogenesis_sdk.threat_summary())  # Threat/suspicious/benign counts

# Clean shutdown — all originals restored
diogenesis_sdk.deactivate()
```

## Core Components

| Component | What It Does |
|-----------|-------------|
| **Interceptors** | Capture every import, file write, subprocess, and network call at runtime |
| **Policy Engine** | Classify behavioral patterns (exfiltration, privilege escalation, shadow imports) with graduated response |
| **Voltage Field** | Track per-module behavioral coherence over time — like bioelectric fields in living tissue |
| **Fibonacci Clock** | Time agent patrols at PHI-ratio intervals. Unpredictable to adversaries, mathematically guaranteed for coverage |
| **Xenobot Agents** | Autonomous investigators that patrol, detect anomalies, and share learning across the swarm |

## Features

- **Zero dependencies** — pure Python standard library only
- **104 automated tests** — production-grade quality
- **Behavioral baseline** — learns what "normal" looks like, alerts on deviation
- **Graduated response** — LOG → WARN → ALERT based on repeat violations
- **5 built-in threat patterns** — data exfiltration, suspicious import chains, write bursts, network scans, shadow imports
- **Biologically inspired** — voltage fields and xenobot agents modeled on biological immune systems
- **Python 3.8+** — works with any Python AI framework

## Built-In Threat Patterns

```python
from diogenesis_sdk import BehavioralPattern, add_pattern

# 5 patterns ship out of the box:
# - data_exfiltration (file read + network send)
# - suspicious_import_chain (suspicious import + subprocess)
# - unusual_write_burst (5+ unexpected file writes in 10s)
# - network_scan (3+ connections to unknown hosts in 5s)
# - shadow_import (suspicious import + sensitive file access)

# Add your own:
custom = BehavioralPattern(
    name="api_key_leak",
    description="Environment variable read followed by network POST",
    event_sequence=[
        {"type": "file", "detail_contains": {"path": ".env"}},
        {"type": "network", "classification": "UNEXPECTED"},
    ],
    window_seconds=30,
    severity="CRITICAL",
)
add_pattern(custom)
```

## Voltage Field — Behavioral Health at a Glance

Every monitored module gets a behavioral "voltage" — a coherence score reflecting how closely its current behavior matches its baseline. Voltage drops before attacks complete.

```python
import diogenesis_sdk

diogenesis_sdk.activate()
# ... application runs ...

state = diogenesis_sdk.field_state()
for module, info in state["modules"].items():
    voltage = info["voltage"]
    if voltage < 0.5:
        print(f"WARNING: {module} behavioral coherence low ({voltage:.2f})")
```

## Xenobot Agents — Autonomous Investigation

When anomalies are detected, xenobot agents run a 5-phase investigation cycle inspired by biological immune response:

1. **Observe** — extract facts from the anomalous event
2. **Question** — generate investigation hypothesis
3. **Search** — gather evidence from context
4. **Synthesize** — form verdict with confidence score
5. **Crystallize** — record finding, update behavioral model

```python
from diogenesis_sdk import XenobotAgent

# Custom agent with your own reasoning logic
agent = XenobotAgent(
    name="my_investigator",
    domain="network",  # Specializes in network events
    reasoning_fn=my_custom_reasoning,  # Optional: plug in LLM or rules
)
```

## Fibonacci Scheduling

Agent patrols fire at Fibonacci intervals (3, 5, 8, 13, 21 cycles). When multiple agents align simultaneously, deep scans trigger. Unpredictable to attackers, mathematically guaranteed for coverage.

```python
from diogenesis_sdk import FibonacciClock

clock = FibonacciClock()
clock.register_agent("fast_check", 0)   # Every 3 cycles
clock.register_agent("deep_scan", 3)    # Every 13 cycles

for _ in range(100):
    result = clock.tick()
    if result["resonance"]:
        print(f"Resonance event: {result['resonance']['type']}")
```

## License

Apache License 2.0. Free for commercial and personal use. Includes patent protection.

## Links

- **Website**: [diogenicsecurity.com](https://diogenicsecurity.com)
- **Source**: [github.com/AI-World-CEO/Prometheus_Prime](https://github.com/AI-World-CEO/Prometheus_Prime)
- **PyPI**: [pypi.org/project/diogenesis-sdk](https://pypi.org/project/diogenesis-sdk/)

---

*Built by Garry Anderson. Behavioral security for the age of autonomous AI.*
