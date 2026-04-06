# Diogenesis SDK

**Runtime security for AI applications.** Monitors what your AI does — every import, file write, network connection, and subprocess — and alerts when behavior deviates from normal.

Zero dependencies. Pure Python. Works with any AI framework.

## Install

```bash
pip install diogenesis-sdk
```

## Quick Start

```python
from diogenesis_sdk import activate, status, threat_summary

# Turn on monitoring
activate()

# Check what's happening
print(status())
```

If it worked, you'll see something like:

```
{'active': True, 'interceptors': 4, 'total_events': 1200, 'field_coherence': 1.0, ...}
```

That means Diogenesis is watching every import, file access, network call, and subprocess.

## What Can It Do?

```python
from diogenesis_sdk import activate, status, field_state, threat_summary

activate()

# System health — are interceptors running?
print(status())

# Behavioral voltage — per-module coherence scores
print(field_state())

# Threat analysis — what did the xenobot agents find?
print(threat_summary())
```

Example output:

```
Threats: 0 | Suspicious: 0
Agents: ['import_guardian', 'file_sentinel', 'network_watcher', 'subprocess_monitor']
```

Four agents are patrolling your application automatically.

## Add Custom Threat Patterns

```python
from diogenesis_sdk import activate, add_pattern, BehavioralPattern

activate()

# Detect: file read followed by network send (possible data leak)
pattern = BehavioralPattern(
    name="api_key_leak",
    description="Sensitive file read followed by outbound network call",
    event_sequence=[
        {"type": "file", "detail_contains": {"path": ".env"}},
        {"type": "network", "classification": "UNEXPECTED"},
    ],
    window_seconds=30,
    severity="CRITICAL",
)
add_pattern(pattern)
```

## Create Custom Agents

```python
from diogenesis_sdk import activate, XenobotAgent, add_agent, investigations

activate()

# Create an agent that specializes in file monitoring
agent = XenobotAgent("file_patrol", domain="file")
add_agent(agent)

# Check investigation findings
print(investigations())
```

Each agent uses a 5-phase investigation cycle: Observe, Question, Search, Synthesize, Crystallize.

## Behavioral Voltage Field

Every module gets a "voltage" score — how closely its behavior matches baseline. Voltage drops before attacks complete.

```python
from diogenesis_sdk import activate, field_state

activate()

state = field_state()
for name, info in state["modules"].items():
    voltage = info["voltage"]
    if voltage < 0.5:
        print(f"WARNING: {name} coherence low ({voltage:.2f})")
    else:
        print(f"OK: {name} stable at {voltage:.2f}")
```

## Core Components

| Component | What It Does |
|-----------|-------------|
| **Interceptors** | Capture every import, file write, subprocess, and network call |
| **Policy Engine** | Classify patterns (exfiltration, privilege escalation, shadow imports) |
| **Voltage Field** | Per-module behavioral coherence — drops before attacks complete |
| **Fibonacci Clock** | Agent patrols at PHI-ratio intervals (3, 5, 8, 13, 21 cycles) |
| **Xenobot Agents** | Autonomous investigators that detect anomalies and share learning |

## Features

- **Zero dependencies** — pure Python standard library only
- **104 automated tests** — production-grade
- **Python 3.8+** — works with any AI framework
- **Behavioral baseline** — learns "normal", alerts on deviation
- **Graduated response** — LOG → WARN → ALERT
- **5 built-in threat patterns** — exfiltration, import chains, write bursts, network scans, shadow imports

## Troubleshooting

**"ModuleNotFoundError: No module named 'diogenesis_sdk'"**
Run: `pip install diogenesis-sdk` (note the hyphen, not underscore)

**"ImportError: cannot import name 'activate'"**
Make sure you have version 0.2.0+: `pip install --upgrade diogenesis-sdk`

## License

Apache License 2.0. Free for commercial and personal use.

## Links

- **Website**: [diogenicsecurity.com](https://diogenicsecurity.com)
- **Source**: [github.com/AI-World-CEO/diogenesis-sdk](https://github.com/AI-World-CEO/diogenesis-sdk)
- **PyPI**: [pypi.org/project/diogenesis-sdk](https://pypi.org/project/diogenesis-sdk/)

---

*Built by Garry Anderson. Behavioral security for the age of autonomous AI.*
