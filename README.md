# Diogenesis SDK

**Behavioral health for Python applications.**

Not signature-based detection. Not rule-based blocking. Behavioral coherence.

## Install

```
pip install diogenesis-sdk
```

## Quick Start

```python
import diogenesis_sdk

diogenesis_sdk.activate()
# your application runs normally — every import, file access,
# subprocess call, and network request is observed

print(diogenesis_sdk.status())    # what's being tracked
print(diogenesis_sdk.log(10))     # last 10 events
print(diogenesis_sdk.baseline())  # behavioral fingerprint (after 1000+ events)

diogenesis_sdk.deactivate()       # cleanly restore all originals
```

## What It Does

Diogenesis intercepts every import, file access, subprocess call, and network request in your Python application. It classifies each as KNOWN, UNEXPECTED, or SUSPICIOUS based on behavioral patterns. After observing 1000+ events, it generates a behavioral baseline that defines what "normal" looks like. Deviations are anomalies — whether from attacks, bugs, or dependency rot.

## Zero Dependencies

Diogenesis uses only the Python standard library. A security product with supply chain risk is a contradiction.

## Philosophy

Inspired by Michael Levin's xenobot research: biological systems maintain health through behavioral coherence, not programmed rules. Diogenesis applies the same principle to software.

## Design Principles

- **Never break the host application.** Every interceptor is try/except wrapped. If Diogenesis fails, your code runs normally.
- **Shadow mode only.** Diogenesis observes. It does not block. Policy enforcement comes in future versions.
- **Zero dependencies.** stdlib only. No supply chain risk.
- **Clean activate/deactivate.** One function call to start. One to stop. All originals restored.

## Configuration

Pass a config dict to `activate()`:

```python
diogenesis_sdk.activate({
    "buffer_size": 5000,
    "interceptors": {"import": True, "file": True, "subprocess": False, "network": True},
    "whitelist": {
        "import_modules": ["myapp", "mylib"],
        "file_paths": ["/app/data/"],
        "network_hosts": ["localhost", "api.myservice.com"],
    },
    "suspicious_patterns": {
        "imports": ["ctypes"],
        "subprocess_commands": ["rm -rf"],
    },
})
```

Or place a `diogenesis_sdk.json` file in your working directory.

## License

MIT
