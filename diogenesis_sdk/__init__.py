"""Diogenesis SDK — Behavioral health for Python applications.

Not signature-based detection. Not rule-based blocking. Behavioral coherence.

Usage:
    import diogenesis_sdk

    diogenesis_sdk.activate()
    print(diogenesis_sdk.status())            # interceptor counts + field coherence
    print(diogenesis_sdk.field_state())       # per-module voltage map
    print(diogenesis_sdk.alerts())            # policy alerts
    print(diogenesis_sdk.investigations())    # xenobot findings
    print(diogenesis_sdk.threat_summary())    # threat/suspicious/benign counts
    diogenesis_sdk.deactivate()
"""

from .engine import DiogenesisEngine
from .policy.pattern import BehavioralPattern
from .timing.fibonacci import FibonacciClock
from .agents.xenobot import XenobotAgent

_engine = DiogenesisEngine()

activate = _engine.activate
deactivate = _engine.deactivate
status = _engine.status
log = _engine.log
baseline = _engine.baseline
configure = _engine.configure
alerts = _engine.alerts
alert_summary = _engine.alert_summary
escalations = _engine.escalations
add_pattern = _engine.add_pattern
evaluate_policies = _engine.evaluate_policies
field_state = _engine.field_state
module_voltage = _engine.module_voltage
voltage_history = _engine.voltage_history
connection_graph = _engine.connection_graph
create_scheduler = _engine.create_scheduler
investigations = _engine.investigations
threat_summary = _engine.threat_summary
add_agent = _engine.add_agent

def start_monitoring(**kwargs):
    """Convenience alias — activates monitoring and returns status."""
    activate(**kwargs)
    return status()

__version__ = "0.2.0"
__author__ = "Garry Anderson"
__all__ = [
    "activate", "deactivate", "status", "log", "baseline", "configure",
    "alerts", "alert_summary", "escalations", "add_pattern", "evaluate_policies",
    "field_state", "module_voltage", "voltage_history", "connection_graph",
    "create_scheduler", "investigations", "threat_summary", "add_agent",
    "start_monitoring",
    "BehavioralPattern", "FibonacciClock", "XenobotAgent",
]
