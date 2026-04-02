import time
import unittest

from diogenesis_sdk.field.voltage import VoltageField, ModuleVoltage
from diogenesis_sdk.field.propagation import VoltagePropagation


def _evt(caller="app.py", etype="import", classification="KNOWN", detail=None, ts=None):
    return {
        "type": etype,
        "timestamp": ts or time.time(),
        "caller_file": caller,
        "caller_line": 1,
        "caller_func": "test",
        "detail": detail or {},
        "classification": classification,
    }


class TestPropagation(unittest.TestCase):

    def test_learn_connections(self):
        prop = VoltagePropagation()
        events = [
            _evt("app.py", "import", detail={"module": "requests"}),
            _evt("app.py", "import", detail={"module": "json"}),
            _evt("lib.py", "import", detail={"module": "requests"}),
        ]
        prop.learn_connections(events)
        graph = prop.get_connection_graph()
        # app imports requests, lib imports requests -> app <-> requests, lib <-> requests
        self.assertIn("requests", graph.get("app", []))
        self.assertIn("requests", graph.get("lib", []))

    def test_propagate_drop(self):
        vf = VoltageField()
        vf.modules["a"] = ModuleVoltage("a")
        vf.modules["b"] = ModuleVoltage("b")

        prop = VoltagePropagation(propagation_factor=0.3)
        prop.connections = {"a": {"b"}, "b": {"a"}}

        old_b = vf.modules["b"].voltage
        affected = prop.propagate(vf, "a", 0.20)
        self.assertEqual(len(affected), 1)
        self.assertEqual(affected[0]["module"], "b")
        expected_drop = 0.20 * 0.3
        self.assertAlmostEqual(vf.modules["b"].voltage, old_b - expected_drop, places=3)

    def test_no_propagate_to_unconnected(self):
        vf = VoltageField()
        vf.modules["a"] = ModuleVoltage("a")
        vf.modules["c"] = ModuleVoltage("c")

        prop = VoltagePropagation()
        prop.connections = {"a": {"b"}}  # c not connected to a

        old_c = vf.modules["c"].voltage
        prop.propagate(vf, "a", 0.20)
        self.assertEqual(vf.modules["c"].voltage, old_c)

    def test_propagation_factor(self):
        vf = VoltageField()
        vf.modules["a"] = ModuleVoltage("a")
        vf.modules["b"] = ModuleVoltage("b")

        prop = VoltagePropagation(propagation_factor=0.5)
        prop.connections = {"a": {"b"}}

        old_b = vf.modules["b"].voltage
        prop.propagate(vf, "a", 0.10)
        self.assertAlmostEqual(vf.modules["b"].voltage, old_b - 0.05, places=3)

    def test_connection_graph(self):
        prop = VoltagePropagation()
        prop.connections = {"a": {"b", "c"}, "b": {"a"}}
        graph = prop.get_connection_graph()
        self.assertEqual(graph["a"], ["b", "c"])
        self.assertEqual(graph["b"], ["a"])


if __name__ == "__main__":
    unittest.main()
