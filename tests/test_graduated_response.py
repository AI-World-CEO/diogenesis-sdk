import unittest

from diogenesis_sdk.policy.response import GraduatedResponse


class TestGraduatedResponse(unittest.TestCase):

    def setUp(self):
        self.gr = GraduatedResponse()

    def test_first_violation_logs(self):
        result = self.gr.record_violation("module_a.py")
        self.assertEqual(result["level"], 1)
        self.assertEqual(result["action"], "LOG")
        self.assertEqual(result["count"], 1)

    def test_second_violation_warns(self):
        self.gr.record_violation("module_a.py")
        result = self.gr.record_violation("module_a.py")
        self.assertEqual(result["level"], 2)
        self.assertEqual(result["action"], "WARN")

    def test_third_violation_alerts(self):
        self.gr.record_violation("module_a.py")
        self.gr.record_violation("module_a.py")
        result = self.gr.record_violation("module_a.py")
        self.assertEqual(result["level"], 3)
        self.assertEqual(result["action"], "ALERT")

    def test_fourth_stays_at_alert(self):
        for _ in range(4):
            result = self.gr.record_violation("module_a.py")
        self.assertEqual(result["level"], 3)
        self.assertEqual(result["action"], "ALERT")
        self.assertEqual(result["count"], 4)

    def test_reset(self):
        self.gr.record_violation("module_a.py")
        self.gr.record_violation("module_a.py")
        self.gr.reset("module_a.py")
        result = self.gr.record_violation("module_a.py")
        self.assertEqual(result["level"], 1)
        self.assertEqual(result["action"], "LOG")

    def test_reset_all(self):
        self.gr.record_violation("a.py")
        self.gr.record_violation("b.py")
        self.gr.reset()
        self.assertEqual(self.gr.total_violations, 0)

    def test_multiple_sources(self):
        self.gr.record_violation("a.py")
        self.gr.record_violation("a.py")
        self.gr.record_violation("b.py")
        escalations = self.gr.get_escalations()
        # Only a.py should be escalated (level 2), b.py is level 1
        self.assertEqual(len(escalations), 1)
        self.assertEqual(escalations[0]["source"], "a.py")

    def test_get_escalations_empty(self):
        self.assertEqual(self.gr.get_escalations(), [])


if __name__ == "__main__":
    unittest.main()
