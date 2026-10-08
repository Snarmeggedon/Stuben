import unittest
from unittest.mock import Mock

from desktop_app import SecurityDashboard


class RecommendationActionTests(unittest.TestCase):
    def test_recommendation_button_uses_common_action_handler(self):
        dashboard = SecurityDashboard.__new__(SecurityDashboard)
        dashboard.execute_threat_action = Mock()

        dashboard._execute_action("Quarantine file", "powershell execution")

        dashboard.execute_threat_action.assert_called_once_with(
            "Quarantine file",
            "powershell execution",
        )


    def test_isolate_system_does_not_quarantine_file(self):
        dashboard = SecurityDashboard.__new__(SecurityDashboard)
        dashboard.history = Mock()
        dashboard.write_output = Mock()
        dashboard.pick_quarantine_file = Mock()
        dashboard.last_review_path = None

        dashboard.execute_threat_action("Isolate system", "beacon")

        dashboard.pick_quarantine_file.assert_not_called()
        self.assertEqual(dashboard.write_output.call_args_list[-1].args[0], "ISOLATION")


if __name__ == "__main__":
    unittest.main()
