"""Fast checks for Dhrithi's controller/topology integration files.

Run from the repository root:
    python3 -m unittest team.Dhrithi.controller.tests.test_controller_config -v
"""

import ast
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from team.Dhrithi.controller import config
from team.Dhrithi.controller.event_logger import EventLogger


class ControllerConfigurationTests(unittest.TestCase):
    def test_python_files_parse_without_importing_ryu_or_mininet(self):
        source_paths = [
            ROOT / "team/Dhrithi/controller/controller.py",
            ROOT / "team/Dhrithi/controller/config.py",
            ROOT / "team/Dhrithi/controller/session_manager.py",
            ROOT / "team/Dhrithi/controller/event_logger.py",
            ROOT / "team/Dhrithi/topology/topo.py",
        ]
        for path in source_paths:
            with self.subTest(path=path):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    def test_policy_matches_expected_role_services(self):
        policy_path = ROOT / "team/Dhrithi/controller/policy.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))

        user_services = policy["roles"]["user"]["services"]
        admin_services = policy["roles"]["admin"]["services"]

        self.assertEqual(
            [(item["ip"], item["port"]) for item in user_services],
            [(config.HOSTS["h5"]["ip"], config.WEB_PORT)]
        )
        self.assertEqual(
            {(item["ip"], item["port"]) for item in admin_services},
            {
                (config.HOSTS["h5"]["ip"], config.WEB_PORT),
                (config.HOSTS["h6"]["ip"], config.ADMIN_PORT),
            }
        )
        self.assertEqual(policy["default_policy"], "deny")

        shared_policy = json.loads(
            (ROOT / "policy.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            shared_policy["roles"]["user"]["services"], ["web"]
        )
        self.assertEqual(
            shared_policy["roles"]["admin"]["services"],
            ["web", "admin"]
        )

    def test_topology_metadata_matches_shared_config(self):
        topology_path = ROOT / "team/Dhrithi/topology/topology.json"
        topology = json.loads(topology_path.read_text(encoding="utf-8"))

        self.assertEqual(topology["hosts"]["cHost"], config.MANAGEMENT_IP)
        self.assertIn(["s3", "cHost"], topology["links"])
        self.assertEqual(topology["openflow"]["port"], config.OPENFLOW_PORT)
        self.assertEqual(
            topology["controller_rest"]["port"], config.REST_API_PORT
        )
        self.assertEqual(set(topology["switches"]), set(config.SWITCHES))

    def test_event_logger_round_trip_and_newline(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "controller_log.json"
            logger = EventLogger(log_path)

            created = logger.log(
                "SESSION_GRANTED",
                "10.0.0.1",
                {"role": "user"}
            )
            entries = logger.read_all()

            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["event"], "SESSION_GRANTED")
            self.assertEqual(entries[0]["ip"], "10.0.0.1")
            self.assertEqual(entries[0]["details"]["role"], "user")
            self.assertIn("timestamp", created)
            self.assertTrue(log_path.read_bytes().endswith(bytes([10])))


if __name__ == "__main__":
    unittest.main()
