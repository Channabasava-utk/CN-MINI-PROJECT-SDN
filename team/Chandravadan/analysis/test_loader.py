import json
import tempfile
import unittest
from pathlib import Path

from loader import (
    load_json, load_access_results, load_controller_log, load_topology,
    validate_fields, validate_records, DataValidationError,
)


class TestLoader(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.temp_dir.name) / "test.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def write(self, data):
        self.file_path.write_text(json.dumps(data), encoding="utf-8")

    def test_valid_json(self):
        self.write({"name": "Alice"})
        self.assertEqual(load_json(self.file_path)["name"], "Alice")

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            load_json(Path(self.temp_dir.name) / "missing.json")

    def test_missing_fields(self):
        with self.assertRaises(DataValidationError):
            validate_fields({"name": "Alice"}, ["name", "ip"], "test.json")

    def test_invalid_record(self):
        with self.assertRaises(DataValidationError):
            validate_records([{"user": "Alice"}], ["user", "ip"], "test.json")

    def test_access_success(self):
        self.write({"run_id": "r1", "scenario": "A3", "mode": "dynamic",
                    "attempts": [{"src": "h1", "dst": "h5", "port": 8000,
                                  "ts": 1730000001.0, "success": True,
                                  "latency_ms": 3.2, "error": None}]})
        self.assertEqual(load_access_results(self.file_path)["attempts"][0]["latency_ms"], 3.2)

    def test_access_failure_null_latency(self):
        self.write({"run_id": "r1", "scenario": "A3", "mode": "dynamic",
                    "attempts": [{"src": "h1", "dst": "h5", "port": 8000,
                                  "ts": 1730000001.0, "success": False,
                                  "latency_ms": None, "error": "Connection refused"}]})
        self.assertIsNone(load_access_results(self.file_path)["attempts"][0]["latency_ms"])

    def test_access_missing_latency(self):
        self.write({"run_id": "r1", "scenario": "A3", "mode": "dynamic",
                    "attempts": [{"src": "h1", "dst": "h5", "port": 8000,
                                  "ts": 1730000001.0, "success": False,
                                  "error": "Connection refused"}]})
        with self.assertRaises(DataValidationError):
            load_access_results(self.file_path)

    def test_controller_nullable_metrics(self):
        self.write({"events": [{"ts": 1.0, "action": "GRANT", "ip": "10.0.0.1",
                                "reason": "auth_ok", "flows_changed": None, "install_ms": None}]})
        self.assertIsNone(load_controller_log(self.file_path)["events"][0]["install_ms"])

    def test_topology_valid(self):
        self.write({"switches": ["s1"], "hosts": {"h1": "10.0.0.1"},
                    "links": [["h1", "s1"]],
                    "openflow": {"version": "1.3", "controller_host": "127.0.0.1",
                                 "controller_port": 6653, "port": 6653},
                    "controller_rest": {"management_ip": "10.0.0.254", "port": 8080}})
        self.assertEqual(load_topology(self.file_path)["switches"], ["s1"])

    def test_topology_bad_port(self):
        self.write({"switches": ["s1"], "hosts": {"h1": "10.0.0.1"},
                    "links": [["h1", "s1"]],
                    "openflow": {"version": "1.3", "controller_host": "127.0.0.1",
                                 "controller_port": "6653", "port": 6653},
                    "controller_rest": {"management_ip": "10.0.0.254", "port": 8080}})
        with self.assertRaises(DataValidationError):
            load_topology(self.file_path)


if __name__ == "__main__":
    unittest.main()
