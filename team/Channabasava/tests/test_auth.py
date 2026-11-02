import sys
import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "team" / "Channabasava"))

from auth import server


class AuthenticationTests(unittest.TestCase):

    def setUp(self):
        self.password = "TestPassword123"
        salt = "test-salt"

        password_hash = hashlib.sha256(
            (salt + self.password).encode()
        ).hexdigest()

        self.test_users = {
            "alice": {
                "salt": salt,
                "password_hash": password_hash,
                "role": "user"
            },
            "bob": {
                "salt": salt,
                "password_hash": password_hash,
                "role": "admin"
            }
        }

        self.test_policy = {
            "roles": {
                "user": {"services": ["web"]},
                "admin": {"services": ["web", "admin"]}
            }
        }

        self.users_patch = patch.dict(
            server.USERS, self.test_users, clear=True
        )
        self.policy_patch = patch.dict(
            server.POLICY, self.test_policy, clear=True
        )

        self.users_patch.start()
        self.policy_patch.start()

        server.sessions.clear()
        server.failed_attempts.clear()
        server.blocked_until.clear()

        self.controller_patch = patch.object(
            server,
            "controller_post",
            return_value={"action": "granted"}
        )
        self.controller_patch.start()

        self.log_patch = patch.object(server, "log_event")
        self.log_patch.start()

    def tearDown(self):
        self.controller_patch.stop()
        self.log_patch.stop()
        self.users_patch.stop()
        self.policy_patch.stop()

        server.sessions.clear()
        server.failed_attempts.clear()
        server.blocked_until.clear()

    def test_valid_user_credentials(self):
        valid, attempts = server.verify_credentials(
            "alice", self.password, "10.0.0.1"
        )

        self.assertTrue(valid)
        self.assertEqual(attempts, 0)

    def test_valid_admin_credentials(self):
        valid, attempts = server.verify_credentials(
            "bob", self.password, "10.0.0.2"
        )

        self.assertTrue(valid)
        self.assertEqual(attempts, 0)

    def test_invalid_password(self):
        valid, attempts = server.verify_credentials(
            "alice", "WrongPassword", "10.0.0.1"
        )

        self.assertFalse(valid)
        self.assertEqual(attempts, 2)

    def test_unknown_username(self):
        valid, attempts = server.verify_credentials(
            "unknown", self.password, "10.0.0.3"
        )

        self.assertFalse(valid)

    def test_role_permissions(self):
        self.assertEqual(
            server.POLICY["roles"]["user"]["services"],
            ["web"]
        )

        self.assertEqual(
            server.POLICY["roles"]["admin"]["services"],
            ["web", "admin"]
        )

    def test_session_creation(self):
        response = server.create_session(
            "alice", "10.0.0.1"
        )

        self.assertEqual(response["type"], "AUTH_OK")
        self.assertEqual(response["role"], "user")
        self.assertEqual(response["services"], ["web"])
        self.assertIn(response["token"], server.sessions)

    def test_admin_session_permissions(self):
        response = server.create_session(
            "bob", "10.0.0.2"
        )

        self.assertEqual(response["role"], "admin")
        self.assertEqual(
            response["services"], ["web", "admin"]
        )

    def test_session_refresh(self):
        response = server.create_session(
            "alice", "10.0.0.1"
        )

        token = response["token"]

        refreshed = server.refresh_session(
            token, "10.0.0.1"
        )

        self.assertEqual(refreshed["type"], "REFRESH_OK")

    def test_refresh_with_invalid_ip(self):
        response = server.create_session(
            "alice", "10.0.0.1"
        )

        result = server.refresh_session(
            response["token"], "10.0.0.99"
        )

        self.assertEqual(result["reason"], "expired")

    def test_successful_logout(self):
        response = server.create_session(
            "alice", "10.0.0.1"
        )

        token = response["token"]

        with patch.object(
            server,
            "controller_post",
            return_value={"action": "revoked"}
        ):
            result = server.logout_session(
                token, "10.0.0.1"
            )

        self.assertEqual(result["type"], "LOGOUT_OK")
        self.assertNotIn(token, server.sessions)

    def test_logout_with_wrong_ip(self):
        response = server.create_session(
            "alice", "10.0.0.1"
        )

        result = server.logout_session(
            response["token"], "10.0.0.99"
        )

        self.assertEqual(result["reason"], "invalid_token")

    def test_unknown_request(self):
        result = server.process_request(
            {"type": "UNKNOWN"},
            "10.0.0.1"
        )

        self.assertEqual(result["type"], "ERROR")
        self.assertEqual(result["reason"], "unknown_request")


if __name__ == "__main__":
    unittest.main(verbosity=2)
