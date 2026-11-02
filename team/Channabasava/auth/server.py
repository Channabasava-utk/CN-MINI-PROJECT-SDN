import socket
import threading
import json
import hashlib
import hmac
import secrets
import time
import logging
import requests
import sys
from pathlib import Path

# Project paths
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

import config

# Load users and policies
with open(ROOT / "users.json") as f:
    USERS = json.load(f)["users"]

with open(ROOT / "policy.json") as f:
    POLICY = json.load(f)

# Server state
sessions = {}
failed_attempts = {}
blocked_until = {}

session_lock = threading.Lock()
attempt_lock = threading.Lock()
log_lock = threading.Lock()

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

AUTH_LOG = ROOT / "data" / "auth_log.json"


# ---------------------------------------
# Authentication event logging
# ---------------------------------------

def log_event(event, user=None, ip=None, detail=None):

    entry = {
        "ts": time.time(),
        "event": event,
        "user": user,
        "ip": ip,
        "detail": detail
    }

    with log_lock:

        try:
            if AUTH_LOG.exists():
                with open(AUTH_LOG) as f:
                    data = json.load(f)
            else:
                data = {"run_id": "run1", "events": []}

            data["events"].append(entry)

            with open(AUTH_LOG, "w") as f:
                json.dump(data, f, indent=4)

        except (OSError, json.JSONDecodeError) as error:
            logger.error(f"Log writing failed: {error}")


# ---------------------------------------
# Controller communication
# ---------------------------------------

def controller_post(endpoint, payload):

    url = f"{config.CONTROLLER_URL}{endpoint}"

    for attempt in range(config.CONTROLLER_RETRIES + 1):

        try:
            response = requests.post(
                url,
                json=payload,
                timeout=config.CONTROLLER_TIMEOUT
            )

            response.raise_for_status()
            return response.json()

        except requests.RequestException as error:

            logger.error(f"Controller error: {error}")

            if attempt < config.CONTROLLER_RETRIES:
                time.sleep(1)

        except ValueError:
            logger.error("Invalid controller response")
            return None

    return None


# ---------------------------------------
# Brute-force protection
# ---------------------------------------

def verify_credentials(username, password, client_ip):

    user = USERS.get(username)

    if user is None:
        salt = secrets.token_hex(16)
        expected = hashlib.sha256(
            (salt + password).encode()
        ).hexdigest()

        hmac.compare_digest(expected, "0" * 64)
        valid = False

    else:
        calculated_hash = hashlib.sha256(
            (user["salt"] + password).encode()
        ).hexdigest()

        valid = hmac.compare_digest(
            calculated_hash,
            user["password_hash"]
        )

    if valid:

        with attempt_lock:
            failed_attempts.pop(client_ip, None)

        return True, 0

    with attempt_lock:
        attempts = failed_attempts.get(client_ip, 0) + 1
        failed_attempts[client_ip] = attempts

    log_event(
        "AUTH_FAIL",
        username,
        client_ip,
        "bad_credentials"
    )

    if attempts >= config.MAX_FAILED_ATTEMPTS:

        result = controller_post(
            "/acl/block",
            {
                "ip": client_ip,
                "duration": config.BLOCK_DURATION_S,
                "reason": "bruteforce"
            }
        )

        if result is None or result.get("action") != "blocked":
            log_event(
                "ERROR", username, client_ip,
                "controller_block_failed"
            )
            return False, -1

        with attempt_lock:
            blocked_until[client_ip] = (
                time.time() + config.BLOCK_DURATION_S
            )

        log_event(
            "BLOCK_REQUEST",
            username,
            client_ip,
            "3 failures"
        )

        return False, 0

    return False, config.MAX_FAILED_ATTEMPTS - attempts


# ---------------------------------------
# Session creation
# ---------------------------------------

def create_session(username, client_ip):

    role = USERS[username]["role"]

    allowed_services = POLICY["roles"][role]["services"]

    ttl = config.SESSION_TTL_S

    token = secrets.token_hex(16)

    # Enforce one session per IP
    with session_lock:
        old_session = next(
            (
                (key, value)
                for key, value in sessions.items()
                if value["ip"] == client_ip
            ),
            None
        )

    if old_session:

        old_token, old_data = old_session

        result = controller_post(
            "/acl/revoke",
            {"ip": client_ip, "reason": "new_login"}
        )

        if result is None or result.get("action") != "revoked":
            return None

        with session_lock:
            sessions.pop(old_token, None)

    # Grant network access before AUTH_OK
    result = controller_post(
        "/acl/grant",
        {
            "ip": client_ip,
            "user": username,
            "role": role,
            "ttl": ttl
        }
    )

    if result is None or result.get("action") != "granted":
        log_event(
            "ERROR", username, client_ip,
            "controller_unavailable"
        )
        return None

    current_time = time.time()

    with session_lock:
        sessions[token] = {
            "user": username,
            "role": role,
            "ip": client_ip,
            "login_time": current_time,
            "expires_at": current_time + ttl,
            "services": allowed_services
        }

    log_event(
        "AUTH_OK",
        username,
        client_ip,
        f"role={role}"
    )

    return {
        "type": "AUTH_OK",
        "token": token,
        "role": role,
        "services": allowed_services,
        "ttl": ttl
    }


# ---------------------------------------
# Session refresh
# ---------------------------------------

def refresh_session(token, client_ip):

    with session_lock:
        session = sessions.get(token)

        if (
            session is None
            or session["ip"] != client_ip
            or time.time() >= session["expires_at"]
        ):
            return {
                "type": "ERROR",
                "reason": "expired"
            }

        username = session["user"]
        role = session["role"]

    result = controller_post(
        "/acl/grant",
        {
            "ip": client_ip,
            "user": username,
            "role": role,
            "ttl": config.SESSION_TTL_S
        }
    )

    if result is None or result.get("action") != "granted":
        return {
            "type": "ERROR",
            "reason": "controller_unavailable"
        }

    with session_lock:

        if token not in sessions:
            return {
                "type": "ERROR",
                "reason": "expired"
            }

        sessions[token]["expires_at"] = (
            time.time() + config.SESSION_TTL_S
        )

    return {
        "type": "REFRESH_OK",
        "ttl": config.SESSION_TTL_S
    }


# ---------------------------------------
# Session logout
# ---------------------------------------

def logout_session(token, client_ip):

    with session_lock:
        session = sessions.get(token)

        if session is None or session["ip"] != client_ip:
            return {
                "type": "ERROR",
                "reason": "invalid_token"
            }

    result = controller_post(
        "/acl/revoke",
        {
            "ip": client_ip,
            "reason": "logout"
        }
    )

    if result is None or result.get("action") != "revoked":
        return {
            "type": "ERROR",
            "reason": "controller_unavailable"
        }

    with session_lock:
        sessions.pop(token, None)

    log_event(
        "LOGOUT",
        session["user"],
        client_ip,
        "logout"
    )

    return {"type": "LOGOUT_OK"}


# ---------------------------------------
# Automatic session expiry
# ---------------------------------------

def session_reaper():

    while True:

        time.sleep(1)

        current_time = time.time()

        with session_lock:
            expired = [
                (token, data)
                for token, data in sessions.items()
                if current_time >= data["expires_at"]
            ]

        for token, data in expired:

            result = controller_post(
                "/acl/revoke",
                {
                    "ip": data["ip"],
                    "reason": "expired"
                }
            )

            # OpenFlow hard timeout also expires the rules.
            with session_lock:
                sessions.pop(token, None)

            log_event(
                "EXPIRED",
                data["user"],
                data["ip"],
                "ttl"
            )


# ---------------------------------------
# Request processing
# ---------------------------------------

def process_request(message, client_ip):

    request_type = message.get("type")

    if request_type == "AUTH":

        username = message.get("user")
        password = message.get("pass")

        if not isinstance(username, str) or not isinstance(password, str):
            return {"type": "ERROR", "reason": "malformed"}

        with attempt_lock:
            if time.time() < blocked_until.get(client_ip, 0):
                return {
                    "type": "BLOCKED",
                    "retry_after": int(
                        blocked_until[client_ip] - time.time()
                    ) + 1
                }

        valid, attempts_left = verify_credentials(
            username,
            password,
            client_ip
        )

        if not valid:

            if attempts_left == -1:
                return {
                    "type": "ERROR",
                    "reason": "controller_unavailable"
                }

            if attempts_left == 0:
                return {
                    "type": "BLOCKED",
                    "retry_after": config.BLOCK_DURATION_S
                }

            return {
                "type": "AUTH_FAIL",
                "reason": "bad_credentials",
                "attempts_left": attempts_left
            }

        response = create_session(username, client_ip)

        if response is None:
            return {
                "type": "ERROR",
                "reason": "controller_unavailable"
            }

        return response

    if request_type == "REFRESH":

        token = message.get("token")

        if not isinstance(token, str):
            return {"type": "ERROR", "reason": "malformed"}

        return refresh_session(token, client_ip)

    if request_type == "LOGOUT":

        token = message.get("token")

        if not isinstance(token, str):
            return {"type": "ERROR", "reason": "malformed"}

        return logout_session(token, client_ip)

    return {
        "type": "ERROR",
        "reason": "unknown_request"
    }


# ---------------------------------------
# TCP client handler
# ---------------------------------------

def handle_client(conn, address):

    client_ip = address[0]

    try:

        conn.settimeout(config.SERVER_TIMEOUT)

        with conn.makefile("rb") as stream:

            raw_message = stream.readline(
                config.MAX_MESSAGE_SIZE + 1
            )

        if not raw_message:
            return

        if (
            len(raw_message) > config.MAX_MESSAGE_SIZE
            or not raw_message.endswith(b"
")
        ):
            response = {
                "type": "ERROR",
                "reason": "malformed"
            }

        else:

            try:
                message = json.loads(raw_message.decode("utf-8"))

                if not isinstance(message, dict):
                    raise ValueError("JSON object required")

                response = process_request(
                    message,
                    client_ip
                )

            except (ValueError, UnicodeDecodeError):
                response = {
                    "type": "ERROR",
                    "reason": "malformed"
                }

        conn.sendall(
            (json.dumps(response) + "
").encode("utf-8")
        )

    except socket.timeout:
        logger.warning(f"Client timeout: {client_ip}")

    except OSError as error:
        logger.error(f"Socket error: {error}")

    finally:
        conn.close()


# ---------------------------------------
# Main TCP authentication server
# ---------------------------------------

def start_server():

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind((
        "0.0.0.0",
        config.AUTH_PORT
    ))

    server.listen(config.SERVER_BACKLOG)

    threading.Thread(
        target=session_reaper,
        daemon=True
    ).start()

    logger.info(
        f"Authentication server listening on port {config.AUTH_PORT}"
    )

    while True:

        try:
            conn, address = server.accept()

            threading.Thread(
                target=handle_client,
                args=(conn, address),
                daemon=True
            ).start()

        except OSError as error:
            logger.error(f"Accept error: {error}")


if __name__ == "__main__":
    try:
        start_server()

    except KeyboardInterrupt:
        logger.info("Authentication server stopped")
