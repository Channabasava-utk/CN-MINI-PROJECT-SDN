from pathlib import Path
import json
import os
import threading
import time


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_LOG_PATH = REPOSITORY_ROOT / "data" / "controller_log.json"


class EventLogger:
    """Append controller events in the shared project JSON format."""

    EVENT_MAP = {
        "SESSION_GRANTED": ("GRANT", "auth_ok"),
        "SESSION_REVOKED": ("REVOKE", "revoked"),
        "SESSION_EXPIRED": ("REVOKE", "expired"),
        "CLIENT_BLOCKED": ("BLOCK", "bruteforce"),
        "CLIENT_UNBLOCKED": ("UNBLOCK", "block_expired"),
        "MODE_CHANGED": ("MODE", "mode_changed"),
        "MODE_CHANGE_FAILED": ("MODE", "mode_change_failed"),
        "BLOCK_INSTALL_FAILED": ("DENY", "block_install_failed"),
        "SCAN_DETECTED": ("DENY", "scan_detected"),
        "REST_ACCESS_DENIED": ("DENY", "rest_access_denied"),
    }

    def __init__(self, filepath=None):
        self.filepath = Path(filepath) if filepath else DEFAULT_LOG_PATH
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()

        if not self.filepath.exists() or self.filepath.stat().st_size == 0:
            self._write_entries([])

    def _read_entries(self):
        try:
            with self.filepath.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

        if isinstance(data, dict):
            entries = data.get("events", [])
        elif isinstance(data, list):
            entries = data
        else:
            raise ValueError("Invalid controller log format")

        normalized = []

        for entry in entries:
            if "ts" in entry and "action" in entry:
                normalized.append(entry)
                continue

            event = entry.get("event", "")
            if event in ("SWITCH_CONNECTED", "SWITCH_DISCONNECTED"):
                continue

            action, default_reason = self.EVENT_MAP.get(
                event, (event.upper(), event.lower())
            )
            details = entry.get("details") or {}

            normalized.append({
                "ts": entry.get("timestamp"),
                "action": action,
                "ip": entry.get("ip"),
                "reason": details.get("reason", default_reason),
                "flows_changed": details.get("flows_changed"),
                "install_ms": details.get("install_ms")
            })

        return normalized

    def _write_entries(self, entries):
        temporary_file = self.filepath.with_name(
            self.filepath.name + ".tmp"
        )

        with temporary_file.open("w", encoding="utf-8") as file:
            json.dump({"events": entries}, file, indent=4)
            file.write("\n")

        os.replace(str(temporary_file), str(self.filepath))

    def read_all(self):
        with self.lock:
            return {"events": self._read_entries()}

    def log(self, event, ip=None, details=None):
        if event in ("SWITCH_CONNECTED", "SWITCH_DISCONNECTED"):
            return None

        details = details or {}

        action, default_reason = self.EVENT_MAP.get(
            event, (event.upper(), event.lower())
        )

        entry = {
            "ts": time.time(),
            "action": action,
            "ip": ip,
            "reason": details.get("reason", default_reason),
            "flows_changed": details.get("flows_changed"),
            "install_ms": details.get("install_ms")
        }

        with self.lock:
            entries = self._read_entries()
            entries.append(entry)
            self._write_entries(entries)

        return entry
