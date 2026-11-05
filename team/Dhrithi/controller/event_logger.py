from pathlib import Path
import json
import os
import threading
import time


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_LOG_PATH = REPOSITORY_ROOT / "data" / "controller_log.json"


class EventLogger:
    """Append controller events to the shared repository data directory."""

    def __init__(self, filepath=None):
        self.filepath = Path(filepath) if filepath else DEFAULT_LOG_PATH
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()

        if not self.filepath.exists() or self.filepath.stat().st_size == 0:
            self._write_entries([])

    def _write_entries(self, entries):
        temporary_file = self.filepath.with_name(self.filepath.name + ".tmp")
        with temporary_file.open("w", encoding="utf-8") as file:
            json.dump(entries, file, indent=4)
            file.write("\n")
        os.replace(str(temporary_file), str(self.filepath))

    def read_all(self):
        with self.lock:
            try:
                with self.filepath.open("r", encoding="utf-8") as file:
                    entries = json.load(file)
            except FileNotFoundError:
                return []
            if not isinstance(entries, list):
                raise ValueError("Controller log must contain a JSON list")
            return entries

    def log(self, event, ip=None, details=None):
        entry = {
            "timestamp": time.time(),
            "event": event,
            "ip": ip,
            "details": details or {}
        }

        with self.lock:
            try:
                with self.filepath.open("r", encoding="utf-8") as file:
                    entries = json.load(file)
                if not isinstance(entries, list):
                    entries = []
            except (json.JSONDecodeError, FileNotFoundError):
                entries = []

            entries.append(entry)
            self._write_entries(entries)

        return entry
