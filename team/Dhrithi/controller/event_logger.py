import json
import os
import time
import threading


class EventLogger:
    def __init__(self, filepath="data/controller_log.json"):
        self.filepath = filepath
        self.lock = threading.Lock()
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            with open(filepath, "w") as file:
                json.dump([], file)

    def log(self, event, ip=None, details=None):
        entry = {
            "timestamp": time.time(),
            "event": event,
            "ip": ip,
            "details": details or {}
        }

        with self.lock:
            try:
                with open(self.filepath, "r") as file:
                    entries = json.load(file)
            except (json.JSONDecodeError, FileNotFoundError):
                entries = []

            entries.append(entry)

            temporary_file = self.filepath + ".tmp"
            with open(temporary_file, "w") as file:
                json.dump(entries, file, indent=4)

            os.replace(temporary_file, self.filepath)

        return entry
