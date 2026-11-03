import time
import threading


class SessionManager:
    """Manages temporary authenticated network sessions."""

    def __init__(self):
        self.sessions = {}
        self.lock = threading.RLock()

    def create_session(self, ip, role, services, ttl=60):
        if role not in ("user", "admin"):
            raise ValueError("Invalid role")

        if not isinstance(ttl, (int, float)) or ttl <= 0:
            raise ValueError("TTL must be positive")

        now = time.time()

        session = {
            "ip": ip,
            "role": role,
            "services": services,
            "created_at": now,
            "expires_at": now + ttl
        }

        with self.lock:
            self.sessions[ip] = session

        return session.copy()

    def get_session(self, ip):
        with self.lock:
            self.cleanup_expired()

            session = self.sessions.get(ip)

            return session.copy() if session else None

    def revoke_session(self, ip):
        with self.lock:
            return self.sessions.pop(ip, None) is not None

    def cleanup_expired(self):
        now = time.time()

        with self.lock:
            expired = [
                ip for ip, session in self.sessions.items()
                if session["expires_at"] <= now
            ]

            for ip in expired:
                del self.sessions[ip]

        return expired

    def get_active_sessions(self):
        with self.lock:
            self.cleanup_expired()

            return {
                ip: session.copy()
                for ip, session in self.sessions.items()
            }
