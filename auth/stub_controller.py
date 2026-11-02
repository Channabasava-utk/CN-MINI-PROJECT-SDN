import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timedelta, timezone


class StubController(BaseHTTPRequestHandler):

    def send_json(self, status, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, ValueError):
            return self.send_json(400, {"error": "Invalid JSON"})

        if self.path == "/acl/grant":
            expires = (
                datetime.now(timezone.utc)
                + timedelta(seconds=int(data.get("ttl", 60)))
            ).isoformat()

            print(f"[STUB] GRANT: {data.get('ip')} role={data.get('role')}")

            return self.send_json(200, {
                "action": "granted",
                "services": ["web", "admin"]
                if data.get("role") == "admin" else ["web"],
                "expires_at": expires
            })

        if self.path == "/acl/revoke":
            print(f"[STUB] REVOKE: {data.get('ip')}")

            return self.send_json(200, {
                "action": "revoked",
                "flows_removed": 6
            })

        if self.path == "/acl/block":
            until = (
                datetime.now(timezone.utc)
                + timedelta(seconds=int(data.get("duration", 60)))
            ).isoformat()

            print(f"[STUB] BLOCK: {data.get('ip')}")

            return self.send_json(200, {
                "action": "blocked",
                "until": until
            })

        return self.send_json(404, {"error": "Unknown endpoint"})

    def log_message(self, format, *args):
        print("[HTTP]", format % args)


if __name__ == "__main__":
    print("Stub controller running on 127.0.0.1:8080")
    HTTPServer(("127.0.0.1", 8080), StubController).serve_forever()
