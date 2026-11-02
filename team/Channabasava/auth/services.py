import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

import config


class ServiceHandler(BaseHTTPRequestHandler):

    service_name = "Unknown"

    def send_page(self, status, title, message):
        body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{title}</title>
            <style>
                body {{
                    font-family: Arial;
                    text-align: center;
                    margin-top: 100px;
                }}
            </style>
        </head>
        <body>
            <h1>{title}</h1>
            <p>{message}</p>
            <p>SDN Socket Project</p>
        </body>
        </html>
        """.encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path != "/":
            return self.send_page(
                404, "Not Found", "Requested page does not exist."
            )

        now = datetime.now(timezone.utc).isoformat()

        print(
            f"[{self.service_name}] Request from "
            f"{self.client_address[0]} at {now}"
        )

        return self.send_page(
            200,
            f"{self.service_name} Service",
            f"{self.service_name} service is running successfully."
        )

    def log_message(self, format, *args):
        print(f"[{self.service_name}] {format % args}")


class WebHandler(ServiceHandler):
    service_name = "WEB"


class AdminHandler(ServiceHandler):
    service_name = "ADMIN"


def start_service(service):
    if service == "web":
        host = "0.0.0.0"
        port = config.WEB_PORT
        handler = WebHandler

    elif service == "admin":
        host = "0.0.0.0"
        port = config.ADMIN_PORT
        handler = AdminHandler

    else:
        raise ValueError("Service must be web or admin")

    server = HTTPServer((host, port), handler)

    print(f"{service.upper()} service listening on port {port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{service.upper()} service stopped")
    finally:
        server.server_close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python auth/services.py [web|admin]")
        sys.exit(1)

    start_service(sys.argv[1].lower())
