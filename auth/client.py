import os
import sys
import json
import socket
import argparse
import getpass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import config

SERVER_HOST = os.getenv("AUTH_SERVER_HOST", "127.0.0.1")
SERVER_PORT = config.AUTH_PORT


def send_request(request):
    message = json.dumps(request).encode("utf-8") + b"\n"

    try:
        with socket.create_connection(
            (SERVER_HOST, SERVER_PORT),
            timeout=config.CLIENT_TIMEOUT
        ) as sock:
            sock.sendall(message)

            with sock.makefile("rb") as stream:
                response = stream.readline(config.MAX_MESSAGE_SIZE + 1)

            if not response or len(response) > config.MAX_MESSAGE_SIZE:
                return None

            return json.loads(response.decode("utf-8"))

    except (OSError, json.JSONDecodeError) as error:
        print("Communication error:", error)
        return None


def login():
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    response = send_request({
        "type": "AUTH",
        "user": username,
        "pass": password
    })

    print(json.dumps(response, indent=4))

    if response and response.get("type") == "AUTH_OK":
        print("\nLogin successful!")
        print("Save this token:", response["token"])


def refresh():
    token = input("Session token: ").strip()

    response = send_request({
        "type": "REFRESH",
        "token": token
    })

    print(json.dumps(response, indent=4))


def logout():
    token = input("Session token: ").strip()

    response = send_request({
        "type": "LOGOUT",
        "token": token
    })

    print(json.dumps(response, indent=4))


def main():
    parser = argparse.ArgumentParser(
        description="SDN Authentication Client"
    )

    parser.add_argument(
        "action",
        choices=["login", "refresh", "logout"]
    )

    action = parser.parse_args().action

    if action == "login":
        login()
    elif action == "refresh":
        refresh()
    elif action == "logout":
        logout()


if __name__ == "__main__":
    main()
