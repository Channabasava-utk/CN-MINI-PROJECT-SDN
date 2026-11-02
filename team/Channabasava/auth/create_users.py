import getpass
import hashlib
import json
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUTPUT_FILE = ROOT / "users.json"

ACCOUNTS = {
    "alice": "user",
    "bob": "admin",
    "carol": "user",
}


def main():
    if OUTPUT_FILE.exists():
        answer = input("users.json already exists. Replace it? [y/N]: ").strip().lower()
        if answer != "y":
            print("Keeping the existing users.json.")
            return

    users = {}

    for username, role in ACCOUNTS.items():
        print(f"Set a password for {username} ({role})")
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")

        if not password:
            raise SystemExit("Password cannot be empty.")
        if password != confirm:
            raise SystemExit(f"Passwords did not match for {username}.")

        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()

        users[username] = {
            "salt": salt,
            "password_hash": password_hash,
            "role": role,
        }

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump({"users": users}, file, indent=4)
        file.write("\n")

    try:
        OUTPUT_FILE.chmod(0o600)
    except OSError:
        pass

    print(f"Created {OUTPUT_FILE}. Keep this file private and do not commit it.")


if __name__ == "__main__":
    main()
