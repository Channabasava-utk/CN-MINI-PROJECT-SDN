import sys
import json
import time
import socket
import argparse
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import config

RESULT_FILE = ROOT / "data" / "access_results.json"


def probe_service(name, host, port, timeout=2):
    start = time.perf_counter()

    result = {
        "service": name,
        "host": host,
        "port": port,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    try:
        with socket.create_connection(
            (host, port), timeout=timeout
        ):
            result["status"] = "REACHABLE"
            result["latency_ms"] = round(
                (time.perf_counter() - start) * 1000, 2
            )

    except OSError as error:
        result["status"] = "BLOCKED_OR_UNAVAILABLE"
        result["error"] = str(error)

    return result


def save_result(result):
    RESULT_FILE.parent.mkdir(parents=True, exist_ok=True)

    if RESULT_FILE.exists():
        with open(RESULT_FILE, "r") as file:
            records = json.load(file)
    else:
        records = []

    records.append(result)

    with open(RESULT_FILE, "w") as file:
        json.dump(records, file, indent=4)


def main():
    parser = argparse.ArgumentParser(
        description="SDN Network Access Probe"
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Target service host"
    )

    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Number of probe rounds"
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=config.PROBE_INTERVAL_S,
        help="Delay between probe rounds"
    )

    args = parser.parse_args()

    if args.count < 1 or args.interval < 0:
        parser.error("Count must be positive and interval non-negative")

    services = [
        ("web", config.WEB_PORT),
        ("admin", config.ADMIN_PORT)
    ]

    print("SDN Network Access Probe")
    print("------------------------")

    for round_number in range(args.count):
        print(f"\nProbe round {round_number + 1}")

        for name, port in services:
            result = probe_service(name, args.host, port)
            save_result(result)

            print(
                f"{name.upper()}: {result['status']}"
                f" | Port: {port}"
            )

        if round_number < args.count - 1:
            time.sleep(args.interval)

    print(f"\nResults saved to: {RESULT_FILE}")


if __name__ == "__main__":
    main()
