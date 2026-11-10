import argparse
import json
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

import config

RESULT_FILE = ROOT / "data" / "access_results.json"


def probe_service(src, dst_label, target_host, port, timeout=2.0):
    """Make one TCP access attempt and return the agreed analysis schema."""
    started = time.perf_counter()
    attempt = {
        "src": src,
        "dst": dst_label,
        "port": port,
        "ts": time.time(),
        "success": False,
        "latency_ms": None,
        "error": None,
    }

    try:
        with socket.create_connection((target_host, port), timeout=timeout):
            attempt["success"] = True
            attempt["latency_ms"] = round(
                (time.perf_counter() - started) * 1000, 2
            )
    except OSError as exc:
        attempt["error"] = f"{type(exc).__name__}: {exc}"

    return attempt


def main():
    parser = argparse.ArgumentParser(
        description="Record SDN web/admin access attempts for analysis."
    )
    parser.add_argument("--run-id", default="run1")
    parser.add_argument("--scenario", default="A3")
    parser.add_argument("--mode", choices=("dynamic", "static"), default="dynamic")
    parser.add_argument(
        "--src",
        default="h1",
        help="Source Mininet host label, e.g. h1, h2 or h3",
    )
    parser.add_argument(
        "--web-host",
        default=config.WEB_SERVER_IP,
        help="IP/hostname to connect to for the web service",
    )
    parser.add_argument("--web-dst", default="h5", help="Analysis label for web destination")
    parser.add_argument(
        "--admin-host",
        default=config.ADMIN_SERVER_IP,
        help="IP/hostname to connect to for the admin service",
    )
    parser.add_argument(
        "--admin-dst", default="h6", help="Analysis label for admin destination"
    )
    parser.add_argument("--count", type=int, default=1, help="Attempts per service")
    parser.add_argument(
        "--interval",
        type=float,
        default=config.PROBE_INTERVAL_S,
        help="Delay between attempts to each service",
    )
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument(
        "--output",
        type=Path,
        default=RESULT_FILE,
        help="Output JSON path (default: data/access_results.json)",
    )
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be at least 1")
    if args.interval < 0 or args.timeout <= 0:
        parser.error("--interval must be non-negative and --timeout must be positive")

    attempts = []
    targets = (
        ("web", args.web_dst, args.web_host, config.WEB_PORT),
        ("admin", args.admin_dst, args.admin_host, config.ADMIN_PORT),
    )

    for round_number in range(args.count):
        for service, dst_label, target_host, port in targets:
            attempt = probe_service(
                args.src, dst_label, target_host, port, timeout=args.timeout
            )
            attempts.append(attempt)
            state = "SUCCESS" if attempt["success"] else "FAILED"
            print(
                f"{service.upper()} {args.src}->{dst_label}:{port}: {state}"
                f" (latency_ms={attempt['latency_ms']}, error={attempt['error']})"
            )
        if round_number < args.count - 1:
            time.sleep(args.interval)

    result = {
        "run_id": args.run_id,
        "scenario": args.scenario,
        "mode": args.mode,
        "attempts": attempts,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=2)

    print(f"\nSaved {len(attempts)} access attempts to: {args.output}")


if __name__ == "__main__":
    main()
