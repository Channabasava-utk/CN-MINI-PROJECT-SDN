import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / "data"
AUTH_FILE = DATA / "auth_log.json"
CONTROLLER_FILE = DATA / "controller_log.json"
OUTPUT_FILE = DATA / "analysis_report.json"
CORRELATION_WINDOW = 5.0


def load_events(path):
    if not path.exists():
        print(f"Warning: {path.name} not found.")
        return []

    with path.open() as file:
        data = json.load(file)

    events = data.get("events", [])
    return events if isinstance(events, list) else []


def count_values(events, field):
    return dict(sorted(Counter(
        event.get(field, "UNKNOWN") for event in events
    ).items()))


def correlate_events(auth_events, controller_events):
    """Match events from the same IP within the configured time window."""
    available = set(range(len(controller_events)))
    matches = []

    auth_events = sorted(
        auth_events, key=lambda event: event.get("ts", 0)
    )

    for auth in auth_events:
        auth_ip = auth.get("ip")
        auth_ts = auth.get("ts")

        if auth_ip is None or not isinstance(auth_ts, (int, float)):
            continue

        candidates = []

        for index in available:
            controller = controller_events[index]

            if controller.get("ip") != auth_ip:
                continue

            controller_ts = controller.get("ts")
            if not isinstance(controller_ts, (int, float)):
                continue

            difference = abs(controller_ts - auth_ts)

            if difference <= CORRELATION_WINDOW:
                candidates.append((difference, index))

        if candidates:
            difference, index = min(candidates)
            controller = controller_events[index]
            available.remove(index)

            matches.append({
                "auth_event": auth.get("event", "UNKNOWN"),
                "controller_action": controller.get("action", "UNKNOWN"),
                "time_difference_seconds": round(difference, 3)
            })

    return matches


def main():
    auth_events = load_events(AUTH_FILE)
    controller_events = load_events(CONTROLLER_FILE)

    auth_counts = count_values(auth_events, "event")
    controller_counts = count_values(controller_events, "action")

    matches = correlate_events(auth_events, controller_events)
    correlation_counts = Counter(
        f"{match['auth_event']} -> {match['controller_action']}"
        for match in matches
    )

    install_times = [
        event["install_ms"]
        for event in controller_events
        if isinstance(event.get("install_ms"), (int, float))
    ]

    flow_values = [
        event["flows_changed"]
        for event in controller_events
        if isinstance(event.get("flows_changed"), (int, float))
    ]

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "correlation_window_seconds": CORRELATION_WINDOW,
        "total_authentication_events": len(auth_events),
        "total_controller_events": len(controller_events),
        "authentication_event_counts": auth_counts,
        "controller_action_counts": controller_counts,
        "correlation": {
            "matched_event_pairs": len(matches),
            "unmatched_authentication_events": len(auth_events) - len(matches),
            "matched_pair_counts": dict(sorted(correlation_counts.items()))
        },
        "network_metrics": {
            "available_installation_time_samples": len(install_times),
            "average_installation_time_ms": (
                round(sum(install_times) / len(install_times), 3)
                if install_times else None
            ),
            "available_flow_change_samples": len(flow_values),
            "total_flows_changed": (
                sum(flow_values) if flow_values else None
            )
        }
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("w") as file:
        json.dump(report, file, indent=4)

    print("\n========== SDN LOG ANALYSIS ==========")
    print("Authentication events:", len(auth_events))
    print("Controller events:", len(controller_events))

    print("\nAuthentication summary:")
    for event, count in auth_counts.items():
        print(f"  {event}: {count}")

    print("\nController summary:")
    for action, count in controller_counts.items():
        print(f"  {action}: {count}")

    print("\nCorrelation summary:")
    print("  Matched event pairs:", len(matches))
    print("  Unmatched authentication events:",
          len(auth_events) - len(matches))

    for pair, count in sorted(correlation_counts.items()):
        print(f"  {pair}: {count}")

    print("\nNetwork metrics:")
    print("  Installation time samples:", len(install_times))
    print("  Average installation time (ms):",
          report["network_metrics"]["average_installation_time_ms"])
    print("  Flow-change samples:", len(flow_values))
    print("  Total flows changed:",
          report["network_metrics"]["total_flows_changed"])

    print("\nReport saved to:", OUTPUT_FILE.relative_to(ROOT))


if __name__ == "__main__":
    main()
