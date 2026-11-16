"""Run the complete SDN analysis pipeline from repository data/."""
import json
from pathlib import Path

from loader import (
    load_auth_log, load_access_results, load_controller_log,
    load_topology, load_acl_state,
)
from correlator import correlate_events
from compliance import load_policy, evaluate_compliance, save_compliance_report
from metrics import calculate_metrics
from visualizer import plot_access_timeline, plot_topology

ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = ROOT / "data"
ANALYSIS_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = ANALYSIS_DIR / "output"
TOPOLOGY_FILE = ROOT / "team" / "Dhrithi" / "topology" / "topology.json"
POLICY_FILE = ROOT / "team" / "Dhrithi" / "controller" / "policy.json"


def _write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=4)


def main():
    required = [
        DATA_DIR / "auth_log.json",
        DATA_DIR / "access_results.json",
        DATA_DIR / "controller_log.json",
        TOPOLOGY_FILE,
        POLICY_FILE,
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError(
            "Cannot run analysis; required integrated project files are missing:\n  "
            + "\n  ".join(missing)
        )

    print("Loading integrated SDN project data...")
    auth = load_auth_log(DATA_DIR / "auth_log.json")
    access = load_access_results(DATA_DIR / "access_results.json")
    controller = load_controller_log(DATA_DIR / "controller_log.json")
    topology = load_topology(TOPOLOGY_FILE)
    policy = load_policy(POLICY_FILE)

    acl_path = DATA_DIR / "acl_state.json"
    acl = load_acl_state(acl_path) if acl_path.is_file() else {"sessions": [], "blocked": []}

    host_ip_map = topology.get("hosts", {})
    timeline = correlate_events(auth, controller, access, host_ip_map)
    compliance = evaluate_compliance(auth, controller, access, policy, topology)
    metrics = calculate_metrics(auth, controller, access, compliance, host_ip_map=host_ip_map)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    _write_json(OUTPUT_DIR / "correlated_events.json", timeline)
    _write_json(OUTPUT_DIR / "compliance_report.json", compliance)
    _write_json(OUTPUT_DIR / "metrics.json", metrics)

    plot_access_timeline(timeline)
    blocked = [item["ip"] for item in acl.get("blocked", [])]
    blocked.extend(
        event["ip"] for event in controller.get("events", [])
        if event.get("action") == "BLOCK" and event.get("ip")
    )
    plot_topology(topology, blocked_hosts=blocked)

    print("\nSDN analysis completed.")
    print(f"Correlated events: {len(timeline)}")
    print(f"Compliance attempts: {compliance['summary']['total_attempts']}")
    print(f"Metrics and reports: {OUTPUT_DIR}")
    print(f"Visualisations: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
