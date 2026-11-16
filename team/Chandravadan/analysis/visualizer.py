"""Generate evaluation-plan visualisations from analysis outputs."""
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUTPUT_DIR = Path(__file__).resolve().parent / "output"


def save_plot(filename):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / filename, dpi=220)
    plt.close()


def plot_static_dynamic_comparison(static, dynamic):
    specs = [
        ("Leaked Requests", "unauthorized_successful_requests"),
        ("Revoke Time (ms)", "average_time_to_revoke_ms"),
        ("False Denials", "false_denials"),
    ]
    for title, key in specs:
        if static.get(key) is None or dynamic.get(key) is None:
            continue
        plt.figure(figsize=(7, 4))
        plt.bar(["Static", "Dynamic"], [static[key], dynamic[key]])
        plt.title(title)
        plt.ylabel(title)
        save_plot(f"comparison_{key}.png")


def plot_access_timeline(timeline):
    if not timeline:
        return
    events = sorted(timeline, key=lambda row: row["ts"])
    start = events[0]["ts"]
    lanes = {"authentication": 3, "controller": 2, "access": 1}
    colors = {
        "AUTH_OK": "green", "LOGOUT": "orange", "EXPIRED": "red",
        "BLOCK_REQUEST": "darkred", "GRANT": "green", "REVOKE": "orange",
        "BLOCK": "red", "UNBLOCK": "purple", "ACCESS_SUCCESS": "blue",
        "ACCESS_FAILURE": "black",
    }
    plt.figure(figsize=(13, 5))
    for event in events:
        plt.scatter(
            event["ts"] - start, lanes.get(event["source"], 0),
            color=colors.get(event["event"], "gray"), s=28
        )
    plt.yticks([1, 2, 3], ["Access", "Controller", "Authentication"])
    plt.xlabel("Time elapsed (seconds)")
    plt.title("SDN Access and Security Event Timeline")
    plt.grid(True, axis="x", alpha=0.3)
    save_plot("access_timeline.png")


def plot_auth_latency_concurrency(results):
    if not results:
        return
    rows = [r for r in results if r.get("concurrent_users") is not None and r.get("average_auth_latency_ms") is not None]
    if not rows:
        return
    plt.figure(figsize=(8, 5))
    plt.plot([r["concurrent_users"] for r in rows], [r["average_auth_latency_ms"] for r in rows], marker="o")
    plt.xlabel("Concurrent Users")
    plt.ylabel("Average Authentication Latency (ms)")
    plt.title("Authentication Latency vs Concurrent Users")
    plt.grid(True, alpha=0.3)
    save_plot("auth_latency_concurrency.png")


def plot_a5_throughput(results):
    if not results:
        return
    rows = [r for r in results if r.get("elapsed_seconds") is not None and r.get("throughput_mbps") is not None]
    if not rows:
        return
    plt.figure(figsize=(9, 5))
    plt.plot([r["elapsed_seconds"] for r in rows], [r["throughput_mbps"] for r in rows], marker="o")
    plt.xlabel("Elapsed Time (seconds)")
    plt.ylabel("Authorized Throughput (Mbps)")
    plt.title("Scenario A5: Authorized Throughput Under Load")
    plt.grid(True, alpha=0.3)
    save_plot("a5_throughput.png")


def plot_topology(topology, allowed_paths=None, blocked_hosts=None):
    """Draw links from the actual topology file; blocked_hosts accepts host labels or IPs."""
    switches = topology["switches"]
    hosts = topology["hosts"]
    links = topology["links"]
    blocked = set(blocked_hosts or [])
    ip_to_host = {ip: host for host, ip in hosts.items()}
    blocked_names = {ip_to_host.get(item, item) for item in blocked}

    positions = {}
    for index, switch in enumerate(switches):
        positions[switch] = (index * 2.5, 1.5)
    switch_set = set(switches)
    host_links = []
    switch_links = []
    for left, right in links:
        if left in switch_set and right in switch_set:
            switch_links.append((left, right))
        elif left in switch_set and right in hosts:
            host_links.append((right, left))
        elif right in switch_set and left in hosts:
            host_links.append((left, right))
    host_counts = {}
    for host, switch in host_links:
        index = host_counts.get(switch, 0)
        host_counts[switch] = index + 1
        x, y = positions[switch]
        positions[host] = (x + (index - 1) * 0.85, 0 if host in ("h1", "h2", "h3") else 3)

    plt.figure(figsize=(12, 6))
    allowed_edges = set()
    for path in (allowed_paths or []):
        if isinstance(path, (list, tuple)) and len(path) >= 2:
            allowed_edges.update(zip(path, path[1:]))
    for left, right in switch_links + host_links:
        highlighted = (left, right) in allowed_edges or (right, left) in allowed_edges
        plt.plot(
            [positions[left][0], positions[right][0]],
            [positions[left][1], positions[right][1]],
            color="green" if highlighted else "gray",
            linewidth=3 if highlighted else 1.5,
        )
    for node, (x, y) in positions.items():
        is_blocked = node in blocked_names
        is_switch = node in switch_set
        plt.scatter(x, y, s=850 if is_switch else 550,
                    color="red" if is_blocked else ("#9bc2e6" if is_switch else "#d9ead3"),
                    edgecolors="black", zorder=3)
        plt.text(x, y, node, ha="center", va="center", zorder=4)
    plt.title("SDN Network Topology (red = blocked host)")
    plt.axis("off")
    save_plot("network_topology.png")
