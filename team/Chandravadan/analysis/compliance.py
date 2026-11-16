"""Evaluate observed access attempts against the project's static/dynamic policy."""
import json
from pathlib import Path

DEFAULT_SERVICE_ENDPOINTS = {
    "web": ("10.0.0.5", 8000),
    "admin": ("10.0.0.6", 8001),
}


def load_policy(policy_path):
    with open(policy_path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def _host_ip_map(topology):
    return {
        host: (value.get("ip") if isinstance(value, dict) else value)
        for host, value in topology.get("hosts", {}).items()
    }


def _normalise_policy(policy, topology):
    """Accept both root policy.json (service names) and controller policy.json (IP/port objects)."""
    endpoints = dict(DEFAULT_SERVICE_ENDPOINTS)
    hosts = _host_ip_map(topology)
    if hosts.get("h5"):
        endpoints["web"] = (hosts["h5"], 8000)
    if hosts.get("h6"):
        endpoints["admin"] = (hosts["h6"], 8001)

    role_services = {}
    for role, definition in policy.get("roles", {}).items():
        services = definition.get("services", [])
        names = set()
        for item in services:
            if isinstance(item, str):
                names.add(item)
            elif isinstance(item, dict):
                name = item.get("name")
                if name:
                    endpoints[name] = (item.get("ip"), int(item.get("port", 0)))
                    names.add(name)
        role_services[role] = names
    return endpoints, role_services


def evaluate_compliance(auth_log, controller_log, access_results, policy, topology):
    host_to_ip = _host_ip_map(topology)
    ip_to_host = {ip: host for host, ip in host_to_ip.items()}
    endpoints, role_services = _normalise_policy(policy, topology)

    # Map target labels (h5/h6) and ports to service names.
    service_by_target = {}
    for service, (ip, port) in endpoints.items():
        service_by_target[(ip, int(port))] = service
        host = ip_to_host.get(ip)
        if host:
            service_by_target[(host, int(port))] = service

    auth_events = sorted(auth_log.get("events", []), key=lambda e: e["ts"])
    controller_events = sorted(controller_log.get("events", []), key=lambda e: e["ts"])

    role_history = {}
    for event in auth_events:
        if event.get("event") == "AUTH_OK" and event.get("ip"):
            detail = event.get("detail") or ""
            role = next((part.split("=", 1)[1] for part in detail.split() if part.startswith("role=")), None)
            if role:
                role_history.setdefault(event["ip"], []).append((event["ts"], role))

    # Reconstruct active intervals from controller events. Session records are per-IP.
    active = {}
    intervals = []
    for event in controller_events:
        ip, action, ts = event.get("ip"), event.get("action"), event["ts"]
        if not ip:
            continue
        if action == "GRANT":
            if ip in active:
                active[ip]["end"] = ts
            interval = {"ip": ip, "start": ts, "end": None}
            intervals.append(interval)
            active[ip] = interval
        elif action in ("REVOKE", "BLOCK"):
            if ip in active:
                active[ip]["end"] = ts
                active.pop(ip, None)

    # Auth logout/expiry are also session boundaries, even if controller log is delayed/missing.
    for event in auth_events:
        if event.get("event") in ("LOGOUT", "EXPIRED", "BLOCK_REQUEST"):
            ip = event.get("ip")
            if ip in active:
                active[ip]["end"] = min(active[ip]["end"] or event["ts"], event["ts"])
                active.pop(ip, None)

    mode = access_results.get("mode")
    if mode not in ("static", "dynamic"):
        raise ValueError(f"Unknown mode: {mode}")

    static_allow = {"10.0.0.1": {"web"}, "10.0.0.2": {"web", "admin"}}
    evaluated = []
    for attempt in access_results.get("attempts", []):
        src = attempt["src"]
        ip = host_to_ip.get(src, src)
        dst, port, ts = attempt["dst"], int(attempt["port"]), attempt["ts"]
        success = attempt["success"]
        target_ip = host_to_ip.get(dst, endpoints.get("web", (None,))[0] if dst == "web" else endpoints.get("admin", (None,))[0] if dst == "admin" else None)
        service = service_by_target.get((dst, port)) or service_by_target.get((target_ip, port))
        if service is None:
            service = next((name for name, (_, p) in endpoints.items() if p == port), None)
            if target_ip is None and service:
                target_ip = endpoints[service][0]

        role = None
        for role_ts, role_value in role_history.get(ip, []):
            if role_ts <= ts:
                role = role_value
            else:
                break

        if mode == "static":
            expected = service in static_allow.get(ip, set())
            reason = "Static allow-list" if expected else "Not in static allow-list"
        else:
            session_active = any(
                interval["ip"] == ip and interval["start"] <= ts
                and (interval["end"] is None or ts < interval["end"])
                for interval in intervals
            )
            permitted = service in role_services.get(role, set())
            expected = bool(session_active and permitted and service is not None)
            if not session_active:
                reason = "No active controller session"
            elif not role:
                reason = "No authenticated role at attempt time"
            elif not permitted:
                reason = "Role not permitted for service"
            else:
                reason = "Active session and role policy permit service"

        evaluated.append({
            "src": src, "ip": ip, "role": role, "dst": dst, "port": port,
            "service": service, "ts": ts, "mode": mode,
            "expected_allowed": expected, "actual_success": success,
            "unauthorized_success": bool(success and not expected),
            "false_denial": bool(expected and not success), "reason": reason,
        })

    total = len(evaluated)
    leaks = sum(item["unauthorized_success"] for item in evaluated)
    false_denials = sum(item["false_denial"] for item in evaluated)
    return {
        "attempts": evaluated,
        "summary": {
            "total_attempts": total,
            "unauthorized_successful_requests": leaks,
            "unauthorized_success_percentage": round(100 * leaks / total, 2) if total else 0,
            "false_denials": false_denials,
            "false_denial_percentage": round(100 * false_denials / total, 2) if total else 0,
            "correct_decisions": total - leaks - false_denials,
        },
    }


def save_compliance_report(result, output_path):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=4)
    return path
