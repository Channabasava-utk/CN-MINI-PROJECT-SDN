"""Calculate evaluation metrics from actual project logs and probe results."""


def _mean(values):
    return round(sum(values) / len(values), 3) if values else None


def calculate_metrics(auth_log, controller_log, access_results, compliance_result=None, throughput_samples=None, host_ip_map=None):
    auth_events = sorted(auth_log.get("events", []), key=lambda e: e["ts"])
    controller_events = sorted(controller_log.get("events", []), key=lambda e: e["ts"])
    attempts = sorted(access_results.get("attempts", []), key=lambda e: e["ts"])
    host_ip_map = host_ip_map or {}

    # AUTH_OK is emitted after the controller grant; actual service reachability is measured
    # by the first successful probe after AUTH_OK, not by the GRANT log timestamp.
    grant_delays = []
    auth_ok_events = [e for e in auth_events if e.get("event") == "AUTH_OK"]
    for auth in auth_ok_events:
        candidates = [
            a for a in attempts
            if host_ip_map.get(a.get("src"), a.get("src")) == auth.get("ip")
            and a["ts"] >= auth["ts"] and a["success"]
        ]
        if candidates:
            first = min(candidates, key=lambda a: a["ts"])
            grant_delays.append((first["ts"] - auth["ts"]) * 1000)

    # Revoke delay is measured to the first failed access attempt after logout/expiry/block.
    revoke_delays = []
    revoke_triggers = [e for e in auth_events if e.get("event") in ("LOGOUT", "EXPIRED", "BLOCK_REQUEST")]
    for trigger in revoke_triggers:
        candidates = [
            a for a in attempts
            if host_ip_map.get(a.get("src"), a.get("src")) == trigger.get("ip")
            and a["ts"] >= trigger["ts"] and not a["success"]
        ]
        if candidates:
            first = min(candidates, key=lambda a: a["ts"])
            revoke_delays.append((first["ts"] - trigger["ts"]) * 1000)

    # Count consecutive failures per IP up to the block request.
    failed_before_block = []
    failure_counts = {}
    for event in auth_events:
        ip = event.get("ip")
        if event.get("event") == "AUTH_FAIL":
            failure_counts[ip] = failure_counts.get(ip, 0) + 1
        elif event.get("event") == "BLOCK_REQUEST":
            failed_before_block.append(failure_counts.get(ip, 0))
            failure_counts[ip] = 0
        elif event.get("event") == "AUTH_OK":
            failure_counts[ip] = 0

    install_samples = [
        e["install_ms"] for e in controller_events
        if isinstance(e.get("install_ms"), (int, float)) and not isinstance(e.get("install_ms"), bool)
    ]

    summary = (compliance_result or {}).get("summary", {})
    throughput = throughput_samples or []
    throughput_values = [
        item["throughput_mbps"] if isinstance(item, dict) else item
        for item in throughput
        if (isinstance(item, dict) and isinstance(item.get("throughput_mbps"), (int, float)))
        or (isinstance(item, (int, float)) and not isinstance(item, bool))
    ]

    return {
        # Not inferable from the current auth event schema: AUTH_OK is logged after
        # controller grant, and no request-start timestamp is recorded.
        "average_auth_latency_ms": None,
        "average_time_to_grant_ms": _mean(grant_delays),
        "average_time_to_revoke_ms": _mean(revoke_delays),
        "unauthorized_successful_requests": summary.get("unauthorized_successful_requests"),
        "unauthorized_success_percentage": summary.get("unauthorized_success_percentage"),
        "false_denials": summary.get("false_denials"),
        "false_denial_percentage": summary.get("false_denial_percentage"),
        "failed_attempts_accepted_before_block": max(failed_before_block) if failed_before_block else 0,
        "average_rule_install_ms": _mean(install_samples),
        "authorized_throughput_mbps": _mean(throughput_values),
        "samples": {
            "grant_delay": len(grant_delays),
            "revoke_delay": len(revoke_delays),
            "rule_install": len(install_samples),
            "throughput": len(throughput_values),
        },
        "unavailable_metrics": [
            name for name, value in (
                ("average_auth_latency_ms", None if True else 0),
                ("authorized_throughput_mbps", _mean(throughput_values)),
            ) if value is None
        ],
    }
