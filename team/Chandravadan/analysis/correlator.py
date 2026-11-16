"""Chronological correlation of authentication, controller and access events."""


def correlate_events(auth_log, controller_log, access_results, host_ip_map=None):
    host_ip_map = host_ip_map or {}
    timeline = []

    def add(ts, source, event, ip, user=None, details=None, **extra):
        row = {
            "ts": ts, "source": source, "event": event,
            "ip": ip, "user": user, "details": details or {},
        }
        row.update(extra)
        timeline.append(row)

    for event in auth_log.get("events", []):
        add(event["ts"], "authentication", event["event"], event.get("ip"),
            event.get("user"), {"detail": event.get("detail")})

    for event in controller_log.get("events", []):
        add(event["ts"], "controller", event["action"], event.get("ip"),
            details={
                "reason": event.get("reason"),
                "flows_changed": event.get("flows_changed"),
                "install_ms": event.get("install_ms"),
            })

    for attempt in access_results.get("attempts", []):
        src = attempt["src"]
        ip = host_ip_map.get(src, src)
        add(
            attempt["ts"], "access",
            "ACCESS_SUCCESS" if attempt["success"] else "ACCESS_FAILURE",
            ip, details={
                "src": src, "dst": attempt["dst"], "port": attempt["port"],
                "success": attempt["success"], "latency_ms": attempt.get("latency_ms"),
                "error": attempt.get("error"),
            }, host=src,
        )

    timeline.sort(key=lambda row: (row["ts"], {"authentication": 0, "controller": 1, "access": 2}.get(row["source"], 3)))

    # Track state per client IP; logout/expiry/revoke/block invalidate prior grants.
    state = {}
    for row in timeline:
        ip = row.get("ip")
        if not ip:
            continue
        if row["source"] == "authentication":
            if row["event"] == "AUTH_OK":
                state.setdefault(ip, {})["auth"] = row
                state[ip]["authenticated"] = True
            elif row["event"] in ("LOGOUT", "EXPIRED", "BLOCK_REQUEST"):
                state.setdefault(ip, {})["auth"] = row
                state[ip]["authenticated"] = False
        elif row["source"] == "controller":
            state.setdefault(ip, {})["controller"] = row
            if row["event"] in ("GRANT",):
                state[ip]["controller_allowed"] = True
            elif row["event"] in ("REVOKE", "BLOCK", "DENY"):
                state[ip]["controller_allowed"] = False
        elif row["source"] == "access":
            current = state.get(ip, {})
            row["correlation"] = {
                "last_auth_event": current.get("auth", {}).get("event"),
                "last_controller_action": current.get("controller", {}).get("event"),
                "authenticated_at_attempt": bool(current.get("authenticated", False)),
                "controller_allowed_at_attempt": current.get("controller_allowed"),
            }
    return timeline
