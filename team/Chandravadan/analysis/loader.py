"""JSON loaders and schema validation for the SDN mini-project."""
import ipaddress
import json
from pathlib import Path


class DataValidationError(Exception):
    """Raised when project JSON does not satisfy its data contract."""


AUTH_EVENTS = {"AUTH_OK", "AUTH_FAIL", "BLOCK_REQUEST", "LOGOUT", "EXPIRED", "ERROR"}
CONTROLLER_ACTIONS = {"GRANT", "REVOKE", "BLOCK", "UNBLOCK", "DENY", "MODE"}
SCENARIOS = {f"A{i}" for i in range(7)}
MODES = {"static", "dynamic"}
ROLES = {"user", "admin"}
SERVICES = {"web", "admin"}


def load_json(file_path):
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Not a file: {path}")
    try:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DataValidationError(f"Invalid JSON in {path}: {exc}") from exc


def require_object(data, name):
    if not isinstance(data, dict):
        raise DataValidationError(f"{name}: expected an object.")


def require_fields(data, fields, name):
    require_object(data, name)
    missing = [field for field in fields if field not in data]
    if missing:
        raise DataValidationError(f"{name}: missing fields: {missing}")


def require_records(records, fields, name):
    if not isinstance(records, list):
        raise DataValidationError(f"{name}: expected a list.")
    for index, record in enumerate(records):
        require_fields(record, fields, f"{name}, record {index}")


# Compatibility wrappers used by the original unit tests.
def validate_fields(data, fields, name):
    require_fields(data, fields, name)


def validate_records(records, fields, name):
    require_records(records, fields, name)


def require_string(value, field, name, nullable=False):
    if nullable and value is None:
        return
    if not isinstance(value, str) or not value.strip():
        raise DataValidationError(f"{name}: '{field}' must be a non-empty string.")


def require_number(value, field, name, nullable=False):
    if nullable and value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DataValidationError(f"{name}: '{field}' must be a number.")
    if value < 0:
        raise DataValidationError(f"{name}: '{field}' must be non-negative.")


def require_integer(value, field, name, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise DataValidationError(
            f"{name}: '{field}' must be an integer >= {minimum}."
        )


def require_ip(value, field, name, nullable=False):
    if nullable and value is None:
        return
    if not isinstance(value, str):
        raise DataValidationError(f"{name}: '{field}' must be an IP address.")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise DataValidationError(f"{name}: invalid IP in '{field}': {value}") from exc


def load_auth_log(file_path):
    data = load_json(file_path)
    name = "auth_log.json"
    require_fields(data, ["run_id", "events"], name)
    require_string(data["run_id"], "run_id", name)
    require_records(data["events"], ["ts", "event", "user", "ip", "detail"], name)
    for i, event in enumerate(data["events"]):
        label = f"{name}, record {i}"
        require_number(event["ts"], "ts", label)
        require_string(event["event"], "event", label)
        if event["event"] not in AUTH_EVENTS:
            raise DataValidationError(f"{label}: unknown event {event['event']!r}.")
        require_string(event["user"], "user", label, nullable=True)
        require_ip(event["ip"], "ip", label)
        require_string(event["detail"], "detail", label, nullable=True)
    return data


def load_access_results(file_path):
    data = load_json(file_path)
    name = "access_results.json"
    require_fields(data, ["run_id", "scenario", "mode", "attempts"], name)
    require_string(data["run_id"], "run_id", name)
    require_string(data["scenario"], "scenario", name)
    if data["scenario"] not in SCENARIOS:
        raise DataValidationError(f"{name}: invalid scenario.")
    require_string(data["mode"], "mode", name)
    if data["mode"] not in MODES:
        raise DataValidationError(f"{name}: invalid mode.")
    require_records(
        data["attempts"],
        ["src", "dst", "port", "ts", "success", "latency_ms", "error"],
        name,
    )
    for i, attempt in enumerate(data["attempts"]):
        label = f"{name}, record {i}"
        require_string(attempt["src"], "src", label)
        require_string(attempt["dst"], "dst", label)
        require_integer(attempt["port"], "port", label, minimum=1)
        if attempt["port"] > 65535:
            raise DataValidationError(f"{label}: port exceeds 65535.")
        require_number(attempt["ts"], "ts", label)
        if not isinstance(attempt["success"], bool):
            raise DataValidationError(f"{label}: 'success' must be boolean.")
        require_number(attempt["latency_ms"], "latency_ms", label, nullable=True)
        require_string(attempt["error"], "error", label, nullable=True)
        if attempt["success"] and attempt["latency_ms"] is None:
            raise DataValidationError(f"{label}: successful attempt needs latency_ms.")
        if not attempt["success"] and attempt["latency_ms"] is not None:
            # A failed TCP connection may have a measured timeout; keep a valid numeric sample.
            pass
    return data


def load_controller_log(file_path):
    data = load_json(file_path)
    name = "controller_log.json"
    require_fields(data, ["events"], name)
    require_records(
        data["events"],
        ["ts", "action", "ip", "reason", "flows_changed", "install_ms"],
        name,
    )
    for i, event in enumerate(data["events"]):
        label = f"{name}, record {i}"
        require_number(event["ts"], "ts", label)
        require_string(event["action"], "action", label)
        if event["action"] not in CONTROLLER_ACTIONS:
            raise DataValidationError(f"{label}: unknown action {event['action']!r}.")
        require_ip(event["ip"], "ip", label, nullable=True)
        require_string(event["reason"], "reason", label, nullable=True)
        require_integer(event["flows_changed"], "flows_changed", label, minimum=0) if event["flows_changed"] is not None else None
        require_number(event["install_ms"], "install_ms", label, nullable=True)
    return data


def load_acl_state(file_path):
    data = load_json(file_path)
    name = "acl_state.json"
    require_fields(data, ["sessions", "blocked"], name)
    require_records(data["sessions"], ["ip", "user", "role", "services", "granted_at", "expires_at"], name)
    require_records(data["blocked"], ["ip", "until", "reason"], name)
    for i, session in enumerate(data["sessions"]):
        label = f"{name}, session {i}"
        require_ip(session["ip"], "ip", label)
        require_string(session["user"], "user", label)
        require_string(session["role"], "role", label)
        if session["role"] not in ROLES:
            raise DataValidationError(f"{label}: invalid role.")
        if not isinstance(session["services"], list) or any(s not in SERVICES for s in session["services"]):
            raise DataValidationError(f"{label}: services must contain only web/admin.")
        require_number(session["granted_at"], "granted_at", label)
        require_number(session["expires_at"], "expires_at", label)
        if session["expires_at"] < session["granted_at"]:
            raise DataValidationError(f"{label}: expires_at precedes granted_at.")
    for i, blocked in enumerate(data["blocked"]):
        label = f"{name}, blocked {i}"
        require_ip(blocked["ip"], "ip", label)
        require_number(blocked["until"], "until", label)
        require_string(blocked["reason"], "reason", label)
    return data


def load_topology(file_path):
    """Validate the repository topology format (host->IP plus host/switch links)."""
    data = load_json(file_path)
    name = "topology.json"
    require_fields(data, ["switches", "hosts", "links", "openflow", "controller_rest"], name)
    switches, hosts, links = data["switches"], data["hosts"], data["links"]
    if not isinstance(switches, list) or not switches:
        raise DataValidationError(f"{name}: switches must be a non-empty list.")
    if any(not isinstance(s, str) or not s for s in switches) or len(set(switches)) != len(switches):
        raise DataValidationError(f"{name}: invalid or duplicate switch names.")
    require_object(hosts, f"{name}: hosts")
    if not hosts:
        raise DataValidationError(f"{name}: hosts cannot be empty.")
    for host, address in hosts.items():
        require_string(host, "host name", name)
        require_ip(address, f"hosts.{host}", name)
    if not isinstance(links, list):
        raise DataValidationError(f"{name}: links must be a list.")
    valid_nodes = set(switches) | set(hosts)
    for index, link in enumerate(links):
        if not isinstance(link, list) or len(link) != 2 or any(node not in valid_nodes for node in link):
            raise DataValidationError(f"{name}: invalid link at index {index}.")
    openflow = data["openflow"]
    require_fields(openflow, ["version", "controller_host", "controller_port", "port"], f"{name}: openflow")
    require_string(openflow["version"], "version", name)
    require_string(openflow["controller_host"], "controller_host", name)
    for field in ("controller_port", "port"):
        require_integer(openflow[field], field, name, minimum=1)
        if openflow[field] > 65535:
            raise DataValidationError(f"{name}: invalid OpenFlow port.")
    rest = data["controller_rest"]
    require_fields(rest, ["management_ip", "port"], f"{name}: controller_rest")
    require_ip(rest["management_ip"], "management_ip", name)
    require_integer(rest["port"], "REST port", name, minimum=1)
    if rest["port"] > 65535:
        raise DataValidationError(f"{name}: invalid controller REST port.")
    return data
