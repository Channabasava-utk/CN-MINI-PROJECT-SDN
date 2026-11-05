"""Configuration shared by the Ryu controller and Mininet topology."""

# Ryu OpenFlow connection (switches connect to this host/port).
OPENFLOW_HOST = "127.0.0.1"
OPENFLOW_PORT = 6653

# The REST API is reached by h4 through the cHost interface in Mininet.
MANAGEMENT_IP = "10.0.0.254"
REST_API_HOST = "0.0.0.0"
REST_API_PORT = 8080

# Keep below Channabasava's 2-second HTTP controller timeout.
FLOW_CONFIRM_TIMEOUT = 1.0

# Backward-compatible names used by the original topology setup.
CONTROLLER_HOST = OPENFLOW_HOST
CONTROLLER_PORT = OPENFLOW_PORT

SWITCH_IDS = (1, 2, 3)
SWITCHES = ["s1", "s2", "s3"]

HOSTS = {
    "h1": {"ip": "10.0.0.1", "role": "user"},
    "h2": {"ip": "10.0.0.2", "role": "admin"},
    "h3": {"ip": "10.0.0.3", "role": "untrusted"},
    "h4": {"ip": "10.0.0.4", "role": "auth_server"},
    "h5": {"ip": "10.0.0.5", "role": "web_server"},
    "h6": {"ip": "10.0.0.6", "role": "admin_server"},
    "cHost": {"ip": MANAGEMENT_IP, "role": "controller_management"},
}

AUTH_PORT = 9000
WEB_PORT = 8000
ADMIN_PORT = 8001

DEFAULT_SESSION_TTL = 60
MAX_SESSION_TTL = 300
MAX_FAILED_ATTEMPTS = 3
BLOCK_DURATION = 60

STATS_INTERVAL = 2
SCAN_THRESHOLD = 20
SCAN_WINDOW = 10

LINK_BANDWIDTH = 10
LINK_DELAY = "5ms"
