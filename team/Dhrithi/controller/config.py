# SDN Network Access Control Configuration

CONTROLLER_HOST = "127.0.0.1"
CONTROLLER_PORT = 6653
REST_API_PORT = 8080

# Network topology
SWITCHES = ["s1", "s2", "s3"]

HOSTS = {
    "h1": {"ip": "10.0.0.1", "role": "user"},
    "h2": {"ip": "10.0.0.2", "role": "admin"},
    "h3": {"ip": "10.0.0.3", "role": "untrusted"},
    "h4": {"ip": "10.0.0.4", "role": "auth_server"},
    "h5": {"ip": "10.0.0.5", "role": "web_server"},
    "h6": {"ip": "10.0.0.6", "role": "admin_server"}
}

# Server ports
AUTH_PORT = 9000
WEB_PORT = 8000
ADMIN_PORT = 8001

# Access-control settings
DEFAULT_SESSION_TTL = 60
MAX_SESSION_TTL = 300
MAX_FAILED_ATTEMPTS = 3
BLOCK_DURATION = 60

# Monitoring settings
STATS_INTERVAL = 2
SCAN_THRESHOLD = 20
SCAN_WINDOW = 10

# Network link settings
LINK_BANDWIDTH = 10
LINK_DELAY = "5ms"
