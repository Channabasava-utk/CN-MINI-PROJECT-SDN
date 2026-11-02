# CN Mini Project — SDN-Based Authentication and Network Access Control

This repository contains the authentication and service-side components for the Computer Networks mini project. The system uses a TCP authentication service and a controller REST API to request temporary network access.

## Team responsibilities

- Channabasava: TCP authentication server and client, user sessions, controller requests, and service-side utilities.
- Dhrithi: Mininet topology and Ryu SDN controller.
- Chandravadan: event correlation, log analysis, monitoring, and visualization.

## Planned Mininet addressing

| Node | Address | Purpose |
| --- | --- | --- |
| h1 | 10.0.0.1 | Client |
| h2 | 10.0.0.2 | Client |
| h3 | 10.0.0.3 | Client |
| h4 | 10.0.0.4 | Authentication server |
| h5 | 10.0.0.5 | Web service |
| h6 | 10.0.0.6 | Admin service |
| Controller | 10.0.0.254:8080 | Controller REST API |

## Repository structure

- auth/server.py — TCP authentication server, login attempts, session creation/refresh/logout, expiry, and controller calls.
- auth/client.py — command-line client for login, refresh, and logout.
- auth/services.py — simple HTTP web and admin demonstration services.
- auth/access_probe.py — TCP reachability probe for the two services.
- auth/stub_controller.py — local mock REST controller for development and tests; it is not the Ryu controller.
- auth/create_users.py — creates a local users.json with salted password hashes.
- config.py — shared IP addresses, ports, timeouts, and thresholds.
- policy.json — role-to-service policy.
- tests/test_auth.py — 12 authentication unit tests.
- data/ — runtime logs and probe results are generated here and intentionally not committed.

## Local setup

Use Python 3.9 or later. From the repository root:

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install -r requirements.txt
    python auth/create_users.py

The user creation script prompts for passwords for alice, bob, and carol and writes a local users.json. Passwords are not stored in plaintext. Do not commit or share users.json.

Run unit tests after creating users.json:

    python -m unittest discover -s tests -v

## Local component test with the stub controller

Open separate terminals from the repository root. Activate the virtual environment in each terminal.

Terminal 1 — start the local stub controller:

    python auth/stub_controller.py

Terminal 2 — point the authentication server to the local stub and start it:

    export CONTROLLER_URL=http://127.0.0.1:8080
    python auth/server.py

Terminal 3 — start the demo web service:

    python auth/services.py web

Terminal 4 — start the demo admin service:

    python auth/services.py admin

Terminal 5 — use the client:

    export AUTH_SERVER_HOST=127.0.0.1
    python auth/client.py login

The client supports these actions: login, refresh, and logout. Use the session token returned by login for refresh or logout. The probe can be run with:

    python auth/access_probe.py --host 127.0.0.1 --count 3

The stub controller is for local development only. Its successful responses do not demonstrate real OpenFlow rule installation.

## Controller REST contract

The authentication server expects the controller to implement these POST endpoints:

- POST /acl/grant — JSON body: ip, user, role, ttl. A successful response has action set to granted.
- POST /acl/revoke — JSON body: ip, reason. A successful response has action set to revoked.
- POST /acl/block — JSON body: ip, duration, reason. A successful response has action set to blocked.

The server grants network access before returning AUTH_OK. If the controller request fails or returns an unexpected action, authentication fails closed. Confirm exact request and response formats with the Ryu controller implementation before integration.

## Current implementation boundary

The authentication code and its unit tests can be exercised locally using the stub controller. The stub is not connected to Mininet and does not install OpenFlow rules. The demo HTTP services listen on all interfaces and do not independently enforce user/admin roles. Actual user-versus-admin network access restrictions must be enforced and verified by the integrated SDN controller and Mininet topology.

## Security and generated files

- users.json contains salted password hashes and is generated locally; it is ignored by Git.
- Authentication logs and access probe results can contain client IP addresses and are ignored by Git.
- Do not commit passwords, session tokens, private keys, or other credentials.
