# Dhrithi — Ryu SDN Controller and Network Access Control

## Overview

This module provides the Ryu OpenFlow 1.3 controller, session flow management, client blocking, event logging, and REST endpoints used by Channabasava's authentication server.

## Files

- `controller.py`: Ryu application and REST API.
- `session_manager.py`: In-memory authenticated session and expiry management.
- `event_logger.py`: Shared JSON event log writer.
- `faults.py`: Helpers for controlled Mininet link/interface fault tests.
- `config.py`: Shared controller/topology constants.
- `policy.json`: Role-to-service permissions and security/monitoring thresholds.

## Package startup

Run from the repository root. Activate the Python environment that contains Ryu 4.34, then start:

```bash
source ryu-env/bin/activate
PYTHONPATH="$PWD" ryu-manager \
  --ofp-tcp-listen-port 6653 \
  --wsapi-host 0.0.0.0 \
  --wsapi-port 8080 \
  team.Dhrithi.controller.controller
```

The Ryu application is imported using its repository package path. Do not use the old `sdn.controller` command; that package does not exist in this repository layout.

Start the Mininet topology in a second terminal after Ryu is running:

```bash
sudo mn -c
sudo python3 team/Dhrithi/topology/topo.py
```

## Network addresses

- OpenFlow switch connection: `127.0.0.1:6653`.
- Controller REST API: `0.0.0.0:8080` (listener).
- Management address reached by h4: `10.0.0.254:8080`, supplied by the root-namespace `cHost` interface.
- Authentication server: `10.0.0.4:9000`.
- Web service: `10.0.0.5:8000`.
- Admin service: `10.0.0.6:8001`.

The REST API listener is bound to all host interfaces so it can be started before Mininet creates cHost. Every REST route also checks the request source IP and permits only h4 (10.0.0.4), the local management address (10.0.0.254), and loopback. OpenFlow base rules permit the authentication server's management connection through the Mininet path. Do not expose the REST API to untrusted networks.

## REST API contract

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/acl/grant` | Install role-specific access flows with a session TTL |
| POST | `/acl/revoke` | Remove a client's session flows |
| POST | `/acl/block` | Remove session flows and install a temporary source-IP drop |
| POST | `/acl/mode` | Switch between static and dynamic access rules |
| GET | `/acl/sessions` | List active controller sessions |
| GET | `/acl/log` | Read controller events |
| GET | `/acl/stats` | Read controller status |
| GET | `/acl/topology` | Read the configured topology |

Example request bodies:

```json
{"ip":"10.0.0.1","user":"alice","role":"user","ttl":60}
{"ip":"10.0.0.1","reason":"logout"}
{"ip":"10.0.0.3","duration":60,"reason":"bruteforce"}
{"mode":"dynamic"}
```

The authentication server checks the `action` field in successful responses. Grant, revoke, block, and mode changes send updates to all three required switches together and wait for their OpenFlow barrier replies under one shared 1-second deadline (`FLOW_CONFIRM_TIMEOUT`). This is shorter than the authentication server's 2-second HTTP timeout. A failed or timed-out switch update is returned as an API error.

## Policy and logs

Role permissions and security thresholds are read from this folder's `policy.json`; network addresses and ports come from `config.py`. Do not edit the root `policy.json` for the Ryu role-service schema.

Controller events are stored in the shared repository path `data/controller_log.json`, independent of the current working directory.

## Verification

After Ryu and Mininet are running, use:

```bash
curl -s http://10.0.0.254:8080/acl/stats
curl -s http://10.0.0.254:8080/acl/topology
```

From the Mininet CLI, verify the API path from h4:

```text
mininet> h4 curl -s http://10.0.0.254:8080/acl/stats
```

Then run the project's authentication tests through h1/h2 and verify the expected WEB/ADMIN access behavior. The source files and API responses alone do not replace an end-to-end test with the authentication service and Mininet.

## Lightweight validation

Run this from the repository root. These checks use only the Python standard library and do not import Ryu or Mininet:

```bash
python3 -m unittest team.Dhrithi.controller.tests.test_controller_config -v
```

The tests parse the controller/topology Python files, compare the Ryu policy with the shared authentication policy, verify the cHost/OpenFlow metadata, and check controller log read/write behavior.
