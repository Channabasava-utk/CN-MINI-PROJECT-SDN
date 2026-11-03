# Dhrithi — Ryu SDN Controller and Network Access Control


## Overview
This module implements the Ryu SDN controller and network access control functionality for the SDN mini-project.

## Files
- controller.py: Main Ryu controller and REST API.
- session_manager.py: Manages client access sessions and expiry.
- event_logger.py: Records controller events.
- faults.py: Provides network fault simulation functions.
- __init__.py: Python package initialization.
- config.py: Project configuration.
- policy.json: Access control policy configuration.

## Controller Startup
The controller was developed and tested in the original SDN_Project workspace.

From the original project root, run:
1. source ryu-env/bin/activate
2. PYTHONPATH="$PWD" ryu-manager --ofp-tcp-listen-port 6653 sdn.controller

OpenFlow connections use port 6653.
The REST API listens on port 8080.

## REST API

| Method | Endpoint | Purpose |
| POST | /acl/grant | Grant client access |
| POST | /acl/revoke | Revoke client access |
| POST | /acl/block | Block a client |
| POST | /acl/mode | Change access mode |
| GET | /acl/sessions | View active sessions |
| GET | /acl/log | View event logs |
| GET | /acl/stats | View controller statistics |
| GET | /acl/topology | View network topology |

## Example Requests

Grant access:
{"ip":"10.0.0.1","role":"user","ttl":120}

Revoke access:
{"ip":"10.0.0.1"}

Block a client:
{"ip":"10.0.0.3","duration":60,"reason":"Suspicious activity"}

Change access mode:
{"mode":"static"}

## Dependencies
- Python
- Ryu 4.34
- Mininet
- Open vSwitch

The controller uses OpenFlow 1.3.

## Integration Notes
Authentication server integration and management API restrictions require coordination with the authentication module.
