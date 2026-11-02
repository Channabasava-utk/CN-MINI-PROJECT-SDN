# CN Mini Project — SDN-Based Authentication and Network Access Control

This is the shared repository for the three-person Computer Networks mini project. Each team member has a separate workspace under `team/`; common configuration and project-wide setup stay at the root.

## Team folder ownership

| Team member | Folder | Responsibility |
| --- | --- | --- |
| Channabasava | `team/Channabasava/` | TCP authentication server/client, credential handling, sessions, service demonstrations, controller API client, and access probe |
| Dhrithi | `team/Dhrithi/` | Ryu SDN controller and Mininet topology |
| Chandravadan | `team/Chandravadan/` | Event correlation, log analysis, monitoring, and visualization |

Each person should upload their implementation into their own folder and update the corresponding README with setup/run instructions. Shared integration changes should be coordinated before merging.

## Repository layout

```text
CN-MINI-PROJECT-SDN/
├── team/
│   ├── Channabasava/
│   │   ├── auth/
│   │   └── tests/
│   ├── Dhrithi/
│   │   ├── controller/
│   │   └── topology/
│   └── Chandravadan/
│       ├── analysis/
│       └── visualization/
├── config.py
├── policy.json
├── requirements.txt
├── data/
├── .gitignore
└── README.md
```

## Shared network plan

| Node | Address | Purpose |
| --- | --- | --- |
| h1 | 10.0.0.1 | Client |
| h2 | 10.0.0.2 | Client |
| h3 | 10.0.0.3 | Client |
| h4 | 10.0.0.4 | Authentication server |
| h5 | 10.0.0.5 | Web service |
| h6 | 10.0.0.6 | Admin service |
| Controller | 10.0.0.254:8080 | Controller REST API |

Shared network settings and role policy are maintained in root-level `config.py` and `policy.json`. Discuss changes to these files with all three members.

## Setup

Use Python 3.9 or later. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python team/Channabasava/auth/create_users.py
```

The user-creation helper prompts locally for passwords for alice, bob, and carol, then generates a root-level `users.json` containing salted hashes. Do not commit or share this file.

Run Channabasava's unit tests:

```bash
python -m unittest discover -s team/Channabasava/tests -v
```

More detailed commands are in [Channabasava's README](team/Channabasava/README.md).

## Controller API contract to integrate

The authentication component currently expects the Ryu controller to implement:
- `POST /acl/grant` — JSON: `ip`, `user`, `role`, `ttl`; successful response: `action: granted`.
- `POST /acl/revoke` — JSON: `ip`, `reason`; successful response: `action: revoked`.
- `POST /acl/block` — JSON: `ip`, `duration`, `reason`; successful response: `action: blocked`.

Confirm exact request/response formats and controller address with Dhrithi's implementation before integrated testing.

## Integration status and limits

Channabasava's authentication module has been tested locally using a stub controller. The stub does not install OpenFlow rules and is not a replacement for the Ryu controller. The demo web/admin services also do not independently enforce role-specific access. Actual user/admin network restrictions must be verified against the combined Ryu controller and Mininet topology.

## Security and generated data

- `users.json`, runtime logs, virtual environments, Python caches, and local environment files are ignored by Git.
- Do not commit passwords, password hashes, session tokens, private keys, or unredacted sensitive logs.
- Use sanitized sample data when sharing analysis/visualization examples.
