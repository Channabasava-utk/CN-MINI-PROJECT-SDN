# Channabasava — Authentication Module

This folder contains the authentication and client/service-side work assigned to Channabasava.

## Files
- `auth/server.py`: TCP authentication server, credential checking, session lifecycle, failed-login handling, and controller REST calls.
- `auth/client.py`: command-line client for login, refresh, and logout.
- `auth/services.py`: demonstration web and admin HTTP services.
- `auth/access_probe.py`: TCP reachability probe for web/admin ports.
- `auth/stub_controller.py`: local mock controller used during development. It is not the Ryu controller.
- `auth/create_users.py`: creates a local root-level `users.json` with salted password hashes.
- `tests/test_auth.py`: authentication unit tests.

Shared configuration remains at the repository root in `config.py` and `policy.json`; generated logs go into the root `data/` directory.

## Setup
Run from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python team/Channabasava/auth/create_users.py
```

Run tests:

```bash
python -m unittest discover -s team/Channabasava/tests -v
```

## Local stub-controller test
Start the following in separate terminals from the repository root:

```bash
python team/Channabasava/auth/stub_controller.py
```

```bash
export CONTROLLER_URL=http://127.0.0.1:8080
python team/Channabasava/auth/server.py
```

```bash
python team/Channabasava/auth/services.py web
python team/Channabasava/auth/services.py admin
```

```bash
export AUTH_SERVER_HOST=127.0.0.1
python team/Channabasava/auth/client.py login
```

```bash
python team/Channabasava/auth/access_probe.py --host 127.0.0.1 --count 3
```

Do not commit `users.json`, session tokens, or runtime logs. Actual Ryu/Mininet integration must be tested with Dhrithi's controller and topology.
