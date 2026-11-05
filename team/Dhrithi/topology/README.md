# Dhrithi — Mininet Network Topology

## Overview

The topology contains three OpenFlow 1.3 switches in a line and six project hosts. A seventh node, `cHost`, creates the management interface in the Ubuntu root namespace so that the authentication host (h4) can reach the Ryu REST API.

## Nodes

| Node | IP address | Purpose |
|---|---|---|
| h1 | 10.0.0.1/24 | User client |
| h2 | 10.0.0.2/24 | Administrator client |
| h3 | 10.0.0.3/24 | Untrusted client |
| h4 | 10.0.0.4/24 | Authentication server |
| h5 | 10.0.0.5/24 | Web service |
| h6 | 10.0.0.6/24 | Admin service |
| cHost | 10.0.0.254/24 | Ubuntu host-side interface for controller REST access |

## Links

- h1, h2 and h3 connect to s1.
- s1 connects to s2; s2 connects to s3.
- h4, h5 and h6 connect to s3.
- cHost connects s3 to the Ubuntu root network namespace.

Host links and inter-switch links use 10 Mbps bandwidth and 5 ms delay. The cHost link is a direct management link.

## Controller addresses

- Switches connect to Ryu at `127.0.0.1:6653` using OpenFlow 1.3.
- h4 calls the controller REST API at `http://10.0.0.254:8080`.
- `cHost` must be present before testing h4-to-controller REST connectivity.

## Startup

Run commands from the repository root. Start the Ryu controller in a separate terminal first (see [controller README](../controller/README.md)). Then run:

```bash
sudo mn -c
sudo python3 team/Dhrithi/topology/topo.py
```

At the Mininet prompt, verify host connectivity and the management path:

```text
mininet> pingall
mininet> h4 ping -c 2 10.0.0.254
mininet> h4 curl -s http://10.0.0.254:8080/acl/stats
```

The last command requires curl to be installed in the h4 namespace. The topology script reads its shared addresses, ports, and link settings from `team/Dhrithi/controller/config.py`.

## Cleanup

Exit the Mininet CLI with `exit`. If needed, run `sudo mn -c` from another terminal to clean up leftover Mininet interfaces and switches.
