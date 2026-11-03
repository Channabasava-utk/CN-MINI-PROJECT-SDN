# Dhrithi — Mininet Network Topology

## Overview
This module implements the SDN network topology using Mininet and Open vSwitch.

## Topology Structure
The network consists of three OpenFlow switches connected in a line:
- s1: Access switch
- s2: Core switch
- s3: Server-side switch

## Hosts and IP Addresses

| Host | IP Address | Role |
|---|---|---|
| h1 | 10.0.0.1 | User |
| h2 | 10.0.0.2 | Administrator |
| h3 | 10.0.0.3 | Untrusted client |
| h4 | 10.0.0.4 | Authentication server |
| h5 | 10.0.0.5 | Web server |
| h6 | 10.0.0.6 | Admin server |

## Switch Connections
- h1, h2 and h3 connect to s1.
- s1 connects to s2.
- s2 connects to s3.
- h4, h5 and h6 connect to s3.

## Controller Connection
The switches connect to the Ryu controller at 127.0.0.1 on OpenFlow port 6653.

## Network Configuration
- Link bandwidth: 10 Mbps
- Link delay: 5 ms
- OpenFlow version: 1.3

## Startup
From the original SDN_Project directory, run:

sudo python3 topo.py

The Ryu controller should be started separately before launching the topology.

## Files
- topo.py: Mininet topology implementation.
- topology.json: JSON representation of the network structure.

## Requirements
- Ubuntu
- Python 3
- Mininet
- Open vSwitch
- Ryu controller
