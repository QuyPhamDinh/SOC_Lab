# SOC Detection Lab

A SOC lab built collaboratively in a cloud-hosted virtual environment: centralized log forwarding into Splunk, custom detections mapped to MITRE ATT&CK, and detection-response playbooks defining triage steps and escalation thresholds.

Architecture was designed as a group; the SIEM pipeline — Splunk deployment, host-based log forwarding, OS-level auditing, detections, dashboards, and triage playbooks — was independently built and owned as part of the project.

## Table of Contents

- [Architecture](#architecture)
  - [Key systems](#key-systems)
- [Repo structure](#repo-structure)
  - [Suggested reading order](#suggested-reading-order)
- [Detections implemented](#detections-implemented)
- [Design notes / known limitations](#design-notes--known-limitations)

## Architecture

```text
                 RemotePC Network
                 192.168.100.0/24
                         |
                  192.168.100.99
                     OPNsense
                     Gateway
                         |
        +----------------+----------------+
        |                |                |
        v                v                v
   Employee         Application        Database
   Workstation        Server            Server
        |                |                |
        +----------------+----------------+
                         |
                         v
                  Splunk SIEM
                192.168.100.120
```

OPNsense serves as the default gateway; because the hosting environment doesn't allow full virtual network segmentation, security boundaries are enforced with **host-based firewall rules** instead of network-level WAN/LAN/DMZ isolation. This is a documented design constraint, not an oversight — see [`01-architecture/network-architecture.md`](01-architecture/network-architecture.md) for the full rationale and the planned future state.

### Key systems

| System | IP | Role |
|---|---|---|
| OPNsense | `192.168.100.99` | Gateway |
| ERPNext Server (Ubuntu) | `192.168.100.113` | Business application |
| Splunk Enterprise (Ubuntu) | `192.168.100.120` | SIEM |
| PostgreSQL (Windows Server 2025) | `192.168.100.125` | Database |
| Employee Workstation (Windows 10) | DHCP | Internal endpoint |

Full inventory: [`01-architecture/asset-inventory.md`](01-architecture/asset-inventory.md)

## Repo structure

```text
01-architecture/                   Network design and asset inventory
02-implementation-data-collection/ Splunk deployment and log forwarding
   siem-log-forwarding/
     splunk-server-setup.md        Splunk Enterprise install + receiver config
     linux-log-forwarding.md       rsyslog forwarding + bash command auditing
     windows-log-forwarding.md     Universal Forwarder + Sysmon/PowerShell auditing
     pipeline-verification.md      End-to-end ingestion verification
03-detection-engineering/          Detections, dashboards, and response playbooks
   detections.md                  Splunk alert logic + MITRE ATT&CK mapping
   dashboards.md                  SOC dashboard panels + SPL
   playbooks.md                   Triage steps + escalation thresholds per detection
```

### Suggested reading order

1. [`01-architecture/network-architecture.md`](01-architecture/network-architecture.md) — what was built and why
2. [`02-implementation-data-collection/siem-log-forwarding/splunk-server-setup.md`](02-implementation-data-collection/siem-log-forwarding/splunk-server-setup.md) → `linux-log-forwarding.md` → `windows-log-forwarding.md` → `pipeline-verification.md` — how logs get from endpoints to Splunk
3. [`03-detection-engineering/detections.md`](03-detection-engineering/detections.md), [`dashboards.md`](03-detection-engineering/dashboards.md), and [`playbooks.md`](03-detection-engineering/playbooks.md) — what the pipeline catches, how it's visualized, and how an analyst responds

## Detections implemented

| # | Detection | MITRE ATT&CK |
|---|---|---|
| 1 | PowerShell spawned from a suspicious parent process (web server, Office, WMI, SQL) | T1059.001, T1204 |
| 2 | Registry Run key persistence | T1547.001 |
| 3 | Multiple failed logins (brute force) | T1110 |
| 4 | Encoded / download-and-execute PowerShell | T1059.001, T1027, T1105 |

Each detection ships with SPL logic, a Sysmon/Windows Event Log data source, tuning notes on likely false positives, and a corresponding response playbook (triage steps + escalation threshold) in [`03-detection-engineering/playbooks.md`](03-detection-engineering/playbooks.md).

## Design notes / known limitations

- No centralized network segmentation (OPNsense as gateway only, not firewall) — a constraint of the hosting environment, documented in `01-architecture/network-architecture.md` along with the future-state plan.
- Detection queries mix `index=main` and `index=*` scoping across files — intentional where broader endpoint coverage was needed, but worth normalizing in a future pass.
