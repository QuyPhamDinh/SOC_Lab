# Network Architecture

## Overview

The SOC lab operates on the existing `192.168.100.0/24` network provided by the RemotePC virtual environment.

The original design planned to use OPNsense for centralized routing and network segmentation. However, the RemotePC environment does not provide sufficient control over IP addressing and virtual network topology to implement the planned isolated WAN/LAN/DMZ architecture.

Therefore, OPNsense is currently used as the **default gateway**, while individual machines use **host-based firewall rules** to restrict unnecessary traffic.

## Current Architecture

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

### Key Systems

| System               | IP                | Role                 |
| --------------------- | ----------------- | -------------------- |
| OPNsense             | `192.168.100.99`  | Gateway              |
| ERPNext Server       | `192.168.100.113` | Business Application |
| Splunk               | `192.168.100.120` | SIEM                 |
| PostgreSQL Server    | `192.168.100.125` | Database             |
| Employee Workstation | DHCP              | Internal Endpoint    |

## Security Model

Because centralized network segmentation cannot be implemented in the RemotePC environment:

```text
Network
   ↓
Host-based Firewall Rules
   ↓
Endpoint / Server Security
   ↓
Security Telemetry
   ↓
Splunk SIEM
   ↓
Detection & Investigation
```

This is a documented design limitation of the lab rather than an attempt to represent the environment as fully segmented.

## Future Improvement

If the lab is moved to an environment with full virtual networking control, OPNsense can be expanded from a gateway into a centralized firewall/router supporting:

* WAN/LAN separation
* DMZ
* Network segmentation
* Inter-zone firewall rules
* Centralized firewall logging
* Network security monitoring
