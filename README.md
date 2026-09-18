# SOC Lab

A four-machine SOC lab documenting how I designed an environment, collected security logs in Splunk, wrote detections, and investigated alerts. The numbered folders provide a path through the core project: **architecture → implementation and data collection → detection engineering → investigations**.

## Lab at a glance

| System | Role | Platform |
| --- | --- | --- |
| ERPNext application server | Business application and Linux log source | Ubuntu 24.04 |
| PostgreSQL server | Database and Windows log source | Windows Server 2025 |
| Splunk Enterprise server | Central log collection, searches, dashboards, and alerts | Ubuntu 24.04 |
| Employee workstation | Endpoint telemetry and investigation target | Windows 10 Pro |

The machines share the RemotePC `192.168.100.0/24` network. OPNsense serves as the existing gateway; the planned isolated WAN/LAN/DMZ design could not be deployed in this environment. Access restrictions are implemented at the hosts where documented, and the architecture notes explain this limitation. See the [network architecture](01-architecture/network-architecture.md) and [asset inventory](01-architecture/asset-inventory.md) for details.

## Start here: core project

| Step | Read | What you will find |
| --- | --- | --- |
| 1. Architecture | [Network architecture](01-architecture/network-architecture.md)<br>[Asset inventory](01-architecture/asset-inventory.md)<br>[Network diagram](01-architecture/Meridian_Vault_Financial-4.Network%20Architecture%20Design.drawio.png) | System roles, network layout, constraints, and intended security model. |
| 2. Implementation and data collection | [Four-machine evidence appendix](02-implementation-data-collection/4%20machines%20setup/4-machine-implementation-evidence.md)<br>[Splunk setup](02-implementation-data-collection/siem-log-forwarding/splunk-server-setup.md)<br>[Windows forwarding](02-implementation-data-collection/siem-log-forwarding/windows-log-forwarding.md)<br>[Linux forwarding](02-implementation-data-collection/siem-log-forwarding/linux-log-forwarding.md)<br>[Pipeline verification](02-implementation-data-collection/siem-log-forwarding/pipeline-verification.md) | Deployment evidence, Windows/Sysmon and Linux/application log inputs, and checks that events reach Splunk. |
| 3. Detection engineering | [Detections](03-detection-engineering/detections.md)<br>[Dashboards](03-detection-engineering/dashboards.md) | SPL searches for suspicious PowerShell, Run key changes, and failed logins; dashboard panels for authentication, firewall, alert, and network activity. |
| 4. Investigations | [LSASS alert triage](04-investigations/T1003.001-lsass-credential-dumping-alert-triage/README.md)<br>[Full LSASS investigation](04-investigations/T1003.001-lsass-credential-dumping-alert-triage/investigation-full.md) | A lab alert investigated with Sysmon and filesystem evidence, including a documented logging gap. |

### Telemetry flow

Windows event logs, Sysmon, and PowerShell logs are sent by Splunk Universal Forwarder. The Linux application server forwards system/authentication/firewall events through rsyslog and application logs through the forwarder. Splunk brings these sources together for searches, dashboards, and alert triage. The [pipeline verification guide](02-implementation-data-collection/siem-log-forwarding/pipeline-verification.md) records checks of the ingestion path.

## Repository map

```text
01-architecture/                       Network design and asset inventory
02-implementation-data-collection/    Deployment evidence and log forwarding
03-detection-engineering/             SPL detections and dashboards
04-investigations/                    LSASS alert triage and investigation
05-threat-hunting/                    Separate threat-hunting project
thm-alert-triage/                     Separate TryHackMe SOC Simulator cases
powershell-automation/               PowerShell automation project
python-automation/                   Python automation project
```

The [threat-hunting project](05-threat-hunting/README.md), [TryHackMe alert triage cases](thm-alert-triage/README.md), [PowerShell automation](powershell-automation/README.md), and [Python automation](python-automation/README.md) have their own entry points. They are additional portfolio work alongside the four-step lab narrative.

## Scope and evidence

This is a training lab. The LSASS investigation documents an Atomic Red Team test and an observed Sysmon FileCreate logging gap; its escalation and remediation checklist describes a lab triage outcome, not a production incident. The implementation appendix includes screenshots of configuration and end-to-end ingestion checks.
