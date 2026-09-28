# Microsoft Sentinel SOC Lab

## Overview

This project documents a hands-on Microsoft Sentinel SOC lab focused on log collection, KQL investigation, alert detection, incident triage, and alert classification.

The lab uses a Windows Server endpoint connected to Microsoft Sentinel through Azure Monitor Agent (AMA) and a Data Collection Rule (DCR). Security telemetry is collected in a Log Analytics workspace and analyzed with KQL.

The project is organized as a progression from environment setup, to log collection, to a practical suspicious PowerShell investigation.

---

## Lab Workflow

```text
Azure Environment
        ↓
Windows Endpoint
        ↓
Azure Monitor Agent (AMA)
        ↓
Data Collection Rule (DCR)
        ↓
Log Analytics Workspace
        ↓
Microsoft Sentinel
        ↓
KQL Hunting
        ↓
Analytics Rule
        ↓
Alert
        ↓
Triage and Investigation
        ↓
Classification
```

---

## Project Sections

### 1. Environment Setup

[01-environment-setup.md](01-environment-setup.md)

Covers:

- Log Analytics workspace creation
- Microsoft Sentinel enablement
- Azure Activity log ingestion
- KQL-based data ingestion verification

This section establishes the core SIEM environment used throughout the lab.

---

### 2. Windows Security Log Collection

[02-windows-log-collection.md](02-windows-log-collection.md)

Covers:

- Windows Server endpoint deployment
- Azure Monitor Agent configuration
- Data Collection Rule configuration
- Windows Security Event ingestion
- `SecurityEvent` table verification
- Event volume review using KQL

This section establishes the endpoint telemetry required for later detection and investigation exercises.

---

### 3. Suspicious PowerShell Investigation

[03-suspicious-powershell.md](03-suspicious-powershell.md)

Covers:

- Generation of harmless encoded PowerShell activity
- Hunting for suspicious PowerShell with KQL
- Custom Scheduled Analytics Rule creation
- Alert generation in Microsoft Sentinel
- PowerShell command decoding
- Parent process review
- PowerShell process ID correlation
- Child process investigation
- Network activity review
- Alert classification
- Investigation outcome and lessons learned

The investigation follows a practical SOC workflow:

```text
Encoded PowerShell Alert
        ↓
Decode Command
        ↓
Review Parent Process
        ↓
Identify PowerShell PID
        ↓
Check Child Processes
        ↓
Check Network Activity
        ↓
Classify the Alert
```

---

## Skills Demonstrated

This project demonstrates hands-on experience with:

- Microsoft Sentinel
- Log Analytics
- Kusto Query Language (KQL)
- Azure Monitor Agent (AMA)
- Data Collection Rules (DCR)
- Windows Security Event logging
- Windows Event ID `4688`
- Alert triage
- Incident investigation
- Detection engineering
- Scheduled Analytics Rules
- Parent-child process analysis
- PowerShell command-line analysis
- Process ID correlation
- Network activity review
- Alert classification
- SOC documentation

---

## Example Detection

The suspicious PowerShell investigation uses Windows Event ID `4688` to identify PowerShell execution with suspicious command-line arguments.

```kusto
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith @"\powershell.exe"
| where CommandLine has_any (
    "-EncodedCommand",
    "-enc",
    "-ExecutionPolicy Bypass",
    "-WindowStyle Hidden"
)
| project
    TimeGenerated,
    Computer,
    Account,
    ParentProcessName,
    NewProcessName,
    NewProcessId,
    CommandLine
```

This query was later converted into a custom Microsoft Sentinel Scheduled Analytics Rule.

---

## Investigation Approach

The lab emphasizes investigation based on evidence rather than treating a single suspicious indicator as automatically malicious.

For the suspicious PowerShell case, the investigation reviewed:

- Encoded PowerShell content
- Parent process
- PowerShell process ID
- Child processes
- Network activity
- Follow-on behavior
- Context of the activity

The final alert classification was based on the full behavior chain rather than only the presence of suspicious PowerShell flags.

---

## Outcome

The lab successfully demonstrated an end-to-end SOC workflow:

```text
Collect Logs
    ↓
Verify Telemetry
    ↓
Hunt with KQL
    ↓
Create Detection
    ↓
Generate Alert
    ↓
Triage
    ↓
Investigate
    ↓
Classify
    ↓
Document
```

The suspicious PowerShell activity was intentionally generated as part of the lab. The analytics rule correctly detected the behavior, and the investigation determined that the underlying activity was an authorized security test with no malicious follow-on behavior identified.

---

## What I Learned

Through this lab, I practiced how to:

- Configure a basic Microsoft Sentinel environment
- Collect Windows Security telemetry
- Validate log ingestion with KQL
- Build custom hunting queries
- Convert a hunting query into an analytics rule
- Investigate suspicious PowerShell activity
- Decode encoded PowerShell commands
- Correlate process IDs to identify child processes
- Review related network activity
- Distinguish suspicious behavior from confirmed malicious activity
- Classify an alert based on supporting evidence
- Document investigation findings in a clear SOC workflow

I also learned the importance of timestamp handling in KQL, especially the difference between local time displayed in the portal and UTC values used in `datetime()` queries.

---

## Repository Structure

```text
Microsoft-Sentinel-SOC-Lab/
│
├── README.md
├── 01-environment-setup.md
├── 02-windows-log-collection.md
├── 03-suspicious-powershell.md
└── screenshots/
    ├── log-analytics-workspace.png
    ├── sentinel-overview.png
    ├── azure-activity-ingestion.png
    ├── windows-vm.png
    ├── windows-security-connector.png
    ├── security-event-ingestion.png
    ├── security-event-summary.png
    ├── encoded-command.png
    ├── analytics-rule.png
    ├── alert-generated.png
    ├── decoded-command.png
    ├── parent-process.png
    ├── child-process.png
    └── check-network-connection.png
```

---

## Notes

This project was created as a hands-on portfolio lab for practicing entry-level SOC analyst workflows using Microsoft Sentinel and Windows security telemetry.

The focus is on practical investigation skills, KQL, alert triage, detection logic, and evidence-based classification.
