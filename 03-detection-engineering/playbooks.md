# Detection & Response Playbooks

Each detection in [`detections.md`](detections.md) has SPL logic and tuning notes for the *detection engineering* side. This file adds the *response* side: what an analyst does when the alert fires, how to tell signal from noise, and when to escalate.

---

## Template

Use this shape for any new detection added to the lab.

```
## <Detection Name>

**MITRE ATT&CK:** <technique ID(s)>
**Trigger:** <what condition fires the alert / SPL reference>
**Data source:** <log source(s)>

### Triage Steps
1. ...
2. ...
3. ...

### False-Positive Checks
- ...

### Escalation Threshold
Escalate if: <condition>
Otherwise: <disposition — monitor / close as benign / tune>

### Response Actions
- Contain: ...
- Notify: ...
- Document: ...
```

---

## 1. PowerShell — Suspicious Parent Process

**MITRE ATT&CK:** T1059.001, T1204 **Trigger:** PowerShell/`pwsh` spawned from `w3wp.exe`, `httpd.exe`, `nginx.exe`, Office apps, `wmiprvse.exe`, or `sqlserver.exe` — see `detections.md` #1 **Data source:** Sysmon Event ID 1

### Triage Steps

1. Pull hostname, timestamp, `ParentImage`, `ParentCommandLine`, `Image`, `CommandLine`, `User`, `ProcessGuid`, and `ParentProcessGuid` from the alert. Retrieve executable hashes and signature information where available.
2. Check whether the parent process is a known automation/EDR agent on this specific host (cross-reference the host's software baseline).
3. If the parent is an Office app: check for a recently opened document and whether macros were enabled around the same timestamp.
4. If the parent is a web server process: check web server access/error logs for the same time window for signs of a web shell drop.
5. Read the complete PowerShell command line. Safely decode encoded commands without executing them, inspect referenced scripts, and review PowerShell 4104/4103 logs where enabled for suspicious behavior.
6. Pivot on the PowerShell `ProcessGuid` for related network connections and file activity where collected. Find child processes whose `ParentProcessGuid` matches this `ProcessGuid`. If using `ProcessId`, constrain the search by host and process lifetime to avoid PID reuse.
7. Scope the activity across other hosts and users for the same command, script/file hash, destination IP/domain, document, or process chain. Check related alerts and persistence activity around the same timestamp, then expand the time window as needed.

### False-Positive Checks

- Known patch-management or EDR agents that legitimately spawn PowerShell from these parents on this host.
- Scheduled maintenance scripts using WMI (`wmiprvse.exe`) at predictable intervals.

### Escalation Threshold

Escalate if: the PowerShell command line contains encoded commands, download cradles, or network connections, **or** the parent process has no known legitimate reason to spawn a shell on this host. Otherwise: document as known-good parent/child pair and add to the host's allowlist.

### Response Actions

- Contain: isolate the host if command line shows download/execute behavior.
- Notify: escalate to IR if a web server or Office parent is confirmed malicious.
- Document: log the parent/child pair and disposition in the allowlist notes.
---

## 3. Multiple Failed Logins

**MITRE ATT&CK:** T1110
**Trigger:** EventCode 4625 within a 15-minute window — see `detections.md` #3
**Data source:** Windows Security Event Log

### Triage Steps
1. Aggregate failures by `Account_Name` and `Source_Network_Address` (the raw query lists individual events — group them before triaging).
2. Determine whether the source is internal or external, and whether it's a single account (targeted) or many accounts (spray).
3. Check `Logon_Type` and `Failure_Reason` — distinguish bad password from account lockout, disabled account, or expired credentials.
4. Check whether the same account has a *successful* login immediately after the failure streak (possible successful brute force).

### False-Positive Checks
- A user who forgot their password and is repeatedly retrying manually.
- A service account with a stale credential hardcoded somewhere, retrying on a schedule.

### Escalation Threshold
Escalate if: high failure count against a single account followed by a success, **or** a password-spray pattern across many accounts from one source.
Otherwise: monitor if it's a known user's manual retry pattern that stops without a lockout or success.

### Response Actions
- Contain: force password reset and/or disable the account if a successful login follows the failure streak.
- Notify: escalate to IR immediately on spray patterns from external sources.
- Document: log source IP, account(s), and whether reset/disable was performed.

---

## 4. PowerShell Encoded Command / Suspicious Execution

**MITRE ATT&CK:** T1059.001, T1027, T1105 **Trigger:** `-enc`/`-EncodedCommand` usage or `Invoke-WebRequest`/`DownloadString`/`DownloadFile` calls — see `detections.md` #4 **Data source:** Sysmon Event ID 1

### Triage Steps

1. Pull hostname, timestamp, `User`, `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `ProcessGuid`, and `ParentProcessGuid` from the alert.
2. Decode the Base64 payload (CyberChef or `[System.Convert]::FromBase64String`) to see the actual command.
3. Identify the parent process — is this consistent with detection #1 (suspicious parent) or a user-initiated shell?
4. If a download cradle is present, extract the URL/domain and check it against threat intel (VirusTotal, OTX).
5. Check for resulting child processes in Sysmon Event ID 1 whose `ParentProcessGuid` matches the PowerShell `ProcessGuid`. Check outbound network connections in Sysmon Event ID 3 using the same `ProcessGuid`, where collected.
6. Check available PowerShell 4104/4103 logs and EDR telemetry for suspicious activity within the PowerShell process itself. Malicious code can execute in memory without creating a child process or dropping an executable.
7. Scope the activity across other hosts and users for the same command, script/file hash, URL/domain/IP, or process chain. Check related alerts and persistence activity around the same timestamp, then expand the time window as needed.

### False-Positive Checks

- Legitimate admin scripts that use encoded commands to avoid shell quoting issues (rare but happens in some automation frameworks — verify against known scheduled tasks).
- Software update mechanisms that use `Invoke-WebRequest` internally.

### Escalation Threshold

Escalate if: the decoded command references an external domain not on an allowlist, downloads and executes a binary, shows suspicious in-memory execution, or was spawned from a suspicious parent (ties to detection #1). Otherwise: document as known automation if the decoded content, destination, and related activity are verified benign.

**Do not close solely because no child process or downloaded binary was observed.** If important telemetry is missing and the activity remains unexplained, escalate for further investigation.

### Response Actions

- Contain: isolate host, block the destination domain/IP at the firewall.
- Notify: escalate to IR if a binary was downloaded and executed or malicious execution within PowerShell is identified.
- Document: preserve the original and decoded command, destination, process identifiers, scoping results, and any dropped file hashes for the case file.
