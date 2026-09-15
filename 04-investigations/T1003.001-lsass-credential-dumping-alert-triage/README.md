# 🚨 Triage Alert — Suspicious Process Access to LSASS.exe

**Alert ID:** ALT-2026-0911-001
**Date/Time Detected:** 2026-09-11 11:34:44 UTC
**Analyst:** Quy Pham
**Severity:** Critical
**Status:** Escalated to IR Team — True Positive, Pending Remediation

**Detection Source:** Sysmon EventCode 10 (ProcessAccess) — Splunk
**MITRE ATT&CK:** [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) (Credential Access)

---

## Alert Summary

Sysmon logged a `ProcessAccess` event where `taskmgr.exe` (PID 4612) requested handle access to `lsass.exe` (PID 696) with `GrantedAccess: 0x1410`, which includes `PROCESS_VM_READ` — the permission required to read LSASS memory contents (credentials, hashes, Kerberos tickets).

## Host / Asset

- **Computer:** DESKTOP-T7E8MSJC
- **User context:** *DESKTOP-T7E8MSJ\rastudent*

## Key Indicators

| Field | Value |
|---|---|
| Source Image | taskmgr.exe |
| Source PID | 4612 |
| Parent Process | explorer.exe |
| Target Image | lsass.exe |
| Target PID | 696 |
| GrantedAccess | 0x1410 |
| Dump Files Found | `C:\Users\rastudent\AppData\Local\Temp\lsass-comsvcs.dmp`, `C:\Users\rastudent\AppData\Local\Temp\lsass_696.dmp` |

## Triage Steps Performed

1. Reviewed ProcessAccess event; confirmed `GrantedAccess=0x1410` includes `PROCESS_VM_READ`.
2. Pivoted on PID 4612 to confirm process identity (taskmgr.exe) and parent (explorer.exe) — consistent with interactive GUI use.
3. Searched Sysmon EventCode 11 (FileCreate) for `.dmp` output — **no results** (logging gap identified: FileCreate not capturing `.dmp` writes).
4. Verified locally via PowerShell (`Get-ChildItem -Filter "*lsass*.dmp"`) — confirmed two dump files present on disk.

## Verdict

**True Positive.** Interactive LSASS memory dump confirmed via filesystem artifact, corroborating the ProcessAccess alert. Two distinct dump artifacts suggest more than one dumping method may have been used (Task Manager GUI + possible comsvcs.dll MiniDump — needs confirmation against atomic test definition).

## Escalation Justification

Escalated to IR due to:
- Confirmed memory dump of LSASS containing potential credential material
- Two distinct dump files/methods observed, suggesting deliberate and repeated access attempts rather than a single accidental action
- Full scope of credential exposure unknown — requires IR to determine which accounts/secrets may have been present in memory at dump time


## Disposition / Actions Taken

- [ ] Host isolated
- [ ] Dump files quarantined/deleted
- [ ] Credentials rotated for affected accounts
- [x] Sysmon config flagged for remediation (FileCreate `.dmp` exclusion gap)
- [x] Escalated to IR team for containment & remediation
- [ ] Ticket closed (pending IR resolution)
## Notes for Follow-up

- Update Sysmon config to capture `.dmp` file creation under `%TEMP%` and `System32`.


---

📄 [Full investigation with step-by-step evidence and screenshots →](./investigation-full.md)
