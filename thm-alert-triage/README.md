# Phishing → C2 → DNS Exfiltration — Incident Write-Up

Two SOC Simulator alerts from the same incident on host `win-3450` / user `michael.ascot`, triaged separately but chained together: a phishing email led to C2 access, which was then used to stage and exfiltrate sensitive files over DNS.

**Verdict (both):** True Positive
**Date:** 2026-08-27

## Alerts

1. **Suspicious Email Attachment** — phishing email → `invoice.pdf.lnk` → PowerShell → `powercat.ps1` → C2 over ngrok
   🔗 [C2 Activity](alert-malicious-attachment-importantInvoice-febrary.md)

2. **DNS Exfiltration & Suspicious Data Collection** — financial files staged from a mapped network share, zipped, and exfiltrated via base64-encoded DNS queries to `haz4rdw4re.io`
   🔗 [DNS Exfiltration](alert-dns-exfiltration.md)

## Why they're grouped

The C2 channel established in alert 1 is what gave the attacker hands-on-keyboard access to mount the network share, stage files, and run the DNS exfiltration in alert 2 — same host, same user, same session. Read them in order for the full attack chain.
