# Alert Triage Portfolio

Index of SOC Simulator alerts triaged, with brief description and verdict.

| Alert | Host | Verdict | Description |
|---|---|---|---|
| [Suspicious Parent-Child Relationship](alert-false-positive-parent-child-win-3459.md) | win-3459 | False Positive | `services.exe` spawning `TrustedInstaller.exe` — standard Windows servicing behavior, no downstream child processes or network activity. |
| [Suspicious Email Attachment](alert-malicious-attachment-importantInvoice-febrary.md) | win-3450 | True Positive | Phishing email delivered `invoice.pdf.lnk`, which launched PowerShell to pull `powercat.ps1` and establish C2 over ngrok. |
| [DNS Exfiltration & Suspicious Data Collection](alert-dns-exfiltration.md) | win-3450 | True Positive | Financial files staged from a mapped network share, zipped, and exfiltrated via base64-encoded DNS queries to `haz4rdw4re.io`. Chained from the C2 access above. |


## Related Incident

The **Suspicious Email Attachment** and **DNS Exfiltration** alerts above are part of the same attack chain on `win-3450` / `michael.ascot` — phishing → C2 access → file staging and exfiltration. See the [incident write-up](incident-writeup-win-3450.md) for the full chain.
