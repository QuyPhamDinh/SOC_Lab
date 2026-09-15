# Automating Patch Management on Linux and Windows Using Python

Two Python scripts that automate checking for pending/installed system updates and save the results as a timestamped report — one for Linux (`apt`), one for Windows (`Get-HotFix`).

This project was built to satisfy the following challenge objectives:

1. Use Python to interact with system utilities (Linux and Windows).
2. Query upgradable/installed packages and pending updates.
3. Generate a formatted patch report using Python.
4. Gain experience automating administrative tasks across both operating systems.

## Files

| File | Platform | Source command |
|---|---|---|
| `linux_patch_report.py` | Linux (Debian/Ubuntu-based) | `apt list --upgradable` |
| `windows_patch_report.py` | Windows (7 through Server 2025) | PowerShell `Get-HotFix` |

## Linux — `linux_patch_report.py`

Runs `apt list --upgradable` to list packages with available updates, then saves the output to a timestamped `.txt` report.

**Note:** this reports packages that *have an update available*, not packages that have already been installed. That distinction matters if you're auditing patch compliance vs. patch history.

### Requirements
- Debian/Ubuntu-based distro with `apt`
- Python 3
- `~/Desktop` directory must exist (falls back to home directory if not)

### Usage
```bash
python3 linux_patch_report.py
```

## Windows — `windows_patch_report.py`

Runs PowerShell's `Get-HotFix` to list installed updates/hotfixes, then saves the output to a timestamped `.txt` report with a header (timestamp + hostname).

`Get-HotFix` is used instead of `wmic` because `wmic` is deprecated and removed by default on Windows 11 24H2+ and Windows Server 2025. `Get-HotFix` covers everything from Windows 7/Server 2008 R2 onward, including the newest builds.

### Requirements
- Windows 7 / Server 2008 R2 or later
- Python 3
- PowerShell available in PATH (present by default on all supported versions)

### Usage
```cmd
python windows_patch_report.py
```

## Output

Both scripts save to:

```
<Desktop or home directory>/installed_updates_<YYYY-MM-DD_HH-MM-SS>.txt
```

The Windows version's report includes a small header (generation timestamp + hostname) before the raw data; the Linux version currently writes the raw `apt` output directly.

## Design notes / known limitations

- Neither script currently parses the raw output into a structured table (package name, current → new version, counts, etc.) — both write the tool's raw text output to the report.
- Neither script checks for admin/root privileges before running, though neither strictly requires elevation to query update status.
- The Linux script's naming (`get_installed_updates`) doesn't fully match its behavior, since `apt list --upgradable` reports *pending*, not installed, updates. Kept as-is to match the original script.

## Author

phamdinhquy
