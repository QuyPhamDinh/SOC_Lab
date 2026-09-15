#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug 17 20:39:13 2026

@author: phamdinhquy
"""

import subprocess
import datetime
import os


def get_installed_updates():
    """Query Windows for installed updates using PowerShell's Get-HotFix."""
    print("Retrieving installed Windows updates...")

    # Step 1: Run Get-HotFix via PowerShell to list installed updates/hotfixes.
    # Using PowerShell instead of wmic since wmic is deprecated/removed on
    # newer Windows builds (e.g. Windows 11 24H2+, Server 2025).
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", "Get-HotFix | Format-Table -AutoSize"],
        capture_output=True,
        text=True,
        encoding="utf-8",   # avoid codepage/decode issues on non-English locales
        errors="replace"
    )

    # Step 2: Check whether the command actually succeeded before trusting the output.
    if result.returncode != 0:
        print("Error retrieving updates:")
        print(result.stderr)
        return None

    print("Installed updates retrieved successfully.")

    return result.stdout


def save_report(updates):
    """Write the retrieved update data to a timestamped report on the Desktop."""
    # Step 1: Bail out early if there's nothing to save.
    if not updates:
        print("No update data to save — skipping report.")
        return

    print("Preparing report...")

    # Step 2: Build a timestamped filename so each run produces a unique report.
    date_stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Step 3: Resolve the Desktop path, falling back to the home directory
    # if Desktop doesn't exist (e.g. some Server/Core configurations).
    home = os.path.expanduser("~")
    desktop = os.path.join(home, "Desktop")
    target_dir = desktop if os.path.isdir(desktop) else home

    filename = os.path.join(
        target_dir,
        f"installed_updates_{date_stamp}.txt"
    )

    print("Saving report to Desktop...")

    # Step 4: Write the report, including a small header (timestamp + hostname)
    with open(filename, "w", encoding="utf-8") as file:
        file.write(f"Windows Installed Updates Report\n")
        file.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        file.write(f"Host: {os.environ.get('COMPUTERNAME', 'unknown')}\n")
        file.write("-" * 60 + "\n\n")
        file.write(updates)

    print(f"Report saved successfully: {filename}")


if __name__ == "__main__":
    # Main flow: retrieve updates, print them, then save the report.
    updates = get_installed_updates()
    print(updates)
    save_report(updates)