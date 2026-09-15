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
    print("Retrieving installed Linux updates...")

    result = subprocess.run(
        ["apt", "list", "--upgradable"],
        capture_output=True,
        text=True
    )

    print("Installed updates retrieved successfully.")

    return result.stdout

updates = get_installed_updates()
print(updates)

def save_report(updates):
    print("Preparing report...")

    date_stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    desktop = os.path.join(os.path.expanduser("~"), "Desktop")

    filename = os.path.join(
        desktop,
        f"installed_updates_{date_stamp}.txt"
    )

    print("Saving report to Desktop...")

    with open(filename, "w") as file:
        file.write(updates)

    print(f"Report saved successfully: {filename}")
    

save_report(updates)