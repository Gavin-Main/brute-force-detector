"""
Project: brute-force-detector

File: alerts.py

Description: Handles the formatting, display, and export of detected security alerts.
             Presents suspicious authentication activity in the terminal and generates
             structured JSON reports containing relevant threat information.

Created by: Gavin Main

Date Finalized: 
"""

import json
from pathlib import Path

"""
Displays detected brute-force security alerts in the terminal.

Arguments:
    alerts (list): List of security alert dictionaries
"""
def display_alerts(alerts):

    print("\n=========== SECURITY ALERTS ===========\n")

    if not alerts:
        print("\nNo suspicious activity detected.")
        return

    for alert in alerts:
        print(f"\n[{alert['severity']}] Potential Brute Force Attack\n")
        print(f"Source IP: {alert['ip']}\n")
        print(f"Total Failed Attempts: {alert['total_failed_attempts']}\n")
        print(f"Failed Attempts in Window: {alert['failed_attempts']}\n")
        print(f"Time Window: {alert['time_window']} seconds\n")
        print(f"First Attempt: {alert['first_attempt']}\n")
        print(f"Last Attempt: {alert['last_attempt']}\n")
        print(f"Targeted Users: {', '.join(alert['usernames'])}\n")

    print("\n========================================")


"""
Exports detected security alerts to a JSON report.

Arguments:
    alerts (list): List of security alert dictionaries.
    filepath (str or Path): Destination path for the JSON report.
"""
def export_alerts(alerts, filepath):
    filepath = Path(filepath)

    # Create the destination directory if it does not exist
    filepath.parent.mkdir(parents=True, exist_ok=True)

    # Convert datetime objects to ISO-formatted strings
    report = []

    for alert in alerts:
        formatted_alert = alert.copy()

        formatted_alert["first_attempt"] = (
            alert["first_attempt"].isoformat()
        )

        formatted_alert["last_attempt"] = (
            alert["last_attempt"].isoformat()
        )

        report.append(formatted_alert)

    # Write the formatted alerts to a JSON file
    with open(filepath, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"\nSecurity report exported to {filepath}")
    