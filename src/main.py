"""
Project: brute-force-detector

File: main.py

Description: 

Created by: Gavin Main

Date Finalized: 
"""

from pathlib import Path
from log_parser import parse_log_file
from detector import detect_brute_force
from alerts import display_alerts, export_alerts

def main():

    # Locate sample authentication log
    project_root = Path(__file__).resolve().parent.parent
    log_path = project_root / "logs" / "sample_auth.log"

    # Parse the authentication logs
    events = parse_log_file(log_path)

    # Detect potential brute-force attacks
    alerts = detect_brute_force(
        events,
        threshold=5,
        window_seconds=60
    )

    # Display analysis summary
    print("========================================\n")
    print("========= BRUTE FORCE DETECTOR =========\n")
    print("========================================\n")

    print(f"\nTotal authentication events: {len(events)}\n")
    print(f"\nSuspicious IP addresses: {len(alerts)}\n")

    # Display alerts in the terminal
    display_alerts(alerts)

    # Export alerts to a JSON report
    report_path = project_root / "reports" / "security_alerts.json"
    export_alerts(alerts, report_path)


if __name__ == "__main__":
    main()