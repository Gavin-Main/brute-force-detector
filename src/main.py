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

    # Display analysis results
    print("========================================\n")
    print("========= BRUTE FORCE DETECTOR =========\n")
    print("========================================\n")

    print(f"\nTotal authentication events: {len(events)}\n")
    print(f"\nSuspicious IP addresses: {len(alerts)}\n")

    print("\n=========== SECURITY ALERTS ===========\n")

    for alert in alerts:
        print("\n[HIGH] Potential Brute Force Attack\n")
        print(f"Source IP: {alert['ip']}\n")
        print(f"Total Failed Attempts: {alert['total_failed_attempts']}\n")
        print(f"Failed Attempts in Detection Window: {alert['failed_attempts']}\n")
        print(f"Time Window: {alert['time_window']} seconds\n")
        print(f"First Attempt: {alert['first_attempt']}\n")
        print(f"Last Attempt: {alert['last_attempt']}\n")
        print(f"Targeted Users: {', '.join(alert['usernames'])}\n")

    print("\n========================================")


if __name__ == "__main__":
    main()