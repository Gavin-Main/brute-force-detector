"""
Project: brute-force-detector

File: main.py

Description: 

Created by: Gavin Main

Date Finalized: 
"""

from pathlib import Path
from log_parser import parse_log_file
from detector import group_failed_attempts

def main():

    # Locate sample authentication log
    project_root = Path(__file__).resolve().parent.parent
    log_path = project_root / "logs" / "sample_auth.log"

    # Parse the authentication logs
    events = parse_log_file(log_path)

    # Group failed login attempts by IP address
    failed_attempts = group_failed_attempts(events)

    # Display general statistics
    print(f"Total authentication events: {len(events)}")
    print(f"Unique IPs with failures: {len(failed_attempts)}")

    total_failures = sum(
        len(attempts) for attempts in failed_attempts.values()
    )

    print(f"Total failed login attempts: {total_failures}")

    # Display failure counts for each IP address
    print("\nFailed Login Attempts by IP:")

    for ip, attempts in failed_attempts.items():
        print(f"{ip}: {len(attempts)} failed attempts.")


if __name__ == "__main__":
    main()