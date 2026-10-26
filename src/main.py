"""
Project: brute-force-detector

File: main.py

Description: Serves as the main entry point for the Brute Force Detector application.
             Handles command-line arguments, validates user input, coordinates SSH log
             parsing and brute-force detection, and generates security alert reports.

Created by: Gavin Main

Date Finalized: 10/25/26
"""
import argparse
from pathlib import Path

from log_parser import parse_log_file
from detector import detect_brute_force
from alerts import display_alerts, export_alerts


def main():

    # Create the command-line argument parser
    parser = argparse.ArgumentParser(
        description="Detect potential SSH brute-force attacks in authentication logs."
    )

    # Optional path to the authentication log
    parser.add_argument(
        "--file",
        type=str,
        default="logs/sample_auth.log",
        help="Path to the SSH authentication log file."
    )

    # Minimum number of failed attempts needed to trigger an alert
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Minimum failed login attempts required to trigger an alert (default: 5)."
    )

    # Time window for detecting repeated failed attempts
    parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Detection time window in seconds (default: 60)."
    )

    # Read the arguments supplied by the user
    args = parser.parse_args()

    # Validate command-line arguments
    if args.threshold < 1:
        parser.error("--threshold must be at least 1.")

    if args.window < 0:
        parser.error("--window cannot be negative.")

    # Locate project root directory
    project_root = Path(__file__).resolve().parent.parent
        
    # Resolve the authentication log path
    log_path = Path(args.file)
    
    # Handle relative file paths
    if not log_path.is_absolute():
        log_path = Path.cwd() / log_path

    # Verify that the authentication log exists
    if not log_path.is_file():
        parser.error(f"Log file not found: {log_path}")

    # Attempt to read and parse the authentication log
    try:
        events = parse_log_file(log_path)

    except PermissionError:
        parser.error(f"Permission denied when reading: {log_path}")

    except UnicodeError:
        parser.error(f"Unable to decode log file: {log_path}")

    except OSError as error:
        parser.error(f"Unable to read log file: {error}")

    # Stop if no valid authentication events were found
    if not events:
        print(f"\nNo valid SSH authentication events found in: {log_path}")
        return

    # Detect potential brute-force attacks
    alerts = detect_brute_force(
        events,
        threshold=args.threshold,
        window_seconds=args.window
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