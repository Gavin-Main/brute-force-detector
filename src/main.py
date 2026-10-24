"""
Project: brute-force-detector

File: main.py

Description: 

Created by: Gavin Main

Date Finalized: 
"""

from pathlib import Path
from log_parser import parse_log_file

def main():
    project_root = Path(__file__).resolve().parent.parent
    log_path = project_root / "logs" / "sample_auth.log"

    events = parse_log_file(log_path)

    print(f"Successfully parsed {len(events)} events.\n")

    for event in events[:5]:
        print(event)

if __name__ == "__main__":
    main()