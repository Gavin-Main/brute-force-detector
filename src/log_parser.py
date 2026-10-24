"""
Project: brute-force-detector

File: log_parser.py

Description: Reads and parses SSH authentication logs to extract timestamps, source IP
             addresses, usernames, and authentication results. Validates extracted
             information and converts matching log entries into structured event data.

Created by: Gavin Main

Date Finalized: 
"""

import re
import ipaddress
from datetime import datetime

LOG_PATTERN = re.compile(

    # Captures timestamp
    r"^(?P<timestamp>\S+)\s+"
    
    # Matches SSH daemon name and process ID
    r"sshd\[\d+\]:\s+"
    
    # Captures login result
    r"(?P<result>Failed|Accepted) password for "
    
    # Handles attempts against nonexistent usernames
    r"(?:invalid user )?"
    
    # Captures the targeted username
    r"(?P<username>\S+) from "
    
    # Captures source IP address
    r"(?P<ip>\S+) port \d+ ssh2$"
)

"""
Parses a single SSH authentication log entry.

Extracts the timestamp, source IP address,
username, and authentication result.

Returns a dictionary containing the extracted
information, or None is the entry is invalid.
"""
def parse_log_line(line):

    # Checks whether log entry matches our regex
    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    # If it is a match, extract captured values
    data = match.groupdict()

    try:
        timestamp = datetime.fromisoformat(
            data["timestamp"]
        )

        ipaddress.ip_address(data["ip"])

    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "ip": data["ip"],
        "username": data["username"],
        "result": data["result"].lower()
    }

"""
Reads an SSH authentication log file and
parses each entry into structured data.

Returns a list of dictionaries containing
valid authentication events.
"""
def parse_log_file(filepath):

    events = []

    with open(filepath, "r", encoding="utf-8") as file:
        for line in file:
            event = parse_log_line(line)

            if event is not None:
                events.append(event)

    return events

