"""
Project: brute-force-detector

File: detector.py

Description: 

Created by: Gavin Main

Date Finalized: 
"""

from collections import defaultdict

"""
Groups failed SSH authentication events by source IP address.

Args: events (list) -> List of parsed authentication events.

Returns: dict -> IP addresses mapped to lists of failed login attempts.
"""
def group_failed_attempts(events):

    # Dictionary to store failed attempts for each IP
    failed_attempts = defaultdict(list)

    # Loop through each authentication event
    for event in events:

        # Only process failed login attempts
        if event["result"] == "failed":

            # Add the failed event to its source IP's list
            failed_attempts[event["ip"]].append(event)

    return failed_attempts