"""
Project: brute-force-detector

File: detector.py

Description: Analyzes SSH authentication events to identify potential brute-force attacks.
             Groups failed login attempts by source IP address and uses a sliding-window
             algorithm to detect repeated failures within a configurable time period.

Created by: Gavin Main

Date Finalized: 
"""

from collections import defaultdict

"""
Groups failed SSH authentication events by source IP address.

Args: 
    events (list): List of parsed authentication events.

Returns: 
    dict: IP addresses mapped to lists of failed login attempts.
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

"""
Detects potential brute-force attacks based on repeated failed
login attempts from the same IP within a specified time window.

Args:
    events (list): List of parsed authentication events.
    threshold (int): Minimum failed attempts to trigger an alert.
    window_seconds (int): Time window in seconds.

Returns:
    list: Dictionaries containing suspicious login activity.
"""
def detect_brute_force(events, threshold=5, window_seconds=60):

    # Validate detection settings
    if threshold < 1 or window_seconds < 0:
        raise ValueError("Invalid detection settings")

    # Group failed login attempts by source IP
    failed_attempts = group_failed_attempts(events)

    # Store detected suspicious activity
    alerts = []

    # Analyze failed attempts for each IP
    for ip, attempts in failed_attempts.items():

            # Sort attempts by timestamp
            attempts.sort(key=lambda event: event["timestamp"])

            # Starting position of the sliding window
            window_start = 0

            # Examine each failed attempt
            for window_end in range(len(attempts)):

                current_time = attempts[window_end]["timestamp"]

                # Remove attempts outside the time window
                while (
                    current_time - attempts[window_start]["timestamp"]
                ).total_seconds() > window_seconds:

                    window_start += 1

                # Count attempts within the current window
                count = window_end - window_start + 1

                # Check whether the detection threshold is reached
                if count >= threshold:

                    # Create an alert for the suspicious IP
                    alert = {
                        "ip": ip,
                        "total_failed_attempts": len(attempts),
                        "failed_attempts": count,
                        "time_window": window_seconds,
                        "first_attempt": attempts[window_start]["timestamp"],
                        "last_attempt": current_time,
                        "usernames": sorted({
                            event["username"]
                            for event in attempts[window_start:window_end + 1]
                        }),
                        "severity": "HIGH"
                    }

                    alerts.append(alert)

                    # Generate only one alert per IP
                    break
    return alerts

