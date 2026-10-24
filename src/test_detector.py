"""
Project: brute-force-detector

File: test_detector.py

Description: 

Created by: Gavin Main

Date Finalized: 
"""

import unittest
from datetime import datetime, timedelta
from detector import detect_brute_force

# Creates a class containing unit tests.
class TestBruteForceDetector(unittest.TestCase):

    # Creates a starting timestamp for each test.
    def setUp(self):
        self.start_time = datetime(2026, 10, 23, 10, 0, 0)

    # Creates a simulated SSH authentication event.
    def create_event(self, seconds, ip="192.0.2.45", 
                     result="failed", username="admin"):

        return {
            "timestamp": self.start_time + timedelta(seconds=seconds),
            "ip": ip,
            "username": username,
            "result": result
        }

    # Five failures within Detection Window should trigger an alert.
    def test_detect_brute_force(self):
        events = [
            self.create_event(seconds)
            for seconds in [0, 10, 20, 30, 40]
        ]

        alerts = detect_brute_force(events)

        # Checks whether the actual result matches the expected result.
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ip"], "192.0.2.45")
        self.assertEqual(alerts[0]["failed_attempts"], 5)
        self.assertEqual(alerts[0]["total_failed_attempts"], 5)

    # Four failures should not trigger an alert.
    def test_below_threshold(self):
        events = [
            self.create_event(seconds)
            for seconds in [0, 10, 20, 30]
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    # Five failures spread beyond Detection Window should not trigger.
    def test_outside_time_window(self):
        events = [
            self.create_event(seconds)
            for seconds in [0, 20, 40, 60, 80]
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

# Five failures spanning the Detection Window exactly should trigger.
    def test_exact_window_boundary(self):
        events = [
            self.create_event(seconds)
            for seconds in [0, 15, 30, 45, 60]
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failed_attempts"], 5)

    # Successful logins should not count toward threshold.
    def test_successful_logins_ignored(self):
        events = [
            self.create_event(0),
            self.create_event(10),
            self.create_event(20, result="accepted"),
            self.create_event(30),
            self.create_event(40)
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    # Detector should correctly process events out of order.
    def test_unsorted_events(self):
        events = [
            self.create_event(seconds)
            for seconds in [40, 0, 30, 10, 20]
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failed_attempts"], 5)
        self.assertEqual(
            alerts[0]["first_attempt"],
            self.start_time
        )

    # Each suspicious IP should generate its own alert.
    def test_multiple_ip_addresses(self):
        events = []

        for seconds in [0, 10, 20, 30, 40]:
            events.append(
                self.create_event(seconds, ip="192.0.2.45")
            )
            events.append(
                self.create_event(seconds, ip="203.0.113.88")
            )

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 2)

        detected_ips = {alert["ip"] for alert in alerts}

        self.assertEqual(
            detected_ips,
            {"192.0.2.45", "203.0.113.88"}
        )


if __name__ == "__main__":
    unittest.main()
