"""
Unit tests for VulnScanner. Run with:
    python -m unittest discover -s tests -v
No network access needed except localhost.
"""

import json
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vuln_scanner.headers import check_headers
from vuln_scanner.password_policy import check_password_policy
from vuln_scanner.port_scanner import is_port_open, scan_ports
from vuln_scanner.report import build_report

from test_server import HOST, PORT, VulnerableHandler
import http.server


class TestPortScanner(unittest.TestCase):
    def test_open_port_detected(self):
        server = http.server.HTTPServer((HOST, 0), VulnerableHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.assertTrue(is_port_open(HOST, port))
            findings = scan_ports(HOST, [port])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["check"], "open-port")
        finally:
            server.shutdown()
            server.server_close()

    def test_closed_port_not_reported(self):
        # Port 1 is (almost) never open on localhost.
        self.assertFalse(is_port_open(HOST, 1, timeout=0.5))
        self.assertEqual(scan_ports(HOST, [1]), [])


class TestHeaders(unittest.TestCase):
    def test_missing_headers_flagged(self):
        server = http.server.HTTPServer((HOST, 0), VulnerableHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            findings = check_headers(f"http://{HOST}:{port}")
            missing = {f["title"] for f in findings}
            # The test server sends none of the six headers.
            self.assertEqual(len(findings), 6)
            self.assertIn("Missing security header: content-security-policy",
                          missing)
        finally:
            server.shutdown()
            server.server_close()


class TestPasswordPolicy(unittest.TestCase):
    def test_weak_policy_flagged(self):
        path = os.path.join(os.path.dirname(__file__), "weak_policy.json")
        findings = check_password_policy(path)
        titles = [f["title"] for f in findings]
        self.assertTrue(any("6 characters" in t for t in titles))
        self.assertTrue(any("uppercase" in t for t in titles))
        self.assertTrue(any("lockout" in t.lower() for t in titles))

    def test_strong_policy_clean(self):
        path = os.path.join(os.path.dirname(__file__), "strong_policy.json")
        self.assertEqual(check_password_policy(path), [])

    def test_missing_file_reported(self):
        findings = check_password_policy("no-such-file.json")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Medium")


class TestReport(unittest.TestCase):
    def test_summary_counts_and_order(self):
        findings = [
            {"check": "x", "severity": "Low", "title": "l", "detail": "", "fix": ""},
            {"check": "x", "severity": "High", "title": "h", "detail": "", "fix": ""},
        ]
        report = build_report("localhost", findings)
        self.assertEqual(report["summary"], {"total": 2, "high": 1,
                                             "medium": 0, "low": 1})
        self.assertEqual(report["findings"][0]["severity"], "High")


if __name__ == "__main__":
    unittest.main()
