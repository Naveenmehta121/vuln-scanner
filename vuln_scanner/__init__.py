"""
VulnScanner — a small, ethical security scanner.

Scans a target *you own or have permission to test* for:
  * open ports
  * missing HTTP security headers
  * expired / soon-to-expire SSL certificates
  * weak password policy (checks a local config file only — never brute force)

Usage:
    python -m vuln_scanner scan localhost --ports 80,8000,443
    python -m vuln_scanner scan example.com --https
    python -m vuln_scanner scan localhost --config tests/weak_policy.json

Everything in this package uses the Python standard library only,
so there is nothing to install.
"""

__version__ = "1.0.0"
