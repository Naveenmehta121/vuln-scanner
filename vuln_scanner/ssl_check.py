"""
SSL certificate checker: connects to the target over TLS and reads the
certificate the server presents.

We check three things:
  1. Is there a certificate at all? (No TLS = no encryption.)
  2. Is it expired?  (Expired = browsers block the site.)
  3. Does it expire soon (within 30 days)? (Renew before it breaks.)

The expiry date comes from the certificate itself, so this works even
against a self-signed cert — we only read dates, we never trust the cert.
"""

import socket
import ssl
from datetime import datetime, timezone

EXPIRY_WARNING_DAYS = 30  # warn when the cert expires within this many days


def check_ssl(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Return findings about the target's TLS certificate (empty = OK)."""
    try:
        ctx = ssl.create_default_context()
        # We only want to READ the certificate, not validate the chain,
        # so verification is off — an expired cert is a finding, not an error.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except Exception as exc:
        return [{
            "check": "ssl",
            "severity": "High",
            "title": "No valid TLS/SSL connection possible",
            "detail": f"Could not establish a TLS connection to {host}:{port}: {exc}",
            "fix": "Enable HTTPS with a valid certificate (e.g. free from "
                   "Let's Encrypt) or check that the port is open.",
        }]

    # notAfter looks like 'Nov 24 12:00:00 2026 GMT'
    expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    expiry = expiry.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    days_left = (expiry - now).days

    if days_left < 0:
        return [{
            "check": "ssl",
            "severity": "High",
            "title": "SSL certificate has EXPIRED",
            "detail": f"Certificate expired on {expiry.date()} "
                      f"({abs(days_left)} days ago). Browsers will block the site.",
            "fix": "Renew the certificate immediately and automate renewal "
                   "(e.g. certbot renew) so it never lapses again.",
        }]
    if days_left <= EXPIRY_WARNING_DAYS:
        return [{
            "check": "ssl",
            "severity": "Medium",
            "title": f"SSL certificate expires soon ({days_left} days left)",
            "detail": f"Certificate expires on {expiry.date()}.",
            "fix": "Renew the certificate now and set up automated renewal "
                   "with a reminder at least 14 days before expiry.",
        }]
    return []  # certificate is fine — nothing to report
