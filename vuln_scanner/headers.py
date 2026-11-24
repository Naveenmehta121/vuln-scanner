"""
Security-header checker: fetches a page over HTTP(S) and looks for the
headers browsers rely on to protect users.

Headers we check (all are standard, well-documented headers):
  * Strict-Transport-Security  — forces HTTPS, stops downgrade attacks
  * Content-Security-Policy    — limits where scripts/styles may load from
  * X-Frame-Options            — stops clickjacking (page embedded in iframe)
  * X-Content-Type-Options     — stops MIME-sniffing attacks
  * Referrer-Policy            — limits what the browser leaks in Referer
  * Permissions-Policy         — disables risky browser features (camera, mic…)

A missing header is not a hack by itself, but it removes a layer of
defence — that is why each missing header is a finding with a fix.
"""

import http.client
import ssl
import urllib.parse

# header name -> (severity, why it matters, how to fix it)
EXPECTED_HEADERS = {
    "strict-transport-security": (
        "Medium",
        "Without HSTS, a first visit over plain HTTP can be downgraded "
        "or intercepted before the browser ever learns to use HTTPS.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    "content-security-policy": (
        "Medium",
        "Without a CSP, an injected script (XSS) runs with full page "
        "privileges — CSP is the main defence-in-depth against XSS.",
        "Add a restrictive Content-Security-Policy, e.g. "
        "default-src 'self'; script-src 'self'",
    ),
    "x-frame-options": (
        "Low",
        "Without it, your page can be embedded in an invisible iframe on "
        "an attacker's site (clickjacking) to trick users into clicking.",
        "Add: X-Frame-Options: DENY  (or SAMEORIGIN if you frame yourself)",
    ),
    "x-content-type-options": (
        "Low",
        "Without nosniff, browsers may guess a file's type and execute an "
        "uploaded file as JavaScript (MIME-sniffing attack).",
        "Add: X-Content-Type-Options: nosniff",
    ),
    "referrer-policy": (
        "Low",
        "Without it, browsers may send the full page URL (possibly with "
        "tokens in the query string) to other sites in the Referer header.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    "permissions-policy": (
        "Low",
        "Without it, any script on the page can request camera, "
        "microphone or geolocation access.",
        "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ),
}


def fetch_headers(url: str, timeout: float = 5.0) -> dict:
    """GET the URL and return its response headers (lower-cased keys)."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"

    if parsed.scheme == "https":
        # For a *header* check we don't need to verify the cert here —
        # ssl_check.py handles certificate validation separately.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    conn.request("GET", path, headers={"User-Agent": "VulnScanner/1.0"})
    response = conn.getresponse()
    response.read()  # drain the body so the connection closes cleanly
    conn.close()
    return {k.lower(): v for k, v in response.getheaders()}


def check_headers(url: str) -> list:
    """Return one finding per missing security header."""
    try:
        headers = fetch_headers(url)
    except Exception as exc:  # host down, DNS failure, refused connection…
        return [{
            "check": "security-headers",
            "severity": "Medium",
            "title": "Could not fetch the site to check headers",
            "detail": f"Request to {url} failed: {exc}",
            "fix": "Make sure the target is up and reachable, then re-run.",
        }]

    findings = []
    for name, (severity, why, fix) in EXPECTED_HEADERS.items():
        if name not in headers:
            findings.append({
                "check": "security-headers",
                "severity": severity,
                "title": f"Missing security header: {name}",
                "detail": why,
                "fix": fix,
            })
    return findings
