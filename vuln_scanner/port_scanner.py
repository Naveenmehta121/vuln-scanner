"""
Port scanner: checks whether a list of TCP ports on the target is open.

How it works
------------
For each port we try to open a TCP connection with a short timeout.
If the connect succeeds, the port is OPEN (something is listening).
If it times out or is refused, the port is CLOSED.

Ethics: only scan hosts you own or have written permission to test.
We deliberately do NOT do banner grabbing, service fingerprinting or
brute-forcing — this is a teaching tool, not an attack tool.
"""

import socket

# Common ports worth checking, with a short description of the service
# that usually lives there. Used when the user does not pass --ports.
COMMON_PORTS = {
    21: "FTP (file transfer, often unencrypted)",
    22: "SSH (remote shell)",
    23: "Telnet (unencrypted remote shell — dangerous if open)",
    25: "SMTP (mail)",
    53: "DNS",
    80: "HTTP (web)",
    110: "POP3 (mail)",
    143: "IMAP (mail)",
    443: "HTTPS (secure web)",
    3306: "MySQL database",
    5432: "PostgreSQL database",
    6379: "Redis (in-memory store)",
    8080: "HTTP alternate (web / proxy)",
    27017: "MongoDB database",
}

# Ports that are a red flag when exposed to the internet, because they
# usually mean a database or admin service is reachable by anyone.
RISKY_PORTS = {21, 23, 3306, 5432, 6379, 27017}


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Try to connect to one port. True = open, False = closed/filtered."""
    try:
        # create_connection() does the DNS lookup + TCP handshake for us.
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_ports(host: str, ports: list, timeout: float = 1.0) -> list:
    """
    Scan a list of ports and return one finding (dict) per OPEN port.
    Closed ports are not reported — a report should only list problems.
    """
    findings = []
    for port in ports:
        if is_port_open(host, port, timeout):
            service = COMMON_PORTS.get(port, "unknown service")
            risky = port in RISKY_PORTS
            findings.append({
                "check": "open-port",
                "severity": "High" if risky else "Low",
                "title": f"Port {port} is open ({service})",
                "detail": (
                    f"Something is listening on TCP port {port}. "
                    f"Expected service: {service}."
                ),
                "fix": (
                    "Close this port in your firewall if the service is not "
                    "needed, or bind it to localhost / a private network only."
                    if risky else
                    "Confirm this service is intentional and up to date; "
                    "close the port if it is not needed."
                ),
            })
    return findings
