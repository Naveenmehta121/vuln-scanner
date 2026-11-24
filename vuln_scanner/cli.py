"""
CLI entry point: `python -m vuln_scanner scan <target> [options]`

Options:
  --ports 80,443,8000   comma-separated ports to scan (default: common ports)
  --https               scan https://target instead of http://target
  --port 8000           port used for the header check (default 80 / 443)
  --ssl                 also check the SSL certificate (needs port 443 by default)
  --ssl-port 443        port to use for the SSL check
  --config FILE         password-policy JSON file to check (local config only)
  --output FILE         save the report as JSON to FILE (text still prints)
"""

import argparse
import sys

from .headers import check_headers
from .password_policy import check_password_policy
from .port_scanner import COMMON_PORTS, scan_ports
from .report import build_report, render_text, save_json
from .ssl_check import check_ssl


def parse_ports(value: str) -> list:
    """Turn '80,443,8000' into [80, 443, 8000]. Raises ValueError on bad input."""
    ports = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        port = int(part)
        if not 1 <= port <= 65535:
            raise ValueError(f"port out of range: {port}")
        ports.append(port)
    if not ports:
        raise ValueError("no ports given")
    return ports


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="vuln-scanner",
        description="Ethical security scanner — only scan targets you own "
                    "or have permission to test.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a target host")
    scan.add_argument("target", help="hostname or IP, e.g. localhost")
    scan.add_argument("--ports", default=",".join(map(str, sorted(COMMON_PORTS))),
                      help="comma-separated ports to scan "
                           "(default: common ports)")
    scan.add_argument("--https", action="store_true",
                      help="use https:// for the header check")
    scan.add_argument("--port", type=int, default=None,
                      help="port for the header check (default: 443 with "
                           "--https, else 80)")
    scan.add_argument("--ssl", action="store_true",
                      help="also check the SSL certificate")
    scan.add_argument("--ssl-port", type=int, default=443,
                      help="port for the SSL check (default: 443)")
    scan.add_argument("--config",
                      help="password-policy JSON file to check (local only)")
    scan.add_argument("--output",
                      help="save the report as JSON to this file")

    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args)
    return 0


def run_scan(args) -> int:
    target = args.target
    print(f"Scanning {target} ... (only scan targets you own or have "
          f"permission to test)\n")

    findings = []

    # 1. Open ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"Error: invalid --ports value: {exc}", file=sys.stderr)
        return 2
    print(f"[*] Checking {len(ports)} ports ...")
    findings += scan_ports(target, ports)

    # 2. Security headers
    scheme = "https" if args.https else "http"
    header_port = args.port or (443 if args.https else 80)
    url = f"{scheme}://{target}:{header_port}"
    print(f"[*] Checking security headers on {url} ...")
    findings += check_headers(url)

    # 3. SSL certificate (only when asked — needs a TLS port)
    if args.ssl:
        print(f"[*] Checking SSL certificate on {target}:{args.ssl_port} ...")
        findings += check_ssl(target, args.ssl_port)

    # 4. Password policy (local config file only — never brute force)
    if args.config:
        print(f"[*] Checking password policy in {args.config} ...")
        findings += check_password_policy(args.config)

    report = build_report(target, findings)
    print()
    print(render_text(report))

    if args.output:
        save_json(report, args.output)
        print(f"JSON report saved to {args.output}")

    # Exit code: 1 if any High-severity finding, else 0.
    # Useful for CI: a failing build when something serious is open.
    return 1 if report["summary"]["high"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
