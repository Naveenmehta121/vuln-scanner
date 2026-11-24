# VulnScanner

A small, ethical **command-line security scanner** written in pure Python
(standard library only — nothing to install).

Point it at a target **you own or have permission to test** and it checks
four things, then prints a report with severity ratings (High / Medium / Low)
and a concrete fix for every finding.

## Why I built this

I wanted to learn how real security checks work under the hood — what a
"missing security header" actually means, how a TLS certificate is read,
why a short password policy is dangerous — so I built the scanner instead
of just reading about it. Every check is written in plain, commented code
so a beginner can follow it.

## What it checks

| Check | What it does |
|---|---|
| **Open ports** | Tries a TCP connection to each port you list. Open risky ports (databases, Telnet, FTP) are flagged High. |
| **Security headers** | Fetches the site and checks for 6 standard headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy). |
| **SSL certificate** | Connects over TLS and reads the certificate's expiry date. Expired = High, expiring within 30 days = Medium. |
| **Password policy** | Reads a local JSON file describing password rules (length, character types, lockout, expiry) and judges them. **Local config only — it never tries passwords and never brute-forces anything.** |

Exit code: `1` if any **High** finding exists, `0` otherwise — so you can
use it in CI to fail a build when something serious is open.

## Tech stack

- **Python 3.8+** — standard library only (`socket`, `ssl`, `http.client`,
  `argparse`, `json`). No dependencies, no virtualenv needed.
- **Tests:** `unittest` (also stdlib), run with `python -m unittest discover -s tests -v`.

## Folder structure

```
vuln-scanner/
├── vuln_scanner/            # the scanner package
│   ├── __init__.py          # version + what the tool does
│   ├── __main__.py          # lets you run: python -m vuln_scanner
│   ├── cli.py               # argument parsing + scan orchestration
│   ├── port_scanner.py      # TCP port checks
│   ├── headers.py           # HTTP security-header checks
│   ├── ssl_check.py         # TLS certificate expiry checks
│   ├── password_policy.py   # local password-policy JSON checks
│   └── report.py            # report building (text + JSON)
├── tests/
│   ├── test_server.py       # deliberately insecure local test server
│   ├── test_vuln_scanner.py # unit tests (7 tests)
│   ├── weak_policy.json     # example weak password policy (gets flagged)
│   └── strong_policy.json   # example strong policy (passes clean)
├── README.md
├── LICENSE                  # MIT
└── .gitignore
```

## How to run

No installation needed — just Python 3.8+.

```bash
# 1. Go into the project
cd vuln-scanner

# 2. Start the local test server (in its own terminal window/tab)
python tests/test_server.py
#    -> Test server running at http://127.0.0.1:8000/

# 3. In another terminal, scan it
python -m vuln_scanner scan localhost --ports 8000 --port 8000

# 4. Scan it with the weak password-policy example too
python -m vuln_scanner scan localhost --ports 8000 --port 8000 \
    --config tests/weak_policy.json

# 5. Save the report as JSON as well
python -m vuln_scanner scan localhost --ports 8000 --port 8000 \
    --config tests/weak_policy.json --output report.json

# 6. Stop the test server with Ctrl+C when you're done
```

### Scanning a real target you own

```bash
# Common ports + headers on a site you own (HTTP)
python -m vuln_scanner scan example.com

# HTTPS site, including the SSL certificate check
python -m vuln_scanner scan example.com --https --ssl

# Only specific ports
python -m vuln_scanner scan example.com --ports 22,80,443,3306
```

### Run the unit tests

```bash
python -m unittest discover -s tests -v
# 7 tests, all passing, no network needed except localhost
```

## How to demo in 60 seconds

1. **Terminal 1:** `python tests/test_server.py` — "This is a deliberately
   insecure test server I run locally, so I never touch a real site."
2. **Terminal 2:** `python -m vuln_scanner scan localhost --ports 8000 --port 8000 --config tests/weak_policy.json`
3. **Point at the output:** "13 findings — 1 High, 3 Medium, 9 Low. The
   High one is a 6-character minimum password; every missing header is
   listed with the exact header to add; and the exit code is 1, so this
   can fail a CI build."
4. **Show the fix:** run the same command with
   `--config tests/strong_policy.json` and the password findings disappear.
5. **Close with the ethics line:** "It only reads — it never attacks, never
   brute-forces, and the test server exists so the demo is always safe."

## Explain this in an interview

- **"What does it do?"** — A CLI that scans a host you own for open ports,
  missing HTTP security headers, SSL certificate expiry, and weak password
  policy, then reports each finding with a severity and a fix.
- **"How does the port scan work?"** — For each port it attempts a TCP
  connection with a short timeout (`socket.create_connection`). A successful
  handshake means something is listening. Risky ports like databases and
  Telnet are flagged High.
- **"How do you check SSL expiry?"** — It opens a TLS connection, reads the
  certificate the server presents with `getpeercert()`, parses `notAfter`,
  and compares it to today — expired is High, under 30 days is Medium.
- **"Why is there no brute-forcing?"** — The password check only reads a
  local JSON config describing the rules. Trying real passwords is an attack,
  not a scan — and it would be illegal without permission. The tool is
  designed so the unethical path doesn't exist in the code.
- **"What would you add next?"** — A check for outdated server software
  versions (from the `Server` header), a `--quiet` mode for CI, and scanning
  a list of hosts from a file.

## Ethics — read this first

**Only scan targets you own or have written permission to test.**
Scanning someone else's server without permission can be illegal
(computer-misuse laws apply in most countries) and can get your IP banned.

This tool is deliberately limited: it only *reads* public information
(open ports, response headers, certificate dates, a config file you give
it). It does not exploit anything, guess passwords, or flood a target.
The included test server exists precisely so you can learn and demo
without ever touching a third-party site.

## Honest limits — what it does NOT do

- **No vulnerability exploitation.** It finds *missing defences*, it does
  not prove a site is exploitable (that's what tools like Nmap/Nessus and
  manual pentesting are for).
- **No service/version detection.** It doesn't banner-grab or fingerprint
  what's running on an open port, so it can't tell you if that service is
  outdated.
- **No web crawling or XSS/SQLi testing.** It checks headers, not the
  application's inputs — it will not find injection flaws.
- **No brute-forcing, ever.** The password check is a local config review.
- **No stealth.** It connects openly and identifies itself in the
  User-Agent (`VulnScanner/1.0`) — a firewall may log or block it.
- **Single host, single run.** No scheduling, no multi-host scans, no
  historical comparison of reports (yet).
- **SSL check reads dates only.** It does not validate the certificate
  chain, so a self-signed or wrong-host certificate is not flagged.

## License

MIT — see [LICENSE](LICENSE).
