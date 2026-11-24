"""
Local test target — a tiny, deliberately insecure HTTP server.

It exists so you can demo VulnScanner safely against localhost without
ever touching a real website. It is insecure ON PURPOSE:
  * it sends NO security headers at all
  * it runs on port 8000 (open by definition while it runs)

Run it in one terminal, then scan it from another:
    python tests/test_server.py
    python -m vuln_scanner scan localhost --ports 8000 --port 8000

Press Ctrl+C to stop it. Never expose this server to the internet.
"""

import http.server

HOST = "127.0.0.1"
PORT = 8000


class VulnerableHandler(http.server.SimpleHTTPRequestHandler):
    """A plain HTTP handler with zero security headers — the point is
    that VulnScanner should flag every missing header."""

    def log_message(self, *args):  # keep the terminal output quiet
        pass


if __name__ == "__main__":
    server = http.server.HTTPServer((HOST, PORT), VulnerableHandler)
    print(f"Test server running at http://{HOST}:{PORT}/")
    print("It sends NO security headers on purpose.")
    print("Scan it with: python -m vuln_scanner scan localhost "
          "--ports 8000 --port 8000")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.server_close()
