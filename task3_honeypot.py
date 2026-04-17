"""
Task 3: Deception-Based Security Mechanism — Honeypot System
=============================================================
Implements three deception traps:
  1. Fake login portal  (HTTP on port 8080)
  2. Honeypot file      (/tmp/honeypot_secrets.txt — monitored via polling)
  3. Dummy API service  (/api/admin/keys — looks real, logs all access)

Any interaction triggers a SUSPICIOUS ACTIVITY ALERT.
"""

import os
import sys
import time
import json
import hashlib
import logging
import threading
import http.server
import urllib.parse
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
HONEYPOT_PORT       = 8080
HONEYPOT_FILE_PATH  = "/tmp/honeypot_secrets.txt"
LOG_FILE            = "honeypot_alerts.log"
ALERT_LOG           = "honeypot_alerts.json"

# ─────────────────────────────────────────────
# Alert subsystem
# ─────────────────────────────────────────────
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)

alerts = []   # in-memory alert store

def raise_alert(trap: str, source: str, detail: str, severity: str = "HIGH"):
    ts = datetime.now().isoformat()
    alert = {
        "timestamp": ts,
        "trap": trap,
        "source": source,
        "detail": detail,
        "severity": severity,
    }
    alerts.append(alert)
    # Persist
    with open(ALERT_LOG, "w") as f:
        json.dump(alerts, f, indent=2)
    # Console + file log
    msg = (f"🚨 ALERT [{severity}] TRAP={trap} | SOURCE={source} | {detail}")
    print(msg)
    logging.warning(msg)
    return alert


# ─────────────────────────────────────────────
# Trap 1 — Fake Login Portal + Dummy API
# ─────────────────────────────────────────────
FAKE_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>SecureAdmin — Login</title>
<style>
  body { font-family: Arial, sans-serif; background:#1a1a2e; display:flex;
         justify-content:center; align-items:center; height:100vh; margin:0; }
  .card { background:#16213e; padding:2rem 2.5rem; border-radius:10px;
          box-shadow:0 0 30px rgba(0,255,255,0.1); min-width:320px; }
  h2 { color:#00b4d8; margin-bottom:1.5rem; text-align:center; }
  input { width:100%; padding:0.6rem; margin:0.4rem 0 1rem; border-radius:5px;
          border:1px solid #0f3460; background:#0f3460; color:#eee;
          box-sizing:border-box; }
  button { width:100%; padding:0.7rem; background:#00b4d8; color:#000;
           font-weight:bold; border:none; border-radius:5px; cursor:pointer; }
  .logo { text-align:center; color:#888; font-size:0.8rem; margin-top:1rem; }
</style>
</head>
<body>
<div class="card">
  <h2>🔒 SecureAdmin Portal</h2>
  <form method="POST" action="/login">
    <label style="color:#aaa">Username</label>
    <input type="text" name="username" placeholder="admin" required/>
    <label style="color:#aaa">Password</label>
    <input type="password" name="password" placeholder="••••••••" required/>
    <button type="submit">Sign In</button>
  </form>
  <div class="logo">SecureCorp Internal Systems v2.4.1</div>
</div>
</body>
</html>"""

FAKE_LOGIN_FAIL_HTML = """<!DOCTYPE html>
<html><head><title>Login Failed</title>
<style>body{background:#1a1a2e;color:#ff6b6b;font-family:Arial;
text-align:center;padding-top:20vh}</style></head>
<body><h2>Invalid credentials. This incident has been logged.</h2>
<p><a style="color:#00b4d8" href="/login">Try again</a></p>
</body></html>"""

def fake_api_response(path: str) -> dict:
    """Returns plausible-looking but fake API data."""
    if "keys" in path or "token" in path:
        return {
            "status": "success",
            "api_keys": [
                {"id": "ak_prod_xK9mQ2rT", "created": "2024-01-15", "scope": "full"},
                {"id": "ak_prod_pL3nW7vX", "created": "2024-03-22", "scope": "read"},
            ],
            "_note": "All access logged."
        }
    return {"status": "ok", "data": [], "_note": "All access logged."}


class HoneypotHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # Suppress default stderr logging

    def _client_ip(self):
        return self.client_address[0]

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        encoded = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", len(encoded))
        self.end_headers()
        self.wfile.write(encoded)

    # ── GET ──────────────────────────────────
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        ip   = self._client_ip()
        ua   = self.headers.get("User-Agent", "unknown")

        if path in ("/", "/login", "/admin", "/admin/login"):
            raise_alert("FAKE_LOGIN_PORTAL",
                        ip,
                        f"GET {path} | UA={ua}",
                        "MEDIUM")
            self._send(200, FAKE_LOGIN_HTML)

        elif path.startswith("/api/"):
            raise_alert("DUMMY_API",
                        ip,
                        f"GET {path} | UA={ua}",
                        "HIGH")
            resp = json.dumps(fake_api_response(path))
            self._send(200, resp, "application/json")

        elif path == "/alerts":
            # Internal dashboard — show current alerts
            self._send(200, json.dumps(alerts, indent=2), "application/json")

        else:
            raise_alert("UNKNOWN_PROBE",
                        ip,
                        f"GET {path} | UA={ua}",
                        "LOW")
            self._send(404, "<h1>404 Not Found</h1>")

    # ── POST ─────────────────────────────────
    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        ip   = self._client_ip()

        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8", errors="replace")

        if path in ("/login", "/admin/login"):
            params = dict(urllib.parse.parse_qsl(body))
            username = params.get("username", "<none>")
            password = params.get("password", "<none>")
            # Hash password in log (don't store plaintext)
            pw_hash = hashlib.sha256(password.encode()).hexdigest()[:16]
            raise_alert("FAKE_LOGIN_PORTAL",
                        ip,
                        f"POST login attempt | user={username} pw_hash={pw_hash}",
                        "CRITICAL")
            self._send(401, FAKE_LOGIN_FAIL_HTML)

        elif path.startswith("/api/"):
            raise_alert("DUMMY_API",
                        ip,
                        f"POST {path} | body={body[:200]}",
                        "HIGH")
            resp = json.dumps({"status": "unauthorized", "message": "Access denied."})
            self._send(403, resp, "application/json")

        else:
            raise_alert("UNKNOWN_PROBE",
                        ip,
                        f"POST {path}",
                        "LOW")
            self._send(404, "Not Found")


# ─────────────────────────────────────────────
# Trap 2 — Honeypot File Monitor
# ─────────────────────────────────────────────
def create_honeypot_file():
    """Creates a tempting-looking secrets file."""
    content = """\
# INTERNAL USE ONLY — DO NOT DISTRIBUTE
# SecureCorp Credentials Store v3
# Generated: 2024-06-01

DB_HOST     = prod-db.securecorp.internal
DB_USER     = svc_app
DB_PASS     = Tr0ub4dor&3

AWS_KEY_ID      = AKIA4EXAMPLE00000001
AWS_SECRET_KEY  = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

ADMIN_TOKEN     = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.FAKE.SIGNATURE
"""
    Path(HONEYPOT_FILE_PATH).write_text(content)
    print(f"[*] Honeypot file created at: {HONEYPOT_FILE_PATH}")
    return os.stat(HONEYPOT_FILE_PATH)


def monitor_honeypot_file(initial_stat, stop_event):
    """Polls the honeypot file every second; raises alert on any access."""
    prev_atime = initial_stat.st_atime
    prev_mtime = initial_stat.st_mtime

    while not stop_event.is_set():
        try:
            s = os.stat(HONEYPOT_FILE_PATH)
        except FileNotFoundError:
            raise_alert("HONEYPOT_FILE",
                        "FILESYSTEM",
                        f"Honeypot file DELETED: {HONEYPOT_FILE_PATH}",
                        "CRITICAL")
            break

        if s.st_atime != prev_atime:
            raise_alert("HONEYPOT_FILE",
                        "FILESYSTEM",
                        f"File READ detected: {HONEYPOT_FILE_PATH}",
                        "HIGH")
            prev_atime = s.st_atime

        if s.st_mtime != prev_mtime:
            raise_alert("HONEYPOT_FILE",
                        "FILESYSTEM",
                        f"File MODIFIED: {HONEYPOT_FILE_PATH}",
                        "CRITICAL")
            prev_mtime = s.st_mtime

        stop_event.wait(1.0)


# ─────────────────────────────────────────────
# Main — Start All Traps
# ─────────────────────────────────────────────
def run_honeypot(duration=None):
    """Start all traps. If duration (seconds) given, auto-stop after that time."""
    print("\n" + "═" * 60)
    print("   DECEPTION-BASED SECURITY SYSTEM — HONEYPOT ACTIVE")
    print("═" * 60)

    stop_event = threading.Event()

    # Trap 2 — File honeypot
    initial_stat = create_honeypot_file()
    file_thread  = threading.Thread(
        target=monitor_honeypot_file,
        args=(initial_stat, stop_event),
        daemon=True
    )
    file_thread.start()

    # Trap 1 & 3 — HTTP server (login + API)
    server = http.server.HTTPServer(("0.0.0.0", HONEYPOT_PORT), HoneypotHandler)
    server.timeout = 1.0
    srv_thread = threading.Thread(target=_serve_forever,
                                  args=(server, stop_event),
                                  daemon=True)
    srv_thread.start()

    print(f"[*] Fake login portal  : http://localhost:{HONEYPOT_PORT}/login")
    print(f"[*] Dummy API endpoint : http://localhost:{HONEYPOT_PORT}/api/admin/keys")
    print(f"[*] Honeypot file      : {HONEYPOT_FILE_PATH}")
    print(f"[*] Alert log          : {ALERT_LOG}")
    print(f"[*] Press Ctrl+C to stop.\n")

    try:
        if duration:
            time.sleep(duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        server.server_close()
        # Remove honeypot file on clean exit
        try:
            os.remove(HONEYPOT_FILE_PATH)
        except Exception:
            pass
        print(f"\n[*] Honeypot stopped. Total alerts: {len(alerts)}")
        print(f"[*] Alerts saved to: {ALERT_LOG}\n")


def _serve_forever(server, stop_event):
    while not stop_event.is_set():
        server.handle_request()


# ─────────────────────────────────────────────
# Demo — simulate attacker interactions
# ─────────────────────────────────────────────
def run_demo():
    import urllib.request
    import urllib.error

    print("\n" + "═" * 60)
    print("  HONEYPOT DEMO — Simulating Attacker Interactions")
    print("═" * 60 + "\n")

    # Start honeypot in background for 30 seconds
    stop_event = threading.Event()
    initial_stat = create_honeypot_file()
    ft = threading.Thread(target=monitor_honeypot_file,
                          args=(initial_stat, stop_event), daemon=True)
    ft.start()
    server = http.server.HTTPServer(("127.0.0.1", HONEYPOT_PORT), HoneypotHandler)
    server.timeout = 0.5
    st = threading.Thread(target=_serve_forever, args=(server, stop_event), daemon=True)
    st.start()
    time.sleep(0.5)

    base = f"http://127.0.0.1:{HONEYPOT_PORT}"

    def req(method, url, data=None, label=""):
        print(f"\n--- Simulating: {label} ---")
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(
                    url,
                    data=data.encode() if data else None,
                    method=method,
                    headers={"User-Agent": "Mozilla/5.0 (AttackerBot/1.0)"}
                ), timeout=3
            )
            body = r.read(200).decode("utf-8", errors="replace")
            print(f"    HTTP {r.status} — {body[:80]}…")
        except urllib.error.HTTPError as e:
            print(f"    HTTP {e.code} (expected)")
        except Exception as e:
            print(f"    Error: {e}")

    # Attacker interactions
    req("GET",  f"{base}/login",                    label="Probe fake login page")
    req("POST", f"{base}/login", "username=admin&password=admin123",
                                                    label="Login brute-force attempt")
    req("POST", f"{base}/login", "username=root&password=toor",
                                                    label="Login brute-force attempt 2")
    req("GET",  f"{base}/api/admin/keys",           label="Access dummy API (key theft)")
    req("POST", f"{base}/api/admin/keys",
        '{"action":"export"}',                      label="POST to dummy API")
    req("GET",  f"{base}/api/v2/users",             label="API enumeration")

    # Simulate file access (honeypot file read)
    print("\n--- Simulating: Honeypot file read ---")
    try:
        with open(HONEYPOT_FILE_PATH, "r") as f:
            _ = f.read()
        print("    File read complete (alert should fire)")
    except Exception:
        pass
    time.sleep(1.5)   # let file monitor detect it

    # Summary
    stop_event.set()
    server.server_close()
    try:
        os.remove(HONEYPOT_FILE_PATH)
    except Exception:
        pass

    print(f"\n{'═'*60}")
    print(f"  DEMO COMPLETE — {len(alerts)} alerts raised")
    print(f"{'═'*60}\n")
    for a in alerts:
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(a["severity"], "⚪")
        print(f"  {sev_icon} [{a['severity']:8s}] {a['trap']:25s} | {a['source']} | {a['detail'][:60]}")
    print(f"\nFull alert log: {ALERT_LOG}\n")


if __name__ == "__main__":
    if "--demo" in sys.argv:
        run_demo()
    elif "--serve" in sys.argv:
        run_honeypot()
    else:
        run_demo()
