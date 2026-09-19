"""Regression tests for dashboard_server.py.

Every case here corresponds to a verified exposure in the previous version.
They are written as a runnable script rather than a pytest suite so they need
no dependencies:

    python3 test_dashboard_security.py

The exposures, all confirmed against the old server before it was replaced:

  GET /native_edge_queue.db  -> 200, 1,011,712 bytes  (held raw `sk-` keys)
  GET /policy.yaml           -> 200, the live detection rules
  GET /src/signing.rs        -> 200, source
  GET /api/events            -> 200, no authentication of any kind
  POST /api/events           -> 200 {"status":"synced"}, unauthenticated
  bind address               -> 0.0.0.0, i.e. reachable off-box

A dashboard that renders a security product's audit trail is itself a piece of
security surface, and this is the file that keeps it that way.
"""

import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "dashboard_server.py")
TOKEN = "test-token-do-not-ship"
DB = os.path.join(HERE, "_dashboard_test_audit.db")

failures = []


def check(cond, msg):
    if cond:
        print(f"  PASS  {msg}")
    else:
        print(f"  FAIL  {msg}")
        failures.append(msg)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def seed_db():
    """An audit trail in the shape an OLDER build produced: a raw secret in the
    `pattern` column. Current builds write only category placeholders, but the
    dashboard must be safe when pointed at a pre-existing database."""
    if os.path.exists(DB):
        os.remove(DB)
    conn = sqlite3.connect(DB)
    conn.executescript(
        """
        CREATE TABLE audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT, code INTEGER, timestamp INTEGER);
        """
    )
    conn.executemany(
        "INSERT INTO audit_logs (pattern, code, timestamp) VALUES (?, ?, ?)",
        [
            ("sk-live-SUPERSECRET0123456789", 10042, 1758153600),
            ("corp_token_xyz", 103, 1758153601),
            ("CREDIT_CARD_NUM", 301, 1758153602),
            ("ENGINE_PANIC", 500, 1758153603),
            ("POLICY_RULE_7", 20007, 1758153604),
        ],
    )
    conn.commit()
    conn.close()


def get(url, token=None, method="GET", data=None):
    req = urllib.request.Request(url, method=method, data=data)
    if token:
        req.add_header("X-Dashboard-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # noqa: BLE001 - probing a server that may not be up yet
        return None, str(e).encode()


def main():
    seed_db()
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    env = dict(
        os.environ,
        PORT=str(port),
        EDGEGUARD_AUDIT_DB=DB,
        EDGEGUARD_DASHBOARD_TOKEN=TOKEN,
    )
    proc = subprocess.Popen(
        [sys.executable, SERVER],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(50):
            if get(f"{base}/healthz", TOKEN)[0] is not None:
                break
            time.sleep(0.1)

        print("\n[1] no file is served from the working directory")
        for path in (
            "native_edge_queue.db",
            "policy.yaml",
            "src/signing.rs",
            "Cargo.toml",
            "dashboard_server.py",
            ".gitignore",
            "../../../etc/passwd",
        ):
            status, _ = get(f"{base}/{path}?t={TOKEN}", TOKEN)
            check(status == 404, f"GET /{path} -> {status} (want 404)")

        print("\n[2] every route requires the token")
        for path in ("/", "/api/events", "/healthz"):
            check(get(f"{base}{path}")[0] == 401, f"{path} without a token -> 401")
            check(
                get(f"{base}{path}", "wrong-token")[0] == 401, f"{path} with a wrong token -> 401"
            )
            check(get(f"{base}{path}", TOKEN)[0] == 200, f"{path} with the right token -> 200")

        print("\n[3] the write endpoint is gone")
        status, _ = get(f"{base}/api/events", method="POST", data=b"x=1")
        check(status == 405, f"unauthenticated POST /api/events -> {status} (want 405)")
        status, _ = get(f"{base}/api/events", TOKEN, method="POST", data=b"x=1")
        check(status == 405, f"authenticated POST /api/events -> {status} (want 405)")

        print("\n[4] legacy raw values are redacted on read")
        status, body = get(f"{base}/api/events", TOKEN)
        text = body.decode()
        check(status == 200, "authenticated read succeeds")
        check("SUPERSECRET" not in text, "raw sk- key is not in the response")
        check("corp_token_xyz" not in text, "raw custom-pattern value is not in the response")
        check(
            "REDACTED_LEGACY_VALUE" in text, "unrecognised values are replaced with a placeholder"
        )
        check("CREDIT_CARD_NUM" in text, "known placeholders still render")
        check("POLICY_RULE_7" in text, "structured rule labels still render")

        print("\n[5] codes are classified the way the SIEM contract says")
        events = {e["code"]: e["code_class"] for e in json.loads(text)}
        check(events.get(500) == "engine_fault", "500 classifies as engine_fault, not a detection")
        check(events.get(10042) == "tenant_rule", "10042 classifies as tenant_rule")
        check(events.get(20007) == "policy_rule", "20007 classifies as policy_rule")
        check(events.get(301) == "builtin", "301 classifies as builtin")

        print("\n[6] the audit database is opened read-only")
        # A read-only handle means the dashboard cannot alter the evidence it
        # renders, even through a bug elsewhere in the process.
        with open(SERVER) as fh:
            src = fh.read()
        check("mode=ro" in src, "sqlite connection uses mode=ro")
        check(
            "SimpleHTTPRequestHandler" not in src.split('"""', 2)[2],
            "SimpleHTTPRequestHandler is not used outside the docstring",
        )
        check('"0.0.0.0"' not in src and "'0.0.0.0'" not in src, "no hardcoded 0.0.0.0 bind")
        check('EDGEGUARD_DASHBOARD_BIND", "127.0.0.1"' in src, "default bind is loopback")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(DB):
            os.remove(DB)

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("All dashboard security checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
