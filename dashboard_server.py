"""Local audit-trail dashboard for the EdgeGuard SDK.

SECURITY NOTES - read before changing anything here
===================================================

This process reads a security product's audit trail. Four properties are
load-bearing, and each replaced a specific defect in the previous version:

1. IT SERVES NO FILES FROM DISK.
   The previous version subclassed `SimpleHTTPRequestHandler` and ended its
   router with `else: super().do_GET()`, which handed every unmatched path to
   the stdlib's static file server rooted at the working directory. Verified
   reachable, unauthenticated, from that fallback:

       GET /native_edge_queue.db  -> 200, 1,011,712 bytes (contained raw keys)
       GET /policy.yaml           -> 200, the live detection rules
       GET /src/signing.rs        -> 200, source

   The audit database is the worst of those, but `policy.yaml` is close behind:
   handing an attacker the exact rule set tells them precisely what to write
   around. This file now derives from `BaseHTTPRequestHandler`, which has no
   filesystem behaviour at all, and every unmatched path is a 404.

2. IT BINDS LOOPBACK BY DEFAULT.
   The previous version bound `0.0.0.0`, so the exposure above was reachable
   from the network rather than only from the machine. Binding elsewhere now
   requires setting EDGEGUARD_DASHBOARD_BIND explicitly and prints a warning.

3. IT REQUIRES A TOKEN.
   There was no authentication of any kind. A token is generated at startup
   (or taken from EDGEGUARD_DASHBOARD_TOKEN) and required on every route,
   compared with `hmac.compare_digest`.

4. IT REDACTS ON READ.
   Current engine builds persist only category placeholders. Older trails did
   not: the database found in this tree held two raw `sk-` keys and a custom
   pattern that was itself a secret. A dashboard pointed at a pre-existing
   database must not put those on a web page, so anything that does not look
   like a known placeholder is redacted here as well. Defence in depth: the
   engine masks on write, this masks on read.

The database is also opened read-only, so the dashboard cannot alter the
evidence it exists to display.

Usage:
    python3 dashboard_server.py
    # then open the URL it prints (it carries the token)
"""

import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

PORT = int(os.environ.get("PORT", "8080"))
DB_PATH = os.environ.get("EDGEGUARD_AUDIT_DB", "native_edge_queue.db")
BIND = os.environ.get("EDGEGUARD_DASHBOARD_BIND", "127.0.0.1")
TOKEN = os.environ.get("EDGEGUARD_DASHBOARD_TOKEN") or secrets.token_urlsafe(32)
MAX_ROWS = 200

# Labels the engine is known to write. Anything else is treated as untrusted
# content from an older build and redacted rather than rendered.
SAFE_LABELS = frozenset(
    {
        "CREDIT_CARD_NUM",
        "AWS_KEY_REDACTED",
        "EMAIL_ADDRESS_REDACTED",
        "IL_ID_NUM",
        "OVER_2MB",
        "ENGINE_PANIC",
        "BIDI_OVERRIDE_DETECTED",
        "CUSTOM_PATTERN_MATCH",
        "OVER_LIMIT",
        "TIER2_SHED",
        "TIER2_UNAVAILABLE",
        "TIER2_FAILED",
        "ALLOWLISTED",
        "SAFE",
    }
)
SAFE_LABEL_RE = re.compile(
    r"^(?:POLICY_RULE_\d+|TENANT_RULE_\d+|GRAPH_RULE_\d+|DETERMINISTIC_\d+"
    r"|SEMANTIC_\d+|OBFUSCATION_[0-9A-F]{4})$"
)


def redact(pattern):
    """Return a value safe to render, or a placeholder describing what it was.

    Deliberately allow-list based. A deny-list ("hide anything starting with
    sk-") only hides the secret shapes somebody thought of, and the whole
    reason this function exists is that the trail contained a shape nobody
    thought of at the time it was written.
    """
    if pattern is None:
        return "(none)"
    p = str(pattern)
    if p in SAFE_LABELS or SAFE_LABEL_RE.match(p):
        return p
    return f"[REDACTED_LEGACY_VALUE len={len(p)}]"


HTML_PAGE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>EdgeGuard Dashboard</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc; padding: 30px; margin: 0; }
        .container { max-width: 900px; margin: 0 auto; }
        h1 { color: #38bdf8; margin-bottom: 4px; }
        p { color: #94a3b8; margin-top: 0; }
        .card { background: #1e293b; border-radius: 8px; padding: 20px; border: 1px solid #334155; margin-top: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #334155; }
        th { background: #0f172a; color: #94a3b8; }
        .badge { padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }
        .badge-rejected { background: #ef4444; color: white; }
        .badge-fault { background: #f59e0b; color: #1f2937; }
        .redacted { color: #f59e0b; font-style: italic; }
        code { color: #7dd3fc; }
    </style>
</head>
<body>
    <div class="container">
        <h1>&#128737; EdgeGuard Dashboard</h1>
        <p>Local audit trail &mdash; loopback only, token required</p>
        <div class="card">
            <h3 style="margin: 0;">Recorded Violations</h3>
            <p style="margin: 4px 0 0; font-size: 13px;">
                Values are redacted twice: the engine writes only a category
                placeholder, and this page re-checks every value against that
                allow-list before rendering it. Anything unrecognised is shown
                as <span class="redacted">[REDACTED_LEGACY_VALUE]</span> rather
                than displayed.
            </p>
            <table>
                <thead>
                    <tr><th>ID</th><th>Label</th><th>Code</th><th>Class</th><th>Timestamp</th><th>Status</th></tr>
                </thead>
                <tbody id="table-body">
                    <tr><td colspan="6" style="text-align:center; color:#94a3b8;">Loading&hellip;</td></tr>
                </tbody>
            </table>
        </div>
    </div>
    <script>
        const TOKEN = new URLSearchParams(location.search).get('t') || '';
        function esc(s) { const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }
        async function loadData() {
            try {
                const res = await fetch('/api/events', { headers: { 'X-Dashboard-Token': TOKEN } });
                if (!res.ok) {
                    document.getElementById('table-body').innerHTML =
                        '<tr><td colspan="6" style="text-align:center; color:#ef4444;">' +
                        'Unauthorized &mdash; open the URL printed by the server.</td></tr>';
                    return;
                }
                const data = await res.json();
                const tbody = document.getElementById('table-body');
                if (!data || data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:#94a3b8;">No events recorded</td></tr>';
                    return;
                }
                tbody.innerHTML = data.map(e => `
                    <tr>
                        <td>#${esc(e.id)}</td>
                        <td class="${e.redacted ? 'redacted' : ''}">${esc(e.label)}</td>
                        <td><code>${esc(e.code)}</code></td>
                        <td>${esc(e.code_class)}</td>
                        <td>${esc(new Date(e.timestamp * 1000).toLocaleString())}</td>
                        <td><span class="badge ${e.code_class === 'engine_fault' ? 'badge-fault' : 'badge-rejected'}">
                            ${e.code_class === 'engine_fault' ? 'FAULT' : 'REJECTED'}</span></td>
                    </tr>`).join('');
            } catch (err) { console.error(err); }
        }
        loadData();
        setInterval(loadData, 2000);
    </script>
</body>
</html>"""


def classify(code):
    """Mirror of `edgeguard::codes::classify`, so the dashboard splits security
    detections from engine faults the same way a SIEM does."""
    try:
        code = int(code)
    except (TypeError, ValueError):
        return "unknown"
    if code == 0:
        return "safe"
    if code == 500:
        return "engine_fault"
    if code <= 999:
        return "builtin"
    if 10_000 < code <= 19_999:
        return "tenant_rule"
    if 20_000 < code <= 29_999:
        return "policy_rule"
    return "unknown"


class Handler(BaseHTTPRequestHandler):
    server_version = "EdgeGuardDashboard"
    sys_version = ""  # do not advertise the Python version

    # --- helpers ----------------------------------------------------------

    def _authorized(self):
        supplied = self.headers.get("X-Dashboard-Token", "")
        if not supplied:
            supplied = (parse_qs(urlparse(self.path).query).get("t") or [""])[0]
        # Constant time, so the token cannot be recovered a byte at a time.
        return hmac.compare_digest(supplied, TOKEN)

    def _send(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        # The page uses one inline script and talks only to itself.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _deny(self):
        self._send(401, b"unauthorized\n", "text/plain; charset=utf-8")

    def _not_found(self):
        self._send(404, b"not found\n", "text/plain; charset=utf-8")

    def log_message(self, fmt, *args):
        # The default logs the full request line, which would write the token
        # into the console and into anything capturing stdout.
        path = urlparse(self.path).path
        sys.stderr.write(f"[dashboard] {self.command} {path} {args[1] if len(args) > 1 else ''}\n")

    # --- routes -----------------------------------------------------------

    def do_GET(self):
        route = urlparse(self.path).path
        if not self._authorized():
            return self._deny()
        if route in ("/", "/index.html"):
            return self._send(200, HTML_PAGE.encode("utf-8"), "text/html; charset=utf-8")
        if route == "/api/events":
            return self._send(200, self._events(), "application/json")
        if route == "/healthz":
            return self._send(200, b'{"ok":true}', "application/json")
        # No fallback to a static file server. This is the whole point.
        return self._not_found()

    def do_POST(self):
        # The previous version accepted an unauthenticated POST to /api/events,
        # discarded the body, and replied {"status":"synced"} - an endpoint that
        # lied about having done something. Ingestion belongs to the control
        # plane, not to a local read-only viewer.
        self._send(405, b"read-only dashboard\n", "text/plain; charset=utf-8")

    def _events(self):
        try:
            # Read-only URI: the dashboard must not be able to alter the
            # evidence it renders, even through a bug.
            uri = (
                "file:"
                + os.path.abspath(DB_PATH).replace("?", "%3f").replace("#", "%23")
                + "?mode=ro"
            )
            conn = sqlite3.connect(uri, uri=True)
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT id, pattern, code, timestamp FROM audit_logs ORDER BY id DESC LIMIT ?",
                    (MAX_ROWS,),
                )
                rows = cur.fetchall()
            finally:
                conn.close()
        except Exception as exc:  # noqa: BLE001 - a missing or locked DB is normal
            # Deliberately broad. The dashboard must render *something* when
            # the audit database is absent, locked by the writer, or corrupt;
            # it must never take the page down because it could not read a
            # log. Reported to stderr and surfaced as an empty list.
            sys.stderr.write(f"[dashboard] cannot read audit log: {exc}\n")
            return b"[]"

        events = []
        for rid, pattern, code, ts in rows:
            shown = redact(pattern)
            events.append(
                {
                    "id": rid,
                    "label": shown,
                    "redacted": shown != (pattern if pattern is not None else "(none)"),
                    "code": code,
                    "code_class": classify(code),
                    "timestamp": ts,
                }
            )
        return json.dumps(events).encode("utf-8")


def main():
    if BIND not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"!! WARNING: binding {BIND}, not loopback.\n"
            f"!! This dashboard renders a security audit trail. Expose it only\n"
            f"!! behind an authenticating reverse proxy.",
            file=sys.stderr,
        )
    url = f"http://{BIND}:{PORT}/?t={TOKEN}"
    print("EdgeGuard dashboard")
    print(f"  bind      : {BIND}:{PORT}")
    print(f"  audit db  : {DB_PATH} (read-only)")
    print(f"  open      : {url}")
    if not os.environ.get("EDGEGUARD_DASHBOARD_TOKEN"):
        print("  token     : generated for this run; set EDGEGUARD_DASHBOARD_TOKEN to pin it")
    HTTPServer((BIND, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
