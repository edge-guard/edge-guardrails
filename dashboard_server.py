from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import sqlite3

PORT = 8080
DB_PATH = "native_edge_queue.db"

HTML_PAGE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Edge-Native SDK Dashboard</title>
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
        .badge-passed { background: #22c55e; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Edge-Native SDK Dashboard</h1>
        <p>Local Guardrails & Event Queue Monitor</p>
        <div class="card">
            <h3 style="margin: 0;">Captured Events</h3>
            <table>
                <thead>
                    <tr><th>ID</th><th>Prompt</th><th>Result</th><th>Status</th></tr>
                </thead>
                <tbody id="table-body">
                    <tr><td colspan="4" style="text-align:center; color:#94a3b8;">Loading events...</td></tr>
                </tbody>
            </table>
        </div>
    </div>
    <script>
        async function loadData() {
            try {
                const res = await fetch('/api/events');
                const data = await res.json();
                const tbody = document.getElementById('table-body');
                if (!data || data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#94a3b8;">No events recorded</td></tr>';
                    return;
                }
                tbody.innerHTML = data.map(e => `
                    <tr>
                        <td>#${e.id}</td>
                        <td>${e.prompt}</td>
                        <td>${e.result}</td>
                        <td><span class="badge ${e.status === 'REJECTED' ? 'badge-rejected' : 'badge-passed'}">${e.status}</span></td>
                    </tr>
                `).join('');
            } catch (err) {
                console.error(err);
            }
        }
        loadData();
        setInterval(loadData, 2000);
    </script>
</body>
</html>"""

class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode('utf-8'))
        elif self.path == '/api/events':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("SELECT id, prompt, result, status FROM events ORDER BY id DESC LIMIT 20")
                rows = c.fetchall()
                conn.close()
                events = [{"id": r[0], "prompt": r[1], "result": r[2], "status": r[3]} for r in rows]
                self.wfile.write(json.dumps(events).encode('utf-8'))
            except Exception:
                self.wfile.write(json.dumps([]).encode('utf-8'))
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == '/api/events':
            length = int(self.headers.get('content-length', 0))
            _ = self.rfile.read(length)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"synced"}')

print(f"🚀 Dashboard running on http://localhost:{PORT}")
HTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
