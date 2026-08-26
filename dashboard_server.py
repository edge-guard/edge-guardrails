from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sqlite3

PORT = 8080
DB_PATH = "native_edge_queue.db"

class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Edge-Native SDK Live Dashboard</title>
                <meta http-equiv="refresh" content="2">
                <style>
                    body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; padding: 24px; }
                    .card { background: #1e293b; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }
                    h1 { color: #38bdf8; margin-bottom: 8px; }
                    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
                    th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid #334155; }
                    th { background: #0f172a; color: #94a3b8; }
                    .badge { padding: 4px 8px; border-radius: 6px; font-weight: 600; font-size: 12px; }
                    .badge-rejected { background: #ef4444; color: #fff; }
                    .badge-passed { background: #22c55e; color: #fff; }
                    .badge-synced { background: #3b82f6; color: #fff; }
                </style>
            </head>
            <body>
                <h1>🛡️ Edge-Native SDK Dashboard</h1>
                <p style="color: #94a3b8;">Local Inference Guardrails & Event Sync Monitor</p>
                <div class="card">
                    <h2>Live Ingested Events</h2>
                    <div id="content">Loading events from SQLite queue...</div>
                </div>
            </body>
            </html>
            """
            self.wfirite(html.encode('utf-8'))
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
            except Exception as e:
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))

    def do_POST(self):
        if self.path == '/api/events':
            length = int(self.headers.get('content-length', 0))
            data = self.rfile.read(length)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"synced"}')

print(f"🚀 Dashboard Server running on http://localhost:{PORT}")
HTTPServer(('0.0.0.0', PORT), DashboardHandler).serve_forever()
