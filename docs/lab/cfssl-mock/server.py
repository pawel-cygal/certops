import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/v1/cfssl/health":
            self._json({"success": True, "result": {"healthy": True}})
            return
        self.send_error(404)

    def do_POST(self):
        if self.path == "/api/v1/cfssl/info":
            cert = Path("/certs/root.pem").read_text()
            self._json({"success": True, "result": {"certificate": cert}})
            return
        self.send_error(404)

    def log_message(self, fmt, *args):
        return

    def _json(self, payload):
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


HTTPServer(("0.0.0.0", 8888), Handler).serve_forever()
