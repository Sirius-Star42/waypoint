import os, socket, sys, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

db = urllib.parse.urlparse(os.environ["DATABASE_URL"])
try:
    socket.create_connection((db.hostname, db.port or 5432), timeout=3).close()
except OSError as e:
    print(f"FATAL: could not connect to database at {db.hostname}:{db.port}: {e}", file=sys.stderr, flush=True)
    sys.exit(1)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok\n")

print("listening on :8080", flush=True)
HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
