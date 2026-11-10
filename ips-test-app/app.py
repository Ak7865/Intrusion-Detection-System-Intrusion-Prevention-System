from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone
from pathlib import Path
import json

HOST = "192.168.56.129"
PORT = 3000

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "logs" / "requests.jsonl"

# Synthetic records for controlled lab testing.
RECORDS = [
    {
        "record_id": i,
        "asset_tag": f"LAB-DEVICE-{i:04d}",
        "status": "active" if i % 2 == 0 else "inactive",
        "category": "test-device"
    }
    for i in range(1, 251)
]


class TestApplication(BaseHTTPRequestHandler):

    def log_event(self, method, path, status):
        event = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "source_ip": self.client_address[0],
            "source_port": self.client_address[1],
            "method": method,
            "path": path,
            "status": status,
            "user_agent": self.headers.get("User-Agent", "")
        }

        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    def respond_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/health":
            self.log_event("GET", path, 200)
            return self.respond_json(200, {
                "status": "healthy",
                "application": "IPS Lab Test Application"
            })

        if path == "/api/records":
            params = parse_qs(parsed.query)

            try:
                page = int(params.get("page", ["1"])[0])
                limit = int(params.get("limit", ["100"])[0])

                if page < 1 or limit < 1 or limit > 100:
                    raise ValueError

            except (ValueError, TypeError):
                self.log_event("GET", path, 400)
                return self.respond_json(400, {
                    "message": "Invalid pagination parameters"
                })

            start = (page - 1) * limit
            end = start + limit

            records = RECORDS[start:end]

            self.log_event("GET", path, 200)

            return self.respond_json(200, {
                "data": records,
                "page": page,
                "limit": limit,
                "total": len(RECORDS)
            })

        if path in ("/", "/robots.txt", "/api/Challenges"):
            self.log_event("GET", path, 200)
            return self.respond_json(200, {
                "message": "Controlled IPS test application"
            })

        if path == "/rest/products/search":
            self.log_event("GET", path, 200)
            return self.respond_json(200, {
                "message": "Product search test endpoint"
            })

        self.log_event("GET", path, 404)
        self.respond_json(404, {"message": "Not found"})

    def do_POST(self):
        path = urlparse(self.path).path

        length = int(self.headers.get("Content-Length", 0))

        if length > 16384:
            self.log_event("POST", path, 413)
            return self.respond_json(413, {
                "message": "Request too large"
            })

        raw = self.rfile.read(length)

        if path == "/rest/user/login":
            try:
                payload = json.loads(raw.decode("utf-8"))

                if not isinstance(payload, dict):
                    raise ValueError("Expected JSON object")

            except (ValueError, UnicodeDecodeError):
                self.log_event("POST", path, 400)
                return self.respond_json(400, {
                    "message": "Invalid JSON"
                })

            self.log_event("POST", path, 401)
            return self.respond_json(401, {
                "message": "Test login rejected"
            })

        self.log_event("POST", path, 404)
        self.respond_json(404, {"message": "Not found"})

    def log_message(self, fmt, *args):
        print(
            f"[HTTP] {self.client_address[0]} - {fmt % args}"
        )


if __name__ == "__main__":
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    server = ThreadingHTTPServer(
        (HOST, PORT),
        TestApplication
    )

    print(
        f"IPS test application listening on "
        f"http://{HOST}:{PORT}"
    )
    print(f"Request metadata: {LOG_FILE}")

    server.serve_forever()