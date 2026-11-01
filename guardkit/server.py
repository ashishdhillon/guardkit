"""Minimal zero-dependency HTTP service.
POST /check  {"text": "...", "stage": "input"|"output"}  ->  Result JSON
Intended for local/dev use behind your own gateway; add auth and TLS before exposing it."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 1_000_000


def make_handler(pipeline):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path != "/check":
                return self._send(404, {"error": "not found"})
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return self._send(413, {"error": "body too large"})
            try:
                req = json.loads(self.rfile.read(n) or b"{}")
                text, stage = req["text"], req.get("stage", "input")
                if not isinstance(text, str) or stage not in ("input", "output"):
                    raise ValueError
            except (ValueError, KeyError):
                return self._send(400, {"error": "expected {text: str, stage: input|output}"})
            fn = pipeline.check_input if stage == "input" else pipeline.check_output
            self._send(200, fn(text).to_dict())

        def log_message(self, *a):  # quiet
            pass
    return Handler


def serve(pipeline, host="127.0.0.1", port=8080):
    ThreadingHTTPServer((host, port), make_handler(pipeline)).serve_forever()
