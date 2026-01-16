# python-real-time-service/http_ingest.py
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from typing import Any, Dict, List
import queue

ACCEPT_PATHS = {"/predict", "/ingest"}  # cicflowmeter README hay dùng /predict

def _as_rows(payload: Any) -> List[Dict[str, Any]]:
    # Chấp nhận nhiều kiểu payload để “auto chịu”
    if isinstance(payload, dict):
        # có thể tool gửi {"flows":[...]} hoặc {"data":[...]}
        for k in ("flows", "data", "records"):
            v = payload.get(k)
            if isinstance(v, list) and all(isinstance(x, dict) for x in v):
                return v
        return [payload]
    if isinstance(payload, list) and all(isinstance(x, dict) for x in payload):
        return payload
    return []

class Handler(BaseHTTPRequestHandler):
    q: "queue.Queue[Dict[str, Any]]" = None  # type: ignore

    def log_message(self, fmt: str, *args) -> None:
        # im lặng cho đỡ spam
        return

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path not in ACCEPT_PATHS:
            self.send_response(404)
            self.end_headers()
            return

        try:
            n = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(n) if n > 0 else b""
            payload = json.loads(raw.decode("utf-8") or "null")
            rows = _as_rows(payload)

            pushed = 0
            for row in rows:
                try:
                    self.q.put(row, timeout=0.2)
                    pushed += 1
                except Exception:
                    pass

            # debug nhẹ: show keys của record đầu tiên
            if os.getenv("INGEST_DEBUG", "false").lower() == "true" and rows:
                print(f"[INGEST] sample keys: {list(rows[0].keys())[:15]}...")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True, "count": pushed}).encode("utf-8"))
        except Exception as e:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": False, "error": str(e)[:200]}).encode("utf-8"))

def start_http_ingest(q: "queue.Queue[Dict[str, Any]]") -> None:
    host = os.getenv("INGEST_HTTP_HOST", "0.0.0.0")
    port = int(os.getenv("INGEST_HTTP_PORT", "8080"))
    Handler.q = q
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"[INGEST] Listening on http://{host}:{port} (paths: /predict, /ingest)")
    httpd.serve_forever()
