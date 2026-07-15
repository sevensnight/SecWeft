from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE = os.getenv("LAB_MODE", "patched")
MARKER = "VULNLAB_SYNTHETIC_FINDING" if MODE == "vulnerable" else "PATCH_APPLIED"


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnLabSynthetic/1.0"

    def do_HEAD(self) -> None:
        self._respond(include_body=False)

    def do_GET(self) -> None:
        self._respond(include_body=True)

    def _respond(self, include_body: bool) -> None:
        body = json.dumps({"fixture": "synthetic", "mode": MODE, "marker": MARKER}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Lab-Mode", MODE)
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
