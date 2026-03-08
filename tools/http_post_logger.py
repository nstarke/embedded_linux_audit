#!/usr/bin/env python3
"""Simple HTTP POST receiver that appends request details and body to a log file."""

from __future__ import annotations

import argparse
import datetime as dt
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def build_handler(log_path: Path):
    class PostLoggerHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args):
            # Keep server console quiet; requests are written to log_path.
            return

        def do_POST(self):
            content_len = int(self.headers.get("Content-Length", "0"))
            payload = self.rfile.read(content_len)
            timestamp = dt.datetime.now(dt.timezone.utc).isoformat()

            with log_path.open("ab") as fp:
                fp.write(f"[{timestamp}] {self.client_address[0]} {self.path}\n".encode("utf-8"))
                for key, value in self.headers.items():
                    fp.write(f"{key}: {value}\n".encode("utf-8"))
                fp.write(b"\n")
                fp.write(payload)
                fp.write(b"\n\n---\n\n")

            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"ok\n")

    return PostLoggerHandler


def main() -> int:
    parser = argparse.ArgumentParser(description="Receive HTTP POST requests and log them to a file")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Bind port (default: 5000)")
    parser.add_argument("--log", default="post_requests.log", help="Log file path")
    args = parser.parse_args()

    log_path = Path(args.log)
    handler = build_handler(log_path)
    server = HTTPServer((args.host, args.port), handler)

    print(f"Listening on http://{args.host}:{args.port}/")
    print(f"Logging POST requests to: {log_path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
