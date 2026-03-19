#!/usr/bin/env python3

import argparse
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path-out", required=True)
    parser.add_argument("--type-out", required=True)
    parser.add_argument("--body-out", required=True)
    parser.add_argument("--auth-out")
    parser.add_argument("--status", type=int, default=200)
    args = parser.parse_args()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _fmt: str, *_args) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)

            with open(args.path_out, "w", encoding="utf-8") as fh:
                fh.write(self.path)
            with open(args.type_out, "w", encoding="utf-8") as fh:
                fh.write(self.headers.get("Content-Type", ""))
            with open(args.body_out, "wb") as fh:
                fh.write(body)
            if args.auth_out:
                with open(args.auth_out, "w", encoding="utf-8") as fh:
                    fh.write(self.headers.get("Authorization", ""))

            self.send_response(args.status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"ok")
            self.wfile.flush()
            self.server.should_stop = True

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.should_stop = False
    print(f"ready:{server.server_address[1]}", flush=True)

    while not server.should_stop:
        server.handle_request()

    server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
