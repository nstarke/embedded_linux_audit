#!/usr/bin/env python3

import argparse
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("post", "file"), required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--path-out", required=True)
    parser.add_argument("--type-out", required=True)
    parser.add_argument("--body-out", required=True)
    parser.add_argument("--payload")
    args = parser.parse_args()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _fmt: str, *_args) -> None:
            return

        def do_POST(self) -> None:
            if args.mode != "post":
                self.send_error(405)
                return

            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)

            with open(args.path_out, "w", encoding="utf-8") as fh:
                fh.write(self.path)
            with open(args.type_out, "w", encoding="utf-8") as fh:
                fh.write(self.headers.get("Content-Type", ""))
            with open(args.body_out, "wb") as fh:
                fh.write(body)

            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"ok")
            self.wfile.flush()
            self.server.should_stop = True

        def do_GET(self) -> None:
            if args.mode != "file" or not args.payload:
                self.send_error(405)
                return

            with open(args.path_out, "w", encoding="utf-8") as fh:
                fh.write(self.path)
            with open(args.type_out, "w", encoding="utf-8") as fh:
                fh.write(self.headers.get("Accept", ""))

            with open(args.payload, "rb") as fh:
                body = fh.read()
            with open(args.body_out, "wb") as fh:
                fh.write(body)

            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
            self.server.should_stop = True

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.should_stop = False

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"ready:{server.server_address[1]}", flush=True)

    while not server.should_stop:
      server.handle_request()

    server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
