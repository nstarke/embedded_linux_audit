#!/usr/bin/env python3
# SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
"""
gdb-ws-proxy.py — stdin/stdout bridge between GDB's RSP and a WebSocket.

This script is meant for use with GDB's "target remote | ..." syntax:

  (gdb) target remote | python3 tools/gdb-ws-proxy.py \\
            --url wss://HOST/gdb/out/<32-hex-key> [--insecure] [--token TOKEN]

GDB writes RSP bytes to stdin and reads them from stdout; this script
forwards those bytes as binary WebSocket frames to the /gdb/out/<key>
endpoint on the ela-gdb bridge service.

For a native WebSocket remote without the pipe syntax, source the companion
GDB Python extension instead:

  (gdb) source tools/gdb-ws-insecure.py
  (gdb) wss-remote [--insecure] wss://HOST/gdb/out/<32-hex-key>

Dependencies:
  pip install websockets
"""

import argparse
import asyncio
import os
import ssl
import sys

try:
    import websockets
except ImportError:
    sys.exit('error: websockets package required: pip install websockets')


async def bridge(url: str, ssl_ctx, headers: dict) -> None:
    async with websockets.connect(url, ssl=ssl_ctx,
                                  additional_headers=headers) as ws:
        loop = asyncio.get_running_loop()

        async def stdin_to_ws() -> None:
            while True:
                data = await loop.run_in_executor(None, sys.stdin.buffer.read, 4096)
                if not data:
                    break
                await ws.send(data)

        async def ws_to_stdout() -> None:
            async for msg in ws:
                if isinstance(msg, (bytes, bytearray)):
                    sys.stdout.buffer.write(msg)
                else:
                    sys.stdout.buffer.write(msg.encode('latin-1'))
                sys.stdout.buffer.flush()

        done, pending = await asyncio.wait(
            [asyncio.ensure_future(stdin_to_ws()),
             asyncio.ensure_future(ws_to_stdout())],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    close_code = getattr(ws, 'close_code', None)
    close_reason = getattr(ws, 'close_reason', '') or ''
    if close_code == 4001:
        sys.stderr.write(
            'wss-remote: agent disconnected — the gdbserver tunnel on the '
            'device closed the session.\n'
            '  Check that "linux gdbserver tunnel <PID> <WSS_URL>" is '
            'still running and that ptrace succeeded.\n'
        )
    elif close_code is not None and close_code not in (1000, 1001):
        sys.stderr.write(
            f'wss-remote: connection closed by server '
            f'(code={close_code}'
            f'{": " + close_reason if close_reason else ""})\n'
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Pipe stdin/stdout GDB RSP to a WebSocket endpoint')
    parser.add_argument('--url', required=True,
                        help='wss://HOST/gdb/out/<32-hex-key>')
    parser.add_argument('--insecure', action='store_true',
                        help='Disable TLS certificate verification')
    parser.add_argument('--token',
                        help='Bearer token for Authorization header')
    args = parser.parse_args()

    ssl_ctx = None
    if args.url.startswith('wss://'):
        ssl_ctx = ssl.create_default_context()
        if args.insecure:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

    headers = {}
    if args.token:
        headers['Authorization'] = f'Bearer {args.token}'
    elif os.environ.get('ELA_API_KEY'):
        headers['Authorization'] = f'Bearer {os.environ["ELA_API_KEY"]}'

    try:
        asyncio.run(bridge(args.url, ssl_ctx, headers))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
