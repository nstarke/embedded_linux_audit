#!/usr/bin/env python3
# SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
"""
ghidra_bridge.py — TCP-to-WebSocket bridge for Ghidra's GDB debugger.

Opens a TCP server on localhost and relays raw GDB RSP bytes between
the first connecting client and a WebSocket endpoint.  Ghidra (or any
GDB-compatible debugger) can connect to localhost:<port> as a plain
GDB remote target without needing WebSocket support.

Usage:

  python3 tools/ghidra_bridge.py \\
      --url wss://HOST/gdb/out/<32-hex-key> \\
      [--port 9999] [--insecure] [--token TOKEN]

Then in Ghidra's Debugger:
  Connect → gdb → "target remote localhost:9999"

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


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                url: str, ssl_ctx, headers: dict) -> None:
    """Bidirectionally relay between a TCP client and a WebSocket."""
    peer = writer.get_extra_info('peername')
    print(f'[ghidra_bridge] client connected from {peer[0]}:{peer[1]}')

    try:
        async with websockets.connect(url, ssl=ssl_ctx,
                                      additional_headers=headers) as ws:
            async def tcp_to_ws() -> None:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    await ws.send(data)

            async def ws_to_tcp() -> None:
                async for msg in ws:
                    if isinstance(msg, (bytes, bytearray)):
                        writer.write(msg)
                    else:
                        writer.write(msg.encode('latin-1'))
                    await writer.drain()

            done, pending = await asyncio.wait(
                [asyncio.ensure_future(tcp_to_ws()),
                 asyncio.ensure_future(ws_to_tcp())],
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
            print('[ghidra_bridge] agent disconnected — the gdbserver tunnel '
                  'on the device closed the session.')
        elif close_code is not None and close_code not in (1000, 1001):
            print(f'[ghidra_bridge] websocket closed '
                  f'(code={close_code}'
                  f'{": " + close_reason if close_reason else ""})')
    except Exception as exc:
        print(f'[ghidra_bridge] error: {exc}')
    finally:
        writer.close()
        print(f'[ghidra_bridge] client {peer[0]}:{peer[1]} disconnected')


async def serve(port: int, url: str, ssl_ctx, headers: dict) -> None:
    async def on_connect(reader, writer):
        await relay(reader, writer, url, ssl_ctx, headers)

    server = await asyncio.start_server(on_connect, '127.0.0.1', port)
    print(f'[ghidra_bridge] listening on 127.0.0.1:{port}')
    print(f'[ghidra_bridge] websocket target: {url}')
    print(f'[ghidra_bridge] waiting for Ghidra to connect ...')
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(
        description='TCP-to-WebSocket bridge for Ghidra GDB remote debugging')
    parser.add_argument('--url', required=True,
                        help='wss://HOST/gdb/out/<32-hex-key>')
    parser.add_argument('--port', type=int, default=9999,
                        help='Local TCP port to listen on (default: 9999)')
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
        asyncio.run(serve(args.port, args.url, ssl_ctx, headers))
    except KeyboardInterrupt:
        print('\n[ghidra_bridge] shutting down')


if __name__ == '__main__':
    main()
