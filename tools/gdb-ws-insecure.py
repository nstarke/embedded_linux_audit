#!/usr/bin/env python3
# SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
"""
gdb-ws-insecure.py — GDB Python extension for WebSocket RSP targets.

Load this from your .gdbinit or interactively:

  (gdb) source /path/to/tools/gdb-ws-insecure.py

It registers two GDB commands:

  wss-remote wss://HOST/gdb/out/<32-hex-key>
      Connect using native GDB WebSocket transport (GDB 14+).
      TLS verification is performed; use --insecure to skip.

  wss-remote --insecure wss://HOST/gdb/out/<32-hex-key>
      Connect via the gdb-ws-proxy.py stdin/stdout pipe with TLS
      verification disabled.  Works with any GDB version that supports
      "target remote | command".

The hex key must be 32 lowercase hex characters matching the key used by
the embedded agent's "linux gdbserver tunnel [--insecure] <PID> <URL>"
command (where the agent URL is /gdb/in/<key> and GDB's URL is
/gdb/out/<key>).

Bearer token: set the ELA_API_KEY environment variable, or pass
--token TOKEN on the command line.

Example workflow:
  # On the device (via ela shell):
  linux gdbserver tunnel --insecure 1234 wss://ela.host/gdb/in/aabbccddeeff00112233445566778899

  # On the analyst workstation:
  gdb-multiarch ./firmware.elf
  (gdb) source tools/gdb-ws-insecure.py
  (gdb) wss-remote --insecure wss://ela.host/gdb/out/aabbccddeeff00112233445566778899
"""

import os
import re
import shlex
import sys

try:
    import gdb  # only available when running inside GDB
except ImportError:
    print('This script must be sourced from inside gdb-multiarch.')
    sys.exit(1)

_HEX32_RE = re.compile(r'^[0-9a-f]{32}$')
_PROXY_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              'gdb-ws-proxy.py')


def _parse_args(arg: str):
    """Return (insecure: bool, url: str, token: str|None)."""
    parts = shlex.split(arg)
    insecure = False
    token = None
    url = None
    i = 0
    while i < len(parts):
        if parts[i] == '--insecure':
            insecure = True
        elif parts[i] == '--token' and i + 1 < len(parts):
            token = parts[i + 1]
            i += 1
        elif parts[i].startswith('wss://') or parts[i].startswith('ws://'):
            url = parts[i]
        i += 1
    return insecure, url, token


def _validate_url(url: str) -> bool:
    """Check that the URL ends with /gdb/out/<32 hex chars>."""
    m = re.search(r'/gdb/out/([0-9a-f]{32})$', url)
    return bool(m)


class WssRemote(gdb.Command):
    """Connect gdb-multiarch to a WebSocket RSP target.

    Usage:
      wss-remote [--insecure] [--token TOKEN] wss://HOST/gdb/out/<32-hex-key>

    Without --insecure, uses GDB's native WebSocket transport (requires
    GDB 14+ built with WebSocket support).

    With --insecure, falls back to the gdb-ws-proxy.py stdin/stdout pipe so
    that TLS certificate verification can be disabled.  This works with any
    GDB version that supports "target remote | command".
    """

    def __init__(self):
        super().__init__('wss-remote', gdb.COMMAND_RUNNING)

    def invoke(self, arg, from_tty):
        insecure, url, token = _parse_args(arg)

        if not url:
            gdb.write('wss-remote: missing URL\n', gdb.STDERR)
            gdb.write('Usage: wss-remote [--insecure] [--token TOKEN] '
                      'wss://HOST/gdb/out/<32-hex-key>\n', gdb.STDERR)
            return

        if not _validate_url(url):
            gdb.write(f'wss-remote: URL must end with /gdb/out/<32 hex chars>: {url}\n',
                      gdb.STDERR)
            return

        if not token:
            token = os.environ.get('ELA_API_KEY', '')

        if insecure:
            # Pipe approach: works regardless of GDB WebSocket support level.
            cmd_parts = ['python3', shlex.quote(_PROXY_SCRIPT),
                         '--url', shlex.quote(url), '--insecure']
            if token:
                cmd_parts += ['--token', shlex.quote(token)]
            pipe_cmd = ' '.join(cmd_parts)
            try:
                gdb.execute(f'target remote | {pipe_cmd}')
            except gdb.error as e:
                msg = str(e)
                gdb.write(f'wss-remote: {msg}\n', gdb.STDERR)
                lmsg = msg.lower()
                if 'reset by peer' in lmsg or 'disconnect' in lmsg or 'eof' in lmsg:
                    gdb.write(
                        'Tip: the bridge closed the connection — check that:\n'
                        '  1. "linux gdbserver tunnel <PID> <WSS_URL>" is running '
                        'on the device\n'
                        '  2. ptrace succeeded (no "Operation not permitted" error)\n'
                        '  3. The session key in the URL matches what the agent '
                        'printed\n',
                        gdb.STDERR,
                    )
        else:
            # Native GDB WebSocket transport (GDB 14+).
            # If your GDB does not support wss:// natively, use --insecure
            # (which uses the pipe fallback) or upgrade to GDB 14+.
            if token:
                # Inject Authorization header via environment so GDB picks it up.
                os.environ['GDB_WS_AUTH'] = f'Bearer {token}'
            try:
                gdb.execute(f'target remote {url}')
            except gdb.error as e:
                msg = str(e)
                gdb.write(f'wss-remote: {msg}\n', gdb.STDERR)
                lmsg = msg.lower()
                if 'reset by peer' in lmsg or 'disconnect' in lmsg or 'eof' in lmsg:
                    gdb.write(
                        'Tip: the bridge closed the connection — check that:\n'
                        '  1. "linux gdbserver tunnel <PID> <WSS_URL>" is running '
                        'on the device\n'
                        '  2. ptrace succeeded (no "Operation not permitted" error)\n'
                        '  3. The session key in the URL matches what the agent '
                        'printed\n',
                        gdb.STDERR,
                    )


WssRemote()
