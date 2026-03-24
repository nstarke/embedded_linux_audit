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

  wss-remote ws://HOST/gdb/out/<32-hex-key>
      Connect to a plain-text (non-TLS) WebSocket endpoint via the
      gdb-ws-proxy.py pipe.  GDB's native transport does not support
      ws://, so the proxy is used automatically regardless of --insecure.

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

# ---------------------------------------------------------------------------
# pwndbg installs internal hardware breakpoints on _dl_debug_state each time
# a shared library is loaded.  With a WebSocket-relayed target these cannot
# be satisfied — hardware debug registers only apply to the single ptrace-
# attached thread, and our stub advertises zero hardware breakpoint slots.
# GDB aborts the 'c' command ("Command aborted") when it cannot insert them.
#
# Two complementary interception layers:
#
#   1. Replace gdb.Breakpoint with a subclass that downgrades
#      BP_HARDWARE_BREAKPOINT to BP_BREAKPOINT at construction time.
#      Works for pwndbg code that uses the gdb.Breakpoint name via the
#      module attribute at call time (i.e. "gdb.Breakpoint(...)").
#
#   2. Register a breakpoint_created event handler that catches any
#      hardware breakpoint that slips through layer 1 — including those
#      created by pwndbg modules that did "from gdb import Breakpoint"
#      before this script was sourced, and C-level GDB internal breakpoints
#      that never go through the Python class at all.  The handler
#      immediately deletes the hardware breakpoint and recreates it as a
#      software breakpoint at the same location.
# ---------------------------------------------------------------------------
_orig_Breakpoint = gdb.Breakpoint


class _SoftwareOnlyBreakpoint(_orig_Breakpoint):
    """Silently converts hardware breakpoints to software breakpoints."""

    def __init__(self, spec, type=gdb.BP_BREAKPOINT, **kwargs):  # noqa: A002
        if type == gdb.BP_HARDWARE_BREAKPOINT:
            type = gdb.BP_BREAKPOINT
        super().__init__(spec, type, **kwargs)


try:
    gdb.Breakpoint = _SoftwareOnlyBreakpoint
except (AttributeError, TypeError):
    pass  # Older GDB that doesn't allow replacing the Breakpoint class


# Layer 2: breakpoint_created event handler — belt-and-suspenders for any
# hardware breakpoints that bypassed the class replacement above.
_bp_fix_active = False


def _on_bp_created(event):
    """Immediately convert hardware breakpoints to software on creation."""
    global _bp_fix_active
    if _bp_fix_active:
        return  # Prevent recursion when we create the software replacement
    bp = event.breakpoint
    if bp.type != gdb.BP_HARDWARE_BREAKPOINT:
        return
    loc = bp.location
    if not loc:
        return  # Cannot recreate a breakpoint with no location spec
    is_internal = bp.number < 0
    _bp_fix_active = True
    try:
        bp.delete()
        _orig_Breakpoint(loc, gdb.BP_BREAKPOINT, internal=is_internal)
    except Exception:
        pass
    finally:
        _bp_fix_active = False


if hasattr(gdb, 'events') and hasattr(gdb.events, 'breakpoint_created'):
    gdb.events.breakpoint_created.connect(_on_bp_created)


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
      wss-remote [--insecure] [--token TOKEN] (wss|ws)://HOST/gdb/out/<32-hex-key>

    wss:// without --insecure: uses GDB's native WebSocket transport (requires
    GDB 14+ built with WebSocket support).

    wss:// with --insecure, or any ws:// URL: uses the gdb-ws-proxy.py
    stdin/stdout pipe.  GDB's native transport only supports wss://, so ws://
    (plain-text) always goes through the proxy.  Works with any GDB version
    that supports "target remote | command".
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

        # GDB has no native WebSocket transport (ws:// or wss://) — confirmed
        # by examining GDB 17.1 source: parse_connection_spec() only recognises
        # the "tcp:", "udp:", "tcp4:", etc. prefixes.  Passing a ws:// or wss://
        # URL directly to "target remote" causes GDB to split the URL at the
        # last ':' and pass the remainder as the service name to getaddrinfo(),
        # yielding "Servname not supported for ai_socktype" (EAI_SERVICE).
        # Always use the gdb-ws-proxy.py pipe bridge for all WebSocket URLs.
        cmd_parts = ['python3', shlex.quote(_PROXY_SCRIPT),
                     '--url', shlex.quote(url)]
        if insecure:
            cmd_parts.append('--insecure')
        if token:
            cmd_parts += ['--token', shlex.quote(token)]
        pipe_cmd = ' '.join(cmd_parts)
        try:
            # WebSocket relay adds latency; extend per-packet timeout so GDB
            # doesn't give up waiting for RSP responses over the bridge.
            gdb.execute('set remotetimeout 30')
            # Our stub only attaches to a single thread, so hardware debug
            # registers are unreliable for multi-threaded targets.  Tell GDB
            # the remote has no hardware breakpoint or watchpoint slots so
            # pwndbg's internal hbreak attempts (e.g. _dl_debug_state) never
            # reach the stub and generate "Cannot insert hardware breakpoint"
            # warnings.
            gdb.execute('set remote hardware-breakpoint-limit 0')
            gdb.execute('set remote hardware-watchpoint-limit 0')
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


WssRemote()
