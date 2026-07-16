// SPDX-License-Identifier: MIT - Copyright (c) 2026 Nicholas Starke
'use strict';

const { runExec } = require('./execCommand');
const { runSpawn } = require('./spawnCommand');
const { runConfigGet } = require('./configCommand');

// Process one operator command received over the `ela-terminal-commands` queue
// (produced by the client API) against the live agent WebSocket sessions this
// process holds. The return value becomes the BullMQ job's result, which the
// client API awaits and relays to the caller.
//
// Every outcome is returned as `{ status, body }` (an HTTP status + JSON body)
// so the client route is a thin proxy — it never has to re-map error codes. The
// client API is the ACL boundary (device association); by the time a command
// reaches here the caller is already authorised for `mac`.

const NO_SESSION = { status: 404, body: { error: 'no active session for mac' } };

// Per-device serialization.
//
// `runExec`/`runSpawn` detect a command's completion by watching the target
// session's shared output stream (entry.outputListeners). Two commands run
// against the SAME device at once would each consume the other's output and its
// completion prompt — so device-touching commands (exec/spawn/killSpawn) must
// run one-at-a-time per MAC. They are independent ACROSS devices, and the
// control-plane commands (sessions/listSpawns/setMeta) touch no output stream
// at all. So instead of a single global worker (concurrency 1 — where one slow
// exec blocked every device, and even the sessions listing), we run the worker
// concurrently and gate only the device-touching commands behind a per-MAC
// lock. Different devices proceed in parallel; a device's own commands queue
// behind each other.
const deviceChains = new Map();

function withDeviceLock(mac, fn) {
  const key = String(mac);
  const prev = deviceChains.get(key) || Promise.resolve();
  // Run fn after prev settles, regardless of whether prev resolved or rejected.
  const run = prev.then(fn, fn);
  // The chain tail swallows outcomes so a rejection never leaks as an unhandled
  // rejection and never poisons the next waiter (which runs on settle anyway).
  const tail = run.then(() => {}, () => {});
  deviceChains.set(key, tail);
  tail.finally(() => {
    // Drop the map entry once this device is idle again, so the map does not
    // grow without bound as devices come and go.
    if (deviceChains.get(key) === tail) {
      deviceChains.delete(key);
    }
  });
  return run;
}

function spawnsFor(entry) {
  if (!entry.spawns) {
    entry.spawns = new Map();
  }
  return entry.spawns;
}

function serializeSpawn(record) {
  const out = {
    pid: record.pid,
    command: record.command,
    args: record.args,
    startedAt: record.startedAt,
  };
  if (record.port !== undefined) {
    out.port = record.port;
  }
  return out;
}

// The live session descriptors, in the exact shape returned to operators. Used
// both by the queue's `sessions` command and by the out-of-band snapshot the
// terminal API publishes for the client API to read directly (sessionSnapshot).
function buildSessionList(sessionRegistry) {
  return sessionRegistry.entries().map(([mac, entry]) => ({
    mac,
    alias: entry.alias || null,
    group: entry.group || null,
    remoteAddress: entry.remoteAddress || null,
    connectedAt: entry.connectedAt || null,
    lastHeartbeat: entry.lastHeartbeat || null,
  }));
}

function listSessions(sessionRegistry) {
  return { status: 200, body: { sessions: buildSessionList(sessionRegistry) } };
}

// mode 'linux' (default) wraps the command as a Linux shell command
// (`linux execute-command`); mode 'ela' sends it verbatim as an ELA agent
// command (e.g. `linux gdbserver ...`).
function wrapShellForMode(mode) {
  return mode !== 'ela';
}

async function execOnSession(sessionRegistry, runExecImpl, { mac, command, timeoutMs, mode }) {
  const entry = sessionRegistry.getSession(mac);
  if (!entry) return NO_SESSION;
  try {
    const result = await runExecImpl({ entry, mac, command, timeoutMs, wrapShell: wrapShellForMode(mode) });
    return { status: 200, body: { ok: true, output: result.output, durationMs: result.durationMs } };
  } catch (err) {
    if (err.code === 'TIMEOUT') {
      return {
        status: 504,
        body: { ok: false, error: 'exec timed out', output: err.output || '', durationMs: err.durationMs },
      };
    }
    if (err.code === 'NOT_CONNECTED') return NO_SESSION;
    return { status: 500, body: { error: 'exec failed' } };
  }
}

async function spawnOnSession(sessionRegistry, runSpawnImpl, runExecImpl, now, { mac, command, args = [], port, mode }) {
  const entry = sessionRegistry.getSession(mac);
  if (!entry) return NO_SESSION;

  // An ELA agent command (e.g. `linux gdbserver tunnel ...`) daemonizes itself
  // rather than shell-backgrounding, so there is no `$!` PID to capture: run it
  // verbatim and return its output (which carries e.g. the gdb tunnel URL).
  if (mode === 'ela') {
    try {
      const result = await runExecImpl({ entry, mac, command, wrapShell: false });
      return { status: 201, body: { ok: true, output: result.output, durationMs: result.durationMs } };
    } catch (err) {
      if (err.code === 'TIMEOUT') {
        return { status: 504, body: { ok: false, error: 'spawn timed out', output: err.output || '' } };
      }
      if (err.code === 'NOT_CONNECTED') return NO_SESSION;
      return { status: 500, body: { error: 'spawn failed' } };
    }
  }

  // A Linux command is shell-backgrounded; capture and track its PID/port.
  try {
    const result = await runSpawnImpl({ entry, mac, command, args, port });
    const record = { pid: result.pid, command, args, port: result.port, startedAt: now() };
    spawnsFor(entry).set(result.pid, record);
    const body = { pid: result.pid };
    if (result.port !== undefined) body.port = result.port;
    return { status: 201, body };
  } catch (err) {
    if (err.code === 'TIMEOUT') return { status: 504, body: { error: 'spawn timed out' } };
    if (err.code === 'NOT_CONNECTED') return NO_SESSION;
    return { status: 500, body: { error: 'spawn failed' } };
  }
}

// Set a device's alias and/or group. `alias`/`group` are optional — undefined
// means "leave unchanged"; a string sets it; null clears it. The value is
// persisted to the DB and, if the device is connected, mirrored onto the live
// session entry so the sessions listing reflects it immediately.
async function setMeta(sessionRegistry, setDeviceAliasImpl, setDeviceGroupImpl, { mac, alias, group }) {
  const entry = sessionRegistry.getSession(mac);
  const out = { mac };

  if (alias !== undefined) {
    const value = await setDeviceAliasImpl(mac, alias);
    out.alias = value || null;
    if (entry) entry.alias = out.alias;
  } else {
    out.alias = entry ? (entry.alias || null) : null;
  }

  if (group !== undefined) {
    const value = await setDeviceGroupImpl(mac, group);
    out.group = value || null;
    if (entry) entry.group = out.group;
  } else {
    out.group = entry ? (entry.group || null) : null;
  }

  return { status: 200, body: out };
}

// Read device settings over the control channel.
//
// This is control-plane despite naming a MAC: the agent answers it from its
// WebSocket parent process, not the REPL, so it neither touches the session
// output stream nor waits on a running command. It must therefore NOT take the
// device lock — the entire point is that it answers while a long `remote-copy`
// holds the device.
//
// A 504 here means "we never got an answer", which is deliberately distinct
// from a 200 carrying an empty value ("the device answered; the setting is
// unset"). Callers depend on that distinction to avoid reporting a timeout as
// a device misconfiguration.
async function configGet(sessionRegistry, runConfigGetImpl, { mac, keys }) {
  const entry = sessionRegistry.getSession(mac);
  if (!entry) return NO_SESSION;
  try {
    const values = await runConfigGetImpl({ entry, keys });
    return { status: 200, body: { ok: true, values } };
  } catch (err) {
    if (err.code === 'NOT_CONNECTED') return NO_SESSION;
    if (err.code === 'TIMEOUT') {
      return { status: 504, body: { ok: false, error: 'config.get timed out' } };
    }
    return { status: 500, body: { error: 'config.get failed' } };
  }
}

function listSpawns(sessionRegistry, { mac }) {
  const entry = sessionRegistry.getSession(mac);
  if (!entry) return NO_SESSION;
  return { status: 200, body: { spawns: [...spawnsFor(entry).values()].map(serializeSpawn) } };
}

async function killSpawn(sessionRegistry, runExecImpl, { mac, pid }) {
  const entry = sessionRegistry.getSession(mac);
  if (!entry) return NO_SESSION;
  const spawns = spawnsFor(entry);
  if (!spawns.has(pid)) return { status: 404, body: { error: 'no such spawn' } };
  try {
    await runExecImpl({ entry, mac, command: `kill ${pid}` });
    spawns.delete(pid);
    return { status: 200, body: { ok: true } };
  } catch (err) {
    if (err.code === 'NOT_CONNECTED') return NO_SESSION;
    return { status: 500, body: { error: 'kill failed' } };
  }
}

/**
 * Dispatch one queued command. Returns `{ status, body }`.
 *
 * @param {object} opts
 * @param {object} opts.job              BullMQ job; job.data = { type, mac, ... }.
 * @param {object} opts.sessionRegistry  Live agent session registry.
 * @param {Function} [opts.runExecImpl]  Override for runExec (tests).
 * @param {Function} [opts.runSpawnImpl] Override for runSpawn (tests).
 * @param {Function} [opts.now]          Clock for spawn start time.
 */
async function processCommand({
  job,
  sessionRegistry,
  runExecImpl = runExec,
  runSpawnImpl = runSpawn,
  runConfigGetImpl = runConfigGet,
  now = () => new Date().toISOString(),
  // Lazily resolved so importing this module (tests) does not pull in the DB.
  setDeviceAliasImpl = (mac, alias) => require('../lib/db/deviceRegistry').setDeviceAlias(mac, alias, 'client_api'),
  setDeviceGroupImpl = (mac, group) => require('../lib/db/deviceRegistry').setDeviceGroup(mac, group),
}) {
  const data = (job && job.data) || {};
  switch (data.type) {
    // Control-plane: touches no device output stream, so it runs concurrently
    // and is never gated behind an in-flight exec.
    case 'sessions':
      return listSessions(sessionRegistry);
    case 'listSpawns':
      return listSpawns(sessionRegistry, data);
    case 'setMeta':
      return setMeta(sessionRegistry, setDeviceAliasImpl, setDeviceGroupImpl, data);
    case 'configGet':
      return configGet(sessionRegistry, runConfigGetImpl, data);
    // Device-touching: serialized per MAC (see withDeviceLock).
    case 'exec':
      return withDeviceLock(data.mac, () => execOnSession(sessionRegistry, runExecImpl, data));
    case 'spawn':
      return withDeviceLock(data.mac, () => spawnOnSession(sessionRegistry, runSpawnImpl, runExecImpl, now, data));
    case 'killSpawn':
      return withDeviceLock(data.mac, () => killSpawn(sessionRegistry, runExecImpl, data));
    default:
      return { status: 400, body: { error: `unknown command type: ${String(data.type)}` } };
  }
}

module.exports = { processCommand, serializeSpawn, buildSessionList };
