# Design: a multiplexed command channel for agent sessions

Status: **partly implemented.** Written 2026-07-16.

- `config.get` — **implemented.** The first slice: a control-plane read that
  answers while the device is busy, and the first frame correlated by request
  id. See "config.get" below.
- The `exec` channel — still a proposal.

Assumption, per project decision: **every agent in the fleet will be updated.**
No back-compat with agents that predate this channel. That assumption removes
capability negotiation and lets the whole prompt-scraping layer be deleted
rather than maintained alongside a new one. See "Flag day" for the one place
that assumption still needs a guard rail.

## Problem

While a long-running command occupies a device — the hour-long
`linux remote-copy --analysis-only --recursive /` that the ghidra-analysis
worker issues is the motivating case — every other device-touching command to
that same device is unserviceable. Operators see:

- `POST /client/terminal/<mac>/ela/spawn` → 504 `terminal command timed out or
  terminal API unavailable` after 30s.
- `POST /client/module-builds/<id>/deliver` → a 400 wrongly blaming the
  device's `ELA_API_URL`, because the route's `set` probe times out and the
  failure is silently reclassified as "device has no `ELA_API_URL`".

The goal: a device should remain serviceable for other commands while a slow
command runs on it.

## What is and is not blocked today

Blocking is already scoped fairly tightly:

- **Other devices are unaffected.** The terminal command worker runs at
  concurrency 8 (`api/lib/queue.js:203`) and the lock is per-MAC.
- **Control-plane commands are unaffected.** `sessions`, `listSpawns` and
  `setMeta` never take the lock (`api/terminal/commandWorker.js:223-228`), and
  `GET /terminal/sessions` reads an out-of-band Redis snapshot without touching
  the queue at all.
- **Blocked:** `exec`, `spawn` and `killSpawn` against the one MAC that is busy
  (`api/terminal/commandWorker.js:229-235`, via `withDeviceLock` at
  `api/terminal/commandWorker.js:34`).

## Why the lock is not the cause

`withDeviceLock` is not a policy we can relax. It reports a real constraint.

An agent session is a single interactive REPL whose stdout is screen-scraped:

- The agent connects over a WebSocket and `ela_ws_run_interactive` forks **one**
  child running `interactive_loop()`, bridged to the socket with pipes
  (`agent/net/ws_client.h:74-82`, `agent/net/ws_client.c:1032`, `:1082`, `:1133`).
- `runExec` writes a raw line into that REPL and watches the shared output
  stream for the prompt token `(<mac>)> ` to decide the command finished
  (`api/terminal/execCommand.js:151`, `findCompletionIndex` at `:27`,
  `promptTokenForMac` at `api/terminal/promptFormatter.js:3`). Around that sit
  layers of heuristics: ANSI/OSC stripping, prompt-redraw detection, input-echo
  removal, `execute-command` record echo removal, and opportunistic JSON parsing.
- Every listener in `entry.outputListeners` receives **all** session output
  (`api/terminal/server.js:262-270`).

Two concurrent commands on one session would therefore consume each other's
output and each other's completion prompts. During the copy the agent's shell is
genuinely occupied and emitting progress output. The lock is honestly reporting
that the device is busy; removing it would produce corruption, which is
precisely what it was added to prevent.

**No server-side change can fix this.** The agent has to stop occupying the
shell.

## Why request-ID output framing alone does not work

The obvious design — tag each command with a request ID, have the agent frame
its output with that ID, demux in `runExec` — **does not solve this problem.**

`interactive_loop()` is a synchronous read-line/dispatch loop
(`agent/shell/interactive.c:708`). It calls:

```c
last_rc = embedded_linux_audit_dispatch(argc + 1, dispatch_argv);
```

directly, in-process, at `agent/shell/interactive.c:822`. While
`linux remote-copy` runs inside that call, the loop is not reading stdin. A
second command sent over the WebSocket sits unread in the pipe buffer until the
copy finishes an hour later.

The bottleneck is **serialized execution on the agent**, not ambiguous output.
Perfect demuxing of a stream nobody is producing changes nothing. Any design
that keeps routing API commands through the single REPL child inherits this
limit.

## Proposal: an out-of-band exec channel

Stop routing API commands through the REPL. Add a control channel on the same
WebSocket where each command is **executed in its own forked child**, with
output tagged by request ID. The REPL child remains, unchanged, for humans
attaching via the TUI.

### The hook already exists

The agent already intercepts structured control frames and decides whether to
forward them to the REPL. `ela_ws_classify_incoming_frame` matches
`"_type":"heartbeat"` and sets `send_heartbeat_ack`, otherwise
`forward_to_repl = 1` (`agent/net/ws_session_util.c:99-104`), returning a
`struct ela_ws_frame_action` (`agent/net/ws_session_util.h:19-27`). The server
side mirrors this: `ws.on('message')` tries `JSON.parse` and handles
`msg._type === 'heartbeat_ack'` before the raw-output path
(`api/terminal/server.js:242-259`).

That dispatch layer has exactly one member today. This design adds members to
it. It is an extension of an existing pattern, not a new architecture.

json-c is vendored (`third_party/json-c`) and already used on the agent
(`agent/linux/linux_filesystem_audit_cmd.c:11`), so real JSON parsing is
available — the current `strstr` matching must not be extended to frames
carrying untrusted operator-supplied fields.

### Protocol sketch

Server → agent:

```json
{"_type":"exec.req","id":"<uuid>","argv":["linux","remote-copy","--recursive","/"],"timeoutMs":3600000}
{"_type":"exec.cancel","id":"<uuid>"}
{"_type":"config.get","id":"<uuid>","keys":["ELA_API_URL"]}
```

There is no `config.set`: the write path already works through `/tmp/.ela.conf`
(see "`set`" below), so the channel only needs to read.

Agent → server:

```json
{"_type":"hello","proto":1,"agentVersion":"..."}
{"_type":"exec.ack","id":"<uuid>","pid":1234}
{"_type":"exec.out","id":"<uuid>","seq":0,"stream":"stdout","data":"..."}
{"_type":"exec.done","id":"<uuid>","code":0,"durationMs":123}
{"_type":"exec.err","id":"<uuid>","error":"..."}
{"_type":"config.value","id":"<uuid>","values":{"ELA_API_URL":"..."}}
```

Passing `argv` as an array rather than a command string removes the shell
quoting and parsing ambiguity that `interactive_parse_line` and
`spawnCommand.js`'s `shellQuote` currently work around.

`exec.done` carries a real exit code — something the prompt-scraping path
cannot report at all today.

### Agent-side changes

1. Send `hello` on connect (see "Flag day" for why it is still worth having).
2. Classify `exec.*` and `config.*` in `ela_ws_classify_incoming_frame` with
   `forward_to_repl = 0`.
3. On `exec.req`, fork a child that runs `embedded_linux_audit_dispatch(argv)`
   with stdout/stderr on a pipe. The parent's existing select loop
   (`agent/net/ws_client.c:1082`, `:1133`) extends from "WebSocket + one REPL
   pipe" to "WebSocket + REPL pipe + N exec pipes", framing each child's output
   into `exec.out` frames tagged with its id.
4. `waitpid` children, emit `exec.done` with the exit code, reap zombies.
5. `exec.cancel` → `kill(pid)`.
6. Cap concurrent exec children (4 is a reasonable start); reject beyond that
   with `exec.err`. These are memory-constrained embedded targets.

Forking to run `dispatch` is not a new capability: the REPL child is already a
fork that runs dispatch (`agent/net/ws_client.c:1032`), and the agent forks for
`ela_fuzz_daemonize` (`agent/linux/fuzz_daemon.c`) and the gdb bridge.

### Terminal API changes

1. Add `runExecMuxed`: correlate replies by `id` off a per-session map of
   pending requests. No prompt scraping.
2. Rewrite `commandWorker`'s `exec` / `spawn` / `killSpawn` onto it.
3. Delete `withDeviceLock`.

## What gets deleted

This is the main dividend of not supporting old agents. `runExec` and `runSpawn`
are consumed **only** by `commandWorker.js`, so once it moves to the channel:

- `api/terminal/execCommand.js` — deleted entirely. With it go
  `findCompletionIndex`, `stripAnsi`, `stripCommandEcho`, `extractExecOutput`
  and `maybeParseJsonOutput`.
- `api/terminal/spawnCommand.js` — deleted entirely, including the
  `__ELA_SPAWN__` sentinel and `shellQuote`.
- `withDeviceLock` and the per-MAC chain map in `commandWorker.js` — deleted.
- `ELA_TERMINAL_CONCURRENCY` and the worker-concurrency reasoning in
  `api/lib/queue.js:189-205` — simplified; there is no longer a device-isolation
  argument to make.

What **stays**, because the REPL child stays for humans on the TUI:

- `api/terminal/promptFormatter.js` — `formatPromptOutput` is the TUI display
  path (`api/terminal/server.js:244`).
- `api/terminal/batchOutput.js` — TUI batch display; uses `promptTokenForMac`
  to filter prompt lines out of the rendered output.

## `updateManager` is the third scraper, and it is not locked

`api/terminal/updateManager.js` drives the self-update flow by **injecting
keystrokes into the human REPL and scraping the replies**. `startSessionUpdate`
sends `\x03` (Ctrl-C), `\x15` (Ctrl-U), then `set\n` (`:38-40`), scrapes for
`ELA_API_URL current=` (`:64`), then sends `--output-format json arch isa\n`
(`:83`) and `arch endianness` (`:107`), scraping `{"record":"arch"...}` out of
each.

Two things follow:

1. **It bypasses the lock.** It writes straight to `entry.ws`, never through the
   command queue, so `withDeviceLock` does not apply. A TUI-initiated
   self-update during a `remote-copy` sends Ctrl-C into that session — killing
   the copy — and the two scrapers then consume each other's output. It is
   operator-initiated (callers: `localCommands.js:45`, `server.js:549`,
   `server.js:734`), so it does not fire on its own, but "the lock protects the
   session" is not actually true today.
2. **It wants the same `set` probe** that `POST /module-builds/:id/deliver`
   wants. Two callers, one need.

Migrating it onto `config.get` plus two `exec.req`s deletes the state machine,
the keystroke injection and the race in one go. It should be in scope.

## `set`: mostly already solved by `ela_conf`

An earlier draft of this document claimed `set` created "two divergent settings
worlds" needing a new REPL→parent control pipe. **That was wrong.** A shared
settings store already exists and `set` already writes through to it.

- `interactive_set_command` calls `ela_conf_update_from_env()` for conf-tracked
  variables (`agent/shell/interactive.c:234`).
- `ELA_API_URL` is conf-tracked — `plan->update_conf = true`
  (`agent/shell/interactive_util.c:208`).
- `main()` already loads and exports conf at startup
  (`agent/embedded_linux_audit.c:895`, `:928`).
- The store is `/tmp/.ela.conf`, mode 0600 (`agent/net/ela_conf.h:10`, `:26`).

So a REPL `set ELA_API_URL ...` is already visible to any process that loads
conf. No new IPC is required.

### What is actually left

**Exec children must reload conf after fork.** They inherit the WS parent's
environment at fork time and would not see a later REPL `set`. The wrinkle:
`ela_conf_export_to_env()` deliberately uses `overwrite=0` ("env set before
launch wins"), so a stale inherited value beats fresh conf. The exec child needs
a load plus an overwrite-permitting export (or a clear-then-export) immediately
after fork, before dispatch. That is a small, local change — not plumbing.

**The read path needs no REPL involvement at all.** The WS parent can answer
`config.get` straight from `ela_conf_load()`. See "config.get" below.

### The five tracked variables, and the rest

Conf covers exactly: `ELA_API_URL`, `ELA_API_INSECURE`, `ELA_OUTPUT_FORMAT`,
`ELA_OUTPUT_HTTP`, `ELA_OUTPUT_INSECURE` (`agent/shell/interactive_util.c:208`,
`:215`, `:235`, `:277`, `:284`).

The rest — `ELA_QUIET`, `ELA_OUTPUT_TCP`, `ELA_SCRIPT`, `ELA_API_KEY`,
`ELA_VERBOSE`, `ELA_DEBUG`, `ELA_WS_RETRY_ATTEMPTS` — are `setenv`-only and do
still diverge between the REPL child and exec children. For most of them that is
tolerable (they are display/diagnostic toggles).

### `ELA_API_KEY` must NOT be added to conf

`ELA_API_KEY` is the one variable that sets `plan->redact_value = true` and
deliberately omits `update_conf` (`agent/shell/interactive_util.c:288-300`). The
exclusion is intentional and must stay, because:

`ELA_CONF_PATH` is `/tmp/.ela.conf`, and `remote-copy` refuses only `/dev`,
`/sys` and `/proc` (`agent/util/remote_copy_util.c:30-34`) — **`/tmp` is
copied**. Persisting the key would mean the next
`linux remote-copy --analysis-only --recursive /` (precisely what the
ghidra-analysis worker runs) uploads the agent's bearer token into the artifact
store at `<macDir>/fs/tmp/.ela.conf`, retrievable through the ghidra output zip
routes. `--analysis-only` uploads plaintext files; `.ela.conf` is plaintext. The
0600 mode protects the file on the device and is irrelevant once it is in the
store.

The key does not need conf: exec children are forked from the WS parent, which
already holds `ELA_API_KEY` in its environment (it authenticated the WebSocket
with it), and `fork()` copies the environment. The only gap is an operator
changing the key mid-session from the REPL. If that must be closed, use an
in-memory control message — never conf, never disk.

`config.get` must likewise refuse to return `ELA_API_KEY`.

## Flag day

"All agents will be updated" is a deployment claim, and the failure mode if it
slips is bad: an old agent classifies `{"_type":"exec.req",...}` as
`forward_to_repl = 1` and its REPL tries to parse the JSON as a command line,
emitting parse errors while the terminal API waits for an `exec.done` that never
arrives.

That is silent garbage rather than a clean error, so keep `hello` **not** as
back-compat but as a guard rail: if a session does not announce `proto: 1`
shortly after connect, mark it unsupported and fail its commands with a clear
"agent too old, upgrade required" rather than sending frames it will mangle.
That is a few lines and it converts a confusing failure into an actionable one.

## Resource and safety notes

- Concurrency cap per session, as above.
- Output backpressure: a chatty command must not exhaust agent memory or flood
  the socket. The current paths cap captured output (`MAX_EXEC_OUTPUT_BYTES`,
  `MAX_SPAWN_OUTPUT_BYTES`); the framed path needs an equivalent applied at the
  agent, where the memory actually matters.
- `exec.out` ordering is guaranteed per-id by the WebSocket, but `seq` is cheap
  insurance and makes gaps detectable.
- Commands that self-daemonize (`linux gdbserver`, `... fuzz --daemon`) fork
  again and their exec child exits promptly, yielding `exec.done` immediately.
  That preserves today's semantics.

## What this does not fix

- **`spawn` with `mode: 'ela'`.** Today it is a blocking exec under the hood
  (`api/terminal/commandWorker.js:123-134`) that merely assumes ELA commands
  daemonize themselves — which is why `linux cpu fuzz` without `--daemon` holds
  the session. On this channel it stops blocking *other* commands, but "spawn
  returns once the process is running" still wants either `--daemon` or an
  explicit detach flag in `exec.req`. Worth folding into the frame design.
- **Genuine device busyness.** A device running one command still cannot run a
  conflicting one against the same hardware. This makes concurrency possible,
  not free.
- **The ghidra copy-completion signal.** Independent of this design: the
  blocking exec's return is currently how the worker knows the copy finished.
  Nothing here changes that, but see below.

## Rough scope

- Agent: `hello`, frame classification, fork/select/frame plumbing, limits, and
  the post-fork conf reload. The select loop is the bulk. Roughly 400-600 lines
  of C plus tests.
- Terminal API: `runExecMuxed`, `commandWorker` rewrite, `updateManager`
  migration, and a satisfying amount of deletion.

`config.get` (below) is a much smaller slice of the same machinery and is worth
landing first on its own.

## `config.get`: the first slice (implemented)

`config.get` was built before the exec channel because it is the smallest useful
piece of this design and it independently fixes the module-deliver bug.

It is **control-plane**: the agent's WebSocket parent answers it from
`/tmp/.ela.conf` plus its own environment, never touching the REPL, so it takes
no device lock and answers while a `remote-copy` holds the device. It is also
the first request/reply frame correlated by `id` — the `exec.v1` demux in
miniature, with none of the fork/select complexity.

Agent:

- `agent/net/ws_config_util.{c,h}` — key policy, request parse (json-c, honouring
  `payload_len`), value precedence, reply build. Pure and unit-tested;
  `env_lookup` is injected.
- `ela_ws_classify_incoming_frame` sets `send_config_value` for
  `"_type":"config.get"`, so the frame never reaches the REPL.
- `ws_client.c` snapshots conf at session start (`startup_conf`) and answers each
  request from a fresh `ela_conf_load()`. A malformed request is dropped, not
  fatal — a bad frame must not kill an operator's live session.

Terminal API:

- `api/terminal/configCommand.js` — `runConfigGet` / `deliverConfigValue`,
  correlated by id off `entry.configWaiters`.
- `server.js` intercepts `config.value` before the output path, so replies never
  land in an exec capture or the TUI.
- `commandWorker` gained a `configGet` case in the **control-plane** group: it
  takes no device lock, which is the entire point.
- `POST /module-builds/:id/deliver` reads the origin through it, and the
  `set`-scraping `parseDeviceApiUrl` is deleted.

### The value-precedence rule

Not simply "conf wins". `ela_conf_export_to_env()` uses `overwrite=0` at
startup, so an `ELA_API_URL` from the launch environment beats a value persisted
by an earlier run — and that launch value is never written back to conf. But a
runtime `set` *does* write through. So the resolver compares current conf
against the startup snapshot: changed means a runtime `set` happened and conf is
newest; unchanged means the parent's environment is the effective value. A
conf-only read would return "" for any device configured purely from its launch
environment and reproduce the very 400 this replaces.

### Restrictions

Serves conf-tracked, non-secret variables only, and refuses `ELA_API_KEY` (see
above). The terminal API filters the same list client-side so the credential is
never even named on the wire.

## Recommendation

Worth doing, and the no-back-compat decision makes it materially cheaper: no
dual-path branching, no permanently-maintained legacy scraper, and a large net
deletion. Suggested sequence:

1. Land the client-API honesty fixes (truthful 504/503 instead of the bogus 400;
   a device-busy signal). Independent, ships today, and buys accurate
   diagnostics while the channel is built.
2. Land `config.get` — fixes the deliver bug outright and prototypes the demux.
3. Implement the channel, including the `updateManager` migration.

An interim step considered and **not** recommended as a substitute: making
`remote-copy` detach via the existing `ela_fuzz_daemonize` helper. It removes
the hour-long lock specifically, but it needs a copy-completion signal (detached,
`latestFilesystemUploadPath` would hand the worker a still-growing tree and
Ghidra would analyze a partial rootfs), and it fixes one command rather than the
class. If the channel is going to be built anyway, skip it.
