---
name: ela-fleet
description: Enumerate and manage ELA devices through the client API — list connected terminal sessions, set device alias/group, check what artifact types a device has uploaded, and smoke-test live control. Use this first, before any other ela-* skill, or whenever the user asks "what devices are connected", "is <device> online", or "what data do we have".
---

# ELA fleet — device discovery and session management

All interaction goes through the **client API** (`api/client/`, docs:
`docs/api/client/index.md`). Never talk to the agent helper API or terminal
server directly — the client API is the single operator surface.

## Preflight (shared by every ela-* skill)

```sh
: "${ELA_CLIENT_URL:=http://localhost:7000}"   # behind nginx: https://<host>/client
# Token must be a CLIENT-scoped key (agent keys are rejected).
# Created with: node tools/add-user-key.js --username <user>
[ -n "$ELA_CLIENT_KEY" ] || echo "Set ELA_CLIENT_KEY to a client-scoped token"
```

Send `Authorization: Bearer $ELA_CLIENT_KEY` on every request. If the user has
not provided `ELA_CLIENT_URL`/`ELA_CLIENT_KEY`, ask for them — do not guess a
remote host. A `401` means wrong/missing token or an agent-scoped token; a
`404` on a device route means the device is either unknown, offline, or not
associated with this user's token (deliberately indistinguishable).

MAC addresses accept either separator and any case (`aa:bb:..` or `AA-BB-..`).

## Steps

1. **List connected devices:**
   ```sh
   curl -s -H "Authorization: Bearer $ELA_CLIENT_KEY" "$ELA_CLIENT_URL/terminal/sessions"
   ```
   Returns `{ sessions: [{ mac, alias, group, remoteAddress, connectedAt, lastHeartbeat }] }`.
   A stale `lastHeartbeat` (> ~60s old) suggests a dying session.

2. **Check artifact inventory** (works even for offline devices):
   ```sh
   curl -s -H "Authorization: Bearer $ELA_CLIENT_KEY" "$ELA_CLIENT_URL/uploads"
   ```
   Returns per-type counts (`dmesg`, `linux-audit`, `uboot-environment`,
   `efi-vars`, `cpu-fuzz`, …). Cross-reference against sessions to summarize:
   which devices are live, which have data, which have neither.

3. **Set alias/group** when the user wants to label a device (works offline too):
   ```sh
   curl -s -X POST -H "Authorization: Bearer $ELA_CLIENT_KEY" -H 'Content-Type: application/json' \
     -d '{"alias":"lab-router-1","group":"engagement-2026-07"}' \
     "$ELA_CLIENT_URL/terminal/sessions/aa:bb:cc:dd:ee:ff"
   ```
   `null` clears a field.

4. **Smoke-test live control** on a connected device before starting real work:
   ```sh
   curl -s -X POST -H "Authorization: Bearer $ELA_CLIENT_KEY" -H 'Content-Type: application/json' \
     -d '{"command":"uname -a","timeoutMs":15000}' \
     "$ELA_CLIENT_URL/terminal/aa:bb:cc:dd:ee:ff/linux/exec"
   ```
   Record the kernel version and architecture — later skills need them.

5. **Check for leftover background processes** from earlier sessions:
   ```sh
   curl -s -H "Authorization: Bearer $ELA_CLIENT_KEY" "$ELA_CLIENT_URL/terminal/aa:bb:cc:dd:ee:ff/spawn"
   ```
   Kill stale ones with `DELETE /terminal/:mac/spawn/:pid` only after telling
   the user what they are.

## Constraints to remember

- `exec` requests cap at `timeoutMs: 60000`. Anything longer must go through
  `spawn` (see ela-collect / ela-fuzz skills).
- The agent session is a single REPL: while one exec/spawn command runs on a
  device, other exec/spawn calls to that same MAC queue or 504. Sequence
  commands per device; parallelize across devices only.
- Every exec/spawn/kill is recorded server-side in `command_logs` — commands
  run against devices are part of the engagement record.

## Output

Report a device table: MAC, alias, group, online status, last heartbeat,
kernel/arch (if probed), artifact-type counts. Recommend the next skill
(`/ela-collect` for a fresh device, `/ela-triage` if data already exists).
