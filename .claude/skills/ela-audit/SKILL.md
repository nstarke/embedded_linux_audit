---
name: ela-audit
description: End-to-end automated security audit of one or more embedded Linux devices through the ELA client API — orchestrates fleet discovery, baseline collection, artifact triage, optional fuzzing/deep-dive, and the final report. Use for "audit this device", "run a full assessment", or any request that spans more than one phase of the ELA workflow.
---

# ELA audit — full engagement orchestrator

This skill sequences the phase skills; it does not duplicate their content.
Invoke each phase with the Skill tool and carry its results forward.

## Preflight

Confirm with the user before phase 1:
- `ELA_CLIENT_URL` (default `http://localhost:7000`, or `https://<host>/client`
  behind nginx) and `ELA_CLIENT_KEY` (client-scoped token from
  `tools/add-user-key.js`). If the stack isn't running, `docker compose up`
  in the repo root brings up PostgreSQL, the APIs, and nginx.
- Target device(s): specific MACs/aliases, or "everything connected".
- Scope boundaries: is active testing (fuzzing) permitted? Is packet capture
  permitted? Anything that must not be touched?

## Phases

1. **`/ela-fleet`** — enumerate devices, verify sessions, probe kernel/arch,
   check existing artifact inventory. If the requested device is offline,
   stop and report; nothing else can proceed for it.
2. **`/ela-collect`** — run on each in-scope device that lacks fresh
   baseline artifacts (skip if triage-able data already exists and the user
   didn't ask for re-collection). Devices are independent — but commands to
   a single device must be sequential.
3. **`/ela-triage`** — analyze everything collected into a prioritized
   findings list.
4. **Optional escalations, driven by triage output and user-approved scope:**
   - `/ela-fuzz` for fuzzable interfaces (requires explicit user go-ahead —
     it can crash the target).
   - `/ela-deep-dive` for binaries flagged in triage (network daemons, SUID
     executables), fuzz-crash root-causing, or firmware extraction.
5. **`/ela-report`** — final deliverable with evidence citations and a
   checklist coverage matrix.

## Ground rules across all phases

- The client API is the only interface: never call the agent helper API,
  terminal server, or database directly.
- One command at a time per device (single agent REPL); long work goes
  through spawn routes; exec caps at 60s.
- Everything executed on a device is audit-logged server-side — behave as if
  every command will be read in the engagement record, because it will.
- Failures of absent subsystems (no TPM, no U-Boot, no EFI) are results, not
  errors. Record them and continue.
- Pause for user confirmation only at the gates named above (fuzzing, pcap,
  GDB attach to live processes, anything power-cycle-risky); run everything
  else through without asking.

## Checkpointing

After each phase, summarize in one short paragraph what was done and what
the next phase will do, so a long engagement remains legible in the
conversation. If the session is interrupted, the artifact store is the
source of truth — a fresh run should start at `/ela-fleet` and let the
inventory decide which phases to redo.
