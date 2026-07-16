---
name: ela-report
description: Produce the final security assessment report for an ELA engagement — pull all evidence for the in-scope devices from the client API uploads routes, merge findings from triage/fuzz/deep-dive phases, map coverage against the manual checklist, and write a structured markdown report. Use when the user asks for "the report", "write up findings", or at the end of an engagement.
---

# ELA report — engagement write-up

Read-only against the client API (standard preflight, see ela-fleet), plus
whatever findings were produced earlier in the conversation or in prior
report drafts the user points at.

## Gather

1. Scope: confirm with the user which devices (MACs/aliases/group) and what
   period the report covers. `GET /terminal/sessions` for alias/group names.
2. Evidence inventory per device: `GET /uploads`, then per-type metadata
   lists filtered by `macAddress`. Record ids are the citation currency —
   every finding must cite at least one artifact id (`uploads/<type>/<id>`).
3. Device facts: kernel (`uname` cmd records or dmesg), architecture (`arch`
   records), firmware/OS identity (cmd records for os-release).
4. Prior analysis: findings from `/ela-triage`, `/ela-fuzz`, `/ela-deep-dive`
   runs in this or earlier sessions. If none exist, run `/ela-triage` first
   rather than re-deriving findings ad hoc here.

## Coverage check

Walk `docs/manual-checklist.md` section by section (Setup, U-Boot, Linux
kernel, EFI/UEFI, BIOS, TPM, Network, Symlinks, Data collection) and mark
each: **covered** (evidence exists — cite artifact ids), **not applicable**
(with reason, e.g. no U-Boot on this platform), or **gap** (should have been
collected but wasn't). Gaps go in the report and drive a follow-up
`/ela-collect` recommendation.

## Report structure

Write to a markdown file (default `reports/<engagement>-<date>.md` in the
working directory; confirm the path with the user):

1. **Executive summary** — device(s), engagement window, top 3–5 findings in
   plain language, overall posture rating.
2. **Scope and methodology** — devices (MAC, alias, hw/kernel/firmware),
   ELA agent version, collection method (terminal sessions via client API),
   note that all commands run are audit-logged server-side (`command_logs`).
3. **Findings** — one subsection each, ordered by severity. Fields: id
   (ELA-FND-nnn), title, severity + rationale, affected device(s), evidence
   (artifact citations + relevant excerpt), impact, remediation, and the
   audit rule id where a `linux audit`/`uboot audit` rule matched (their
   remediation text is a good starting point — quote or adapt it).
4. **Coverage matrix** — the checklist walk from above.
5. **Appendices** — full artifact inventory per device (type, id, sha256
   from `payloadSha256`, timestamp), fuzz campaign parameters, commands of
   note.

## Rules

- Severity honestly: an `unknown` audit status is reported as unverified, not
  as pass or fail. A finding without a reproducible evidence citation gets
  flagged as such.
- Include not-applicable results — proving a subsystem absent is part of the
  assessment.
- Don't paste huge raw payloads into the report; excerpt the relevant lines
  and cite the artifact id for the rest.

Show the user the executive summary in the conversation and tell them the
report file path.
