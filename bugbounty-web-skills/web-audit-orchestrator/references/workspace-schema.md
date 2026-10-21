# Workspace Schema

All audit state lives in `audit/` next to the target source. Mini-agents communicate only through these files.

```
audit/
├── scope.md              program scope, version, rules of engagement (human-confirmed)
├── human-context.md      append-only facts and instructions from the human
├── checklist.md          master checklist; ticked only with a log reference
├── log.md                append-only task log
├── attack-surface.md     output of attack-surface-mapper
├── authz-matrix.md       output of authz-matrix-audit
├── candidates.md         index of every candidate (one row each)
├── dismissals.md         repo-specific reasons a pattern is NOT exploitable (grows over time)
├── notes/
│   └── C-001.md          one note per candidate: trace, then triage verdict
└── findings/
    └── F-001.md          one file per verified finding / report draft
```

## IDs
- Candidates: `C-001`, `C-002`, ... (never reused, even if dismissed)
- Findings: `F-001`, ... (a finding is a candidate that survived triage and verification; keep the `C-` link)
- Routes/entry points (in attack-surface.md and authz-matrix.md): `R-001`, ...
- Log entries: `#001`, `#002`, ...
- Checklist items: phase.number, e.g. `P1.3`

## Candidate statuses (column `status` in candidates.md)
- `NEW` found, not yet traced
- `TRACING` a tracer job is in progress
- `TRACED` trace complete, awaiting triage
- `TRIAGE` triage in progress
- `LIKELY-TP` survived triage
- `NEEDS-HUMAN` triage could not decide; human input required
- `DISMISSED` false positive or not exploitable (reason mandatory)
- `APPROVED` human approved for verification
- `VERIFIED` PoC confirmed (locally or as approved)
- `REPORTED` report drafted or submitted
- `RECHECK` earlier work invalidated by new context

## candidates.md columns
`ID | class | location (path:line) | origin | status | confidence | auth needed | one-line summary | note`

`origin` is one of: `tracer`, `authz`, `variant`, `semgrep`, `codeql`, `grep`, `secrets`, `human`, `mapper`.
`auth needed` is one of: `none`, `user`, `role:<name>`, `admin`, `unknown`.

## Log entry format (append only)
```
#014 | 2026-10-20T12:03Z | attack-surface-mapper | P1.3
did:    inventoried HTTP routes and WP ajax/REST hooks (127 entry points)
files:  audit/attack-surface.md (routes table), includes/ajax.php, includes/rest.php
result: DONE (3 routes unclear; flagged for human)
next:   P1.4 auth model
```
`result` is `DONE`, `PARTIAL`, `BLOCKED` or `DECISION` (for recorded human decisions). Always say what is next.

## Evidence format
Cite as `path/to/file.ext:LINE` or `path/to/file.ext:START-END`. When a claim is inferred rather than read, prefix with `inferred:`. When something could not be confirmed, prefix with `unverified:`.
