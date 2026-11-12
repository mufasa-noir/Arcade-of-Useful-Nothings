# Mini-Agent Dispatch

A mini-agent is one narrow job run in a fresh context. The brief is the whole interface: if the brief is vague, the agent will wander. Write it like you are handing a ticket to a colleague who has never seen this audit.

## Brief template

```
JOB: <skill name> - <one-sentence goal>
CHECKLIST ITEM: <e.g. P2.4>
READ FIRST: AGENTS.md, audit/human-context.md, audit/scope.md
INPUTS: <exact files / candidate IDs / route IDs / function locations>
DO: <the specific thing, bounded: ONE sink, ONE route group, ONE candidate>
DO NOT: <explicit out-of-scope things; e.g. "do not trace other sinks; log new leads to candidates.md as NEW">
OUTPUT: <exact path and format, e.g. audit/notes/C-007.md using the tracer template>
EVIDENCE: every claim cites path:line; label observed / inferred / unverified
STOP WHEN: <done condition and give-up condition, e.g. "trace complete, or 40 tool calls, whichever first; report PARTIAL with what blocked you">
RETURN: a 5-line summary: result, confidence, new leads (IDs), questions for the human, log entry text
```

## Sizing rules
- One sink / one function / one entry point per tracer job. If the flow fans out, the agent logs the branches as new candidates instead of following all of them.
- One route group (about 20-40 handlers sharing a router/controller area) per authz job.
- One candidate per triage job. Never triage a batch in one context: later items get less scrutiny.
- Cap effort in the brief (tool calls or a time hint) so a stuck job returns `PARTIAL` instead of burning budget.

## Worked examples

**Tracer job**
```
JOB: source-sink-tracer - trace C-004 (SQL string built in includes/search.php:88) from sink back to attacker input
CHECKLIST ITEM: P2.3
READ FIRST: AGENTS.md, audit/human-context.md, audit/scope.md, audit/attack-surface.md (auth model section)
INPUTS: audit/candidates.md row C-004; web-vuln-playbooks/references/stacks/php-wordpress.md; web-vuln-playbooks/references/classes/injection.md
DO: backward trace from includes/search.php:88 to every attacker-reachable source; judge each sanitizer on the path
DO NOT: trace other queries in the file; log them as NEW candidates instead
OUTPUT: audit/notes/C-004.md (tracer template), update the C-004 row to TRACED
STOP WHEN: all paths to the sink are accounted for, or 40 tool calls
RETURN: 5-line summary
```

**Authz job**
```
JOB: authz-matrix-audit - authorization matrix for the REST and admin-ajax handlers in includes/api/
CHECKLIST ITEM: P2.5
INPUTS: audit/attack-surface.md routes R-031..R-066; roles from the auth model section
DO: for each route, expected principal vs enforced check (with file:line); classify gaps
DO NOT: judge exploitability beyond the gap class; triage happens later
OUTPUT: append rows to audit/authz-matrix.md; create candidates for confirmed gaps
```

**Triage job**
```
JOB: candidate-triage - try to knock down C-004
INPUTS: audit/notes/C-004.md, audit/dismissals.md, audit/scope.md
DO: re-verify every citation, run the false-positive criteria, give a verdict
OUTPUT: append the Triage section to audit/notes/C-004.md; update the row
```

## Environments without sub-agents
Run each job sequentially yourself, but simulate the fresh context: re-read the brief inputs from disk, ignore earlier reasoning, write the output file, log, and only then start the next job.
