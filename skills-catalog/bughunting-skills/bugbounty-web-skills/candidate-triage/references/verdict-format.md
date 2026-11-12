# Triage section format (append to audit/notes/C-###.md)

```markdown
## Triage (candidate-triage, <date>)

Verdict: LIKELY-TP | NEEDS-HUMAN | FP
Confidence: low | medium | high

### Citation check
| claim | cited at | result (confirmed / wrong / unreadable) |
|-------|----------|-----------------------------------------|

### Knock-down criteria
| criterion | result (defeats / weakens / no effect / unknown) | evidence |
|-----------|--------------------------------------------------|----------|

### Attack in plain steps (steelman)
1. <attacker and starting position>
2. <input / request shape>
3. <path through code with file:line>
4. <what they gain>

### Reasons for the verdict
1. ...
2. ...

### Strongest counter-argument to this verdict
...

### What would change this verdict
...

### Questions for the human (NEEDS-HUMAN only)
- ...
```

## Row update (audit/candidates.md)
Set `status` to `LIKELY-TP`, `NEEDS-HUMAN` or `DISMISSED`; set `confidence`; put the one-line reason in `note`. For `DISMISSED`, the reason is mandatory.

## dismissals.md entry (when the reason will recur)
`- D-007 | 2026-10-20 | pattern: string-built SQL in admin export | reason: value is cast with absint() at all three call sites | evidence: export.php:31,58,90 | source: triage`
