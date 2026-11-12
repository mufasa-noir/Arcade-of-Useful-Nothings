# C-000: <short title>

- Class: <sqli | xss | ssrf | path | upload | deser | ssti-eval | authn | authz | csrf-cors | logic | xxe | secrets | other>
- Location: <path:line of the sink or the missing check>
- Origin: <tracer | authz | variant | semgrep | codeql | grep | secrets | human | mapper>
- Status: <see workspace-schema.md>
- Confidence (tracer): <low | medium | high>
- Auth needed: <none | user | role:<name> | admin | unknown>

## Entry point(s)
<route/hook/handler id (R-###), HTTP method, path/params, file:line>

## Source(s): where attacker input originates
| # | Source | file:line | attacker control (full / partial / typed) |
|---|--------|-----------|-------------------------------------------|

## Path: hop by hop
| Hop | file:line | what happens to the value | observed / inferred / unverified |
|-----|-----------|---------------------------|----------------------------------|

## Controls on the path (sanitizers, validators, auth checks, framework protections)
| Control | file:line | what it actually does | holds for this context? why / why not |
|---------|-----------|-----------------------|----------------------------------------|

## Sink
- Function/operation: <...> at <file:line>
- Dangerous argument: <...>
- Safe counterpart exists and is not used? <...>

## Preconditions and reachability
<config flags, roles, feature toggles, default state, who can reach it, user interaction needed>

## Stored / second-order notes
<does the value pass through storage? where is it written and where is it read?>

## Tracer assessment
<2-4 sentences: what is established, what is inferred, what is unverified; confidence and what would change it>

## Open questions for the human
- <...>

## New leads found (also added to candidates.md as NEW)
- <C-### ...>

---
## Triage (filled by candidate-triage)
<verdict, numbered reasons, evidence, counter-arguments, what would change the verdict>
