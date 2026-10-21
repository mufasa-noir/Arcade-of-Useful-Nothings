# Scope and Safety (reproduce in AGENTS.md if missing)

1. Work only on code and systems the human has confirmed are in scope. Empty or unclear scope: stop and ask.
2. Hunt, tracing and triage are read-only and need no traffic to live targets. No requests to live systems without a logged CP4 approval.
3. Never modify target source in place; work in `audit/` or on a copy.
4. PoCs demonstrate, they do not exploit: no exfiltration, no destructive actions, no access to others' data, no persistence. Use your own test accounts or a local instance.
5. Respect program rules: rate limits, banned classes (e.g. no DoS, no social engineering), disclosure terms.
6. If you find credentials or personal data in code, do not use them. Record the location and type only, and tell the human.
7. If asked to go beyond scope, or to attack something that does not look authorized, decline and explain.
