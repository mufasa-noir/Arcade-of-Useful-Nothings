# Business Logic, Races, Mass Assignment, Workflow Bypass

**Root cause:** the application enforces its invariants in the wrong place, in the wrong order, or not atomically.

## What to look for
- **Mass assignment:** request fields bound into models or update calls so privileged fields (role, owner, price, status, verified, balance) become writable. Check allowlists, read-only serializer fields, and explicit field copying.
- **Trusting client values:** prices, quantities, discounts, user IDs, state flags sent by the client and used by the server; negative or fractional numbers; integer limits; currency/rounding.
- **Workflow bypass:** step N endpoint callable without steps 1..N-1; one-time actions replayable; approvals self-approved; state transitions not validated against the current state.
- **Races (TOCTOU):** check-then-act on balances, coupon/vote/invite limits, unique constraints enforced only in application code, token consumption not atomic, file operations between check and use. Look for missing transactions, locks, unique indexes, or conditional updates.
- **Limits and quotas:** enforced only client-side or per-request.
- **Resource ownership across features:** feature A creates an object that feature B trusts (e.g., attach someone else's file or draft to your record).
- **Business-rule inconsistencies:** two code paths implementing the same rule differently (web vs API, create vs update, import vs UI).

## Review questions
- Which invariant should hold (balance never negative, one coupon per user, only the owner approves)? Where is it enforced, and is it enforced on every path that changes the relevant state?
- Is the enforcement atomic (transaction, row lock, unique constraint, conditional update)?
- Which fields does the request bind, and which of them should never be client-writable?
- Can steps be skipped, repeated or reordered?

## False-positive traps
Invariant enforced by a database constraint or transaction you did not read; fields ignored by the persistence layer; races requiring unrealistic timing; features disabled by default.

## Variant ideas
Bulk/import endpoints skipping checks, admin-created objects reachable by users, update endpoints with weaker validation than create, API vs web parity, webhook handlers that trust payload values.
