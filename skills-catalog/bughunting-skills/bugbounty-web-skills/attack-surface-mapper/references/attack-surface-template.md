# attack-surface.md template

Use this exact structure.

```markdown
# Attack Surface: <target> @ <commit/tag>

## 1. Overview
- Languages / frameworks (versions):
- Request flow (one paragraph, with file:line anchors):
- Data stores / external services:
- Templating / rendering:
- Build / bundling / client code:
- Skip-list (not reviewed, and why):

## 2. Entry points
| ID | method | path / hook | handler file:line | params | intended principal (guess?) | visible auth check |
|----|--------|-------------|-------------------|--------|------------------------------|--------------------|
Total: N. Registration mechanisms found: <list>. Possible gaps in this inventory: <...>

## 3. Auth model
- Authentication mechanisms (file:line):
- Roles / capabilities and where defined:
- Where authorization is enforced (middleware / decorators / policies / in-handler):
- Default for a new route (default-allow or default-deny):
- Session / token handling notes (cookie flags, JWT algorithm and key source):
- Open questions for the human:

## 4. Trust boundaries and data flows worth knowing
<uploads, imports, webhooks, admin-authored content shown to users, user content shown to admins, cross-tenant surfaces, stored data that is later rendered or queried>

## 5. Dangerous capability inventory
| class | count | top locations (file:line, clustered) | notes |
|-------|-------|--------------------------------------|-------|
| raw SQL | | | |
| process execution | | | |
| filesystem (variable paths) | | | |
| outbound HTTP | | | |
| deserialization | | | |
| dynamic template / eval | | | |
| XML parsing | | | |
| redirects | | | |
| upload handling | | | |
| token / randomness | | | |

## 6. Secrets and dependencies
- Secrets found (type, location only):
- Dependencies with advisories that are reachable:

## 7. Git history signals
<commit hashes + one line each; for patch-variant-hunt>

## 8. Hot spots (ranked)
1. <area> (<file:line or R-ids>) - why:
2. ...

## 9. Could not determine / questions for the human
- ...
```
