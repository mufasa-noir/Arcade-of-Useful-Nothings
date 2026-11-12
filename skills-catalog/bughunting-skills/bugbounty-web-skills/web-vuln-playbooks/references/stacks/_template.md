# <Stack>: Source/Sink Catalog

Contents: sources, sinks by class, safe counterparts, sanitizer gotchas, authorization primitives, config/hardening pitfalls, grep seeds.

## Sources (attacker-controlled input)
- 

## Sinks by class
| class | sink / API | safe counterpart | notes |
|-------|------------|------------------|-------|

## Sanitizer and validator gotchas
- 

## Authorization primitives (what a correct check looks like; what common wrong checks look like)
- Authentication:
- Authorization (role/capability/policy):
- Object-level scoping:
- Default for a new route:
- Common wrong checks:

## Config and hardening pitfalls
- 

## Grep seeds (starting points; refine, then read the code)
```bash
rg -n '<pattern>' --glob '!vendor' --glob '!node_modules'
```
