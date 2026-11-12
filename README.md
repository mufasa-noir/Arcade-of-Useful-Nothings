# Arcade of Useful Nothings

A collection of practical agent skills and small security-analysis utilities. The repository brings together reusable workflows for reviewing web and Android code, inspecting source trees, and producing supporting reports.

## What's inside

### Agent skills

Skills are kept in [`skills-catalog/`](skills-catalog/) and documented in their own `SKILL.md` files:

- **Web source auditing** — [`bughunting-skills/`](skills-catalog/bughunting-skills/) contains a human-guided workflow and focused skills for mapping attack surfaces, tracing source-to-sink paths, reviewing authorization, triaging candidates, checking patch variants, and reporting verified findings. See its [README](skills-catalog/bughunting-skills/README.md) for workflow and setup details.
- **Android bug hunting** — [`android-bughunt-skillset/`](skills-catalog/android-bughunt-skillset/) provides a staged review pipeline for already-decompiled Android app sources.
- **Proof-of-concept building** — [`poc-builder/`](skills-catalog/poc-builder/) provides a checkpoint-based workflow for reproducing and documenting a supplied finding or CVE.
- **CV and resume building** — [`Cv builder-v1/`](skills-catalog/Cv%20builder-v1/) contains a skill for creating tailored CVs and resumes.

### Python utilities

The scripts in [`scripts/`](scripts/) run with Python 3 and use the standard library:

- **Argus** ([`argus.py`](scripts/argus.py)) crawls a web application, analyzes JavaScript and related resources, and writes JSON and Markdown reports.
- **Polyscan** ([`polyscan.py`](scripts/polyscan.py)) scans source or decompiled files for hardcoded secrets, weak cryptography, and other low-hanging security issues; it writes a Markdown report.

## Quick start

Check a script's available options:

```bash
python3 scripts/argus.py --help
python3 scripts/polyscan.py --help
```

Run Argus against an authorized web application:

```bash
python3 scripts/argus.py https://example.com -o example-report
```

This writes `example-report.json` and `example-report.md` in the current directory. For an authenticated application, credentials can be supplied with `--cookie`, `--token`, or `--header`; avoid putting sensitive values in shared shell history or reports.

Scan a local source tree with Polyscan:

```bash
python3 scripts/polyscan.py ./path/to/source -o findings.md
```

Use `--all` to scan all text files, or `--ext` to specify extensions.

## Responsible use

Only run network scans against systems you own or are explicitly authorized to test. Confirm scope and program rules before scanning; Argus makes HTTP requests, and its `--allow-destructive` option enables requests to URL paths that may change application state. Review scanner output manually before treating a result as a confirmed finding.

## Contributing

Keep each skill's instructions and supporting references alongside that skill. When adding a utility, document its purpose, usage, and safety considerations here.
