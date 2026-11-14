# Arcade of Useful Nothings

A collection of reusable agent skills and standalone Python tools for security analysis, job discovery, and sharing files across devices.

## What's inside

### Agent skills

Skills live in [`skills-catalog/`](skills-catalog/) and include their own `SKILL.md` instructions:

- **Web source auditing** — [`bughunting-skills/`](skills-catalog/bughunting-skills/) contains a human-guided workflow and focused skills for mapping attack surfaces, tracing source-to-sink paths, reviewing authorization, triaging candidates, checking patch variants, and reporting verified findings. See its [README](skills-catalog/bughunting-skills/README.md) for workflow and setup details.
- **Android bug hunting** — [`android-bughunt-skillset/`](skills-catalog/android-bughunt-skillset/) provides a staged review pipeline for already-decompiled Android app sources.
- **Proof-of-concept building** — [`poc-builder/`](skills-catalog/poc-builder/) provides a checkpoint-based workflow for reproducing and documenting a supplied finding or CVE.
- **CV and resume building** — [`Cv builder-v1/`](skills-catalog/Cv%20builder-v1/) contains a skill for creating tailored CVs and resumes.

### Python tools

- **Argus** ([`argus.py`](scripts/argus.py)) crawls an authorized web application, analyzes JavaScript and related resources, and writes JSON and Markdown reports.
- **Polyscan** ([`polyscan.py`](scripts/polyscan.py)) scans source or decompiled files for hardcoded secrets, weak cryptography, and other potential security issues; it writes a Markdown report.
- **Jobwatch** ([`jobwatch.py`](scripts/job-watcher/jobwatch.py)) checks configured job boards, feeds, forums, and career APIs for matching postings, then records new matches in Markdown.
- **Landrop** ([`landrop.py`](scripts/landrop.py)) serves a small browser interface for transferring files and text between devices on a local network.

## Requirements

The scripts require Python 3.10 or newer. Install dependencies only for the tools you plan to use:

```bash
# Argus
python3 -m pip install requests

# Jobwatch
python3 -m pip install -r scripts/job-watcher/requirements.txt

# Optional terminal QR code in Landrop
python3 -m pip install qrcode
```

Polyscan and Landrop otherwise use only the Python standard library.

## Quick start

Show command-line options:

```bash
python3 scripts/argus.py --help
python3 scripts/polyscan.py --help
python3 scripts/job-watcher/jobwatch.py --help
python3 scripts/landrop.py --help
```

### Argus

Run against a web application that you own or are authorized to test:

```bash
python3 scripts/argus.py https://example.com -o example-report
```

This writes `example-report.json` and `example-report.md` in the current directory. Supply authentication with `--cookie`, `--token`, or `--header` when needed. Argus is rate-limited by default; review its scope and options before scanning.

### Polyscan

Scan a local source tree or file:

```bash
python3 scripts/polyscan.py ./path/to/source -o findings.md
```

By default, Polyscan scans recognized source-file extensions. Use `--all` to include all text files or `--ext` to provide an extension list.

### Jobwatch

Check configured sources without writing output, then run a scan:

```bash
python3 scripts/job-watcher/jobwatch.py --config scripts/job-watcher/config.yaml --check
python3 scripts/job-watcher/jobwatch.py --config scripts/job-watcher/config.yaml
```

Use `--dry-run` to preview new matches, `--watch 15` to repeat every 15 minutes, or `--only RemoteOK` to check selected sources. Review [`config.yaml`](scripts/job-watcher/config.yaml) to set keywords, exclusions, sources, output and state paths, and optional `ntfy` notifications. The regional board entries currently use example URLs; replace them with real board URLs and tune their link patterns before relying on them. Output and state paths are relative to the config file.

### Landrop

Start a local file-sharing server:

```bash
python3 scripts/landrop.py --dir ./landrop-files --port 8000
```

Open the printed URL on another device on the same network. A random access token is generated for each run by default. Landrop uses plain HTTP, so use it only on a trusted network.

## Responsible use

Only run Argus against systems you own or are explicitly authorized to test. Confirm scope and program rules first; its `--allow-destructive` option enables requests to URL paths that may change application state. Polyscan results are leads for manual review, not confirmed vulnerabilities. Jobwatch fetches external sources and is configured to respect robots.txt for HTML scraping. Keep Landrop limited to trusted networks.

## Contributing

Keep each skill's instructions and supporting references alongside that skill. When adding a utility, document its purpose, usage, dependencies, and safety considerations here.
