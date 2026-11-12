#!/usr/bin/env python3
"""
polyscan.py — Multi-language static scanner for hardcoded secrets,
weak cryptography, and other low-hanging security fruit.

Works line-by-line with regex, so it's language-agnostic: point it at C
source, decompiled Java/Smali from an APK, PHP, JS, Python, config files,
or a mixed pile of all of the above, and it will scan every file it
recognizes (or every text file, with --all).

Categories covered:
  - Hardcoded Credentials
  - API Keys & Tokens
  - Weak Cryptography & Hashing
  - Custom/Suspicious Encryption
  - Private Keys & Certificates
  - Hardcoded URLs & Endpoints
  - Revealing Developer Comments
  - Dangerous Functions (Injection Risks)
  - Debug/Insecure Configuration
  - High-Entropy Strings (generic catch-all for likely secrets)

Pure standard library. No dependencies to install.

Usage:
    python polyscan.py /path/to/source
    python polyscan.py /path/to/source -o report.md
    python polyscan.py /path/to/source --all              # scan every text file, not just known source extensions
    python polyscan.py decompiled_apk/ --ext .java .smali .xml
    python polyscan.py single_file.c
"""

import argparse
import math
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

__version__ = "1.0.0"

# --------------------------------------------------------------------------
# Banner
# --------------------------------------------------------------------------

BANNER_ART = r"""
______ _____ _   __   _______ _____   ___   _   _
| ___ \  _  | |  \ \ / /  ___/  __ \ / _ \ | \ | |
| |_/ / | | | |   \ V /\ `--.| /  \// /_\ \|  \| |
|  __/| | | | |    \ /  `--. \ |    |  _  || . ` |
| |   \ \_/ / |____| | /\__/ / \__/\| | | || |\  |
\_|    \___/\_____/\_/ \____/ \____/\_| |_/\_| \_/
""".strip("\n")


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


def print_banner():
    c = _color_enabled()
    red = "\033[91m" if c else ""
    dim = "\033[2m" if c else ""
    bold = "\033[1m" if c else ""
    reset = "\033[0m" if c else ""

    print(f"{red}{BANNER_ART}{reset}")
    print(f"{dim}  Multi-language static scanner for hardcoded secrets, weak crypto{reset}")
    print(f"{dim}  & other low-hanging security fruit{reset}   {bold}v{__version__}{reset}")
    print(f"{dim}  {'-' * 64}{reset}")


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULT_EXTENSIONS = {
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp",
    ".java", ".smali",
    ".js", ".jsx", ".ts", ".tsx", ".mjs",
    ".py", ".php", ".phtml",
    ".go", ".rb", ".swift", ".kt", ".kts", ".cs",
    ".rs", ".m", ".mm",
    ".xml", ".json", ".yaml", ".yml", ".properties", ".gradle",
    ".txt", ".ini", ".conf", ".cfg", ".env",
    ".sql", ".sh", ".asm", ".s",
}

EXCLUDED_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "venv", ".venv",
    "__pycache__", "build", "dist", "target", "bin", "obj",
    ".idea", ".vscode", ".gradle", "DerivedData",
}

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB — skip anything bigger (likely a blob/binary)
CONTEXT_CHARS = 160              # how much of the matched line to show in the report
MAX_LINE_LEN = 2000              # skip scanning minified/huge single lines (mostly noise)

# (category, finding name, severity, regex)
# severity: High / Medium / Low
RAW_PATTERNS = [
    # ---- Hardcoded Credentials ----------------------------------------
    ("Hardcoded Credentials", "Hardcoded password/pwd assignment", "High",
     r'(?i)\b(password|passwd|pwd)\s*[:=]\s*["\']([^"\'\n]{3,})["\']'),
    ("Hardcoded Credentials", "Hardcoded secret assignment", "High",
     r'(?i)\bsecret\s*[:=]\s*["\']([^"\'\n]{3,})["\']'),
    ("Hardcoded Credentials", "Basic auth credentials embedded in URL", "High",
     r'[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/"\'<>]+:[^\s/"\'<>@]+@'),
    ("Hardcoded Credentials", "DB connection string with embedded credentials", "High",
     r'(?i)(jdbc|mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis)://[^\s"\'<>]*:[^\s"\'<>]*@'),

    # ---- API Keys & Tokens ----------------------------------------------
    ("API Keys & Tokens", "Generic API key / token assignment", "High",
     r'(?i)\b(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*["\']([A-Za-z0-9_\-.]{12,})["\']'),
    ("API Keys & Tokens", "AWS Access Key ID", "High",
     r'\bAKIA[0-9A-Z]{16}\b'),
    ("API Keys & Tokens", "AWS Secret Access Key (likely)", "High",
     r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}["\']'),
    ("API Keys & Tokens", "Google API Key", "High",
     r'\bAIza[0-9A-Za-z\-_]{35}\b'),
    ("API Keys & Tokens", "Slack Token", "High",
     r'\bxox[baprs]-[0-9A-Za-z-]{10,}\b'),
    ("API Keys & Tokens", "GitHub Token", "High",
     r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'),
    ("API Keys & Tokens", "Stripe API Key", "High",
     r'\b(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b'),
    ("API Keys & Tokens", "JWT-looking token", "Medium",
     r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'),
    ("API Keys & Tokens", "Bearer token embedded in code", "Medium",
     r'(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}'),

    # ---- Weak Cryptography & Hashing -------------------------------------
    ("Weak Cryptography & Hashing", "MD5 usage", "Medium",
     r'(?i)\bmd5\s*\('),
    ("Weak Cryptography & Hashing", "SHA-1 usage", "Medium",
     r'(?i)\bsha-?1\b'),
    ("Weak Cryptography & Hashing", "DES / 3DES cipher usage", "High",
     r'\b(?:3)?DES(?:ede)?\b'),
    ("Weak Cryptography & Hashing", "RC4 cipher usage", "High",
     r'\bRC4\b'),
    ("Weak Cryptography & Hashing", "ECB cipher mode", "High",
     r'(?i)\bECB\b'),
    ("Weak Cryptography & Hashing", "Non-cryptographic PRNG used (check if used for security)", "Medium",
     r'\b(Math\.random\s*\(|java\.util\.Random\s*\(|rand\s*\(\s*\)|srand\s*\()'),
    ("Weak Cryptography & Hashing", "Fixed/all-zero crypto key or IV", "Medium",
     r'(?i)\b(iv|key)\s*=\s*["\'](?:0x)?0{8,}["\']'),

    # ---- Custom / Suspicious Encryption ----------------------------------
    ("Custom/Suspicious Encryption", "Custom cipher/encrypt/decrypt function", "Low",
     r'(?i)\b(?:custom|simple|my|basic)\w*(?:encrypt|decrypt|cipher)\w*\s*\('),
    ("Custom/Suspicious Encryption", "XOR-based obfuscation pattern", "Medium",
     r'(?i)\bxor\b[^\n]{0,40}\bkey\b|\^\s*(?:0x[0-9A-Fa-f]{1,2}|[A-Za-z_]\w*key\w*)\b'),
    ("Custom/Suspicious Encryption", "Base64 used alongside 'encrypt/secure' naming (false sense of crypto)", "Low",
     r'(?i)\b(?:encrypt|secure|protect)\w*.{0,40}\bbase64\b'),

    # ---- Private Keys & Certificates -------------------------------------
    ("Private Keys & Certificates", "Private key block embedded in source", "High",
     r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    ("Private Keys & Certificates", "PGP private key block embedded in source", "High",
     r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    ("Private Keys & Certificates", "Certificate embedded in source", "Low",
     r'-----BEGIN CERTIFICATE-----'),

    # ---- Hardcoded URLs & Endpoints ---------------------------------------
    ("Hardcoded URLs & Endpoints", "Hardcoded HTTP(S) URL", "Low",
     r'https?://[^\s"\'<>)]{4,}'),
    ("Hardcoded URLs & Endpoints", "Hardcoded IP address", "Low",
     r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b'),
    ("Hardcoded URLs & Endpoints", "Internal/staging/debug endpoint reference", "Low",
     r'(?i)\b(?:internal|staging|dev|debug|test)[-.][a-z0-9.\-]*\.[a-z]{2,}\b'),

    # ---- Revealing Developer Comments --------------------------------------
    ("Revealing Developer Comments", "TODO/FIXME/HACK/XXX/BUG marker", "Low",
     r'(?i)(?://|#|\*)\s*(?:TODO|FIXME|HACK|XXX|BUG)\b.*'),
    ("Revealing Developer Comments", "Comment referencing credentials/backdoor/debug bypass", "Medium",
     r'(?i)(?://|#).*\b(?:backdoor|bypass|debug\s*only|do not ship|remove before (?:release|prod)|temporary password|default (?:password|creds))\b.*'),

    # ---- Dangerous Functions (Injection Risks) -----------------------------
    ("Dangerous Functions (Injection Risks)", "C unsafe function (strcpy/sprintf/gets/strcat)", "Medium",
     r'\b(?:strcpy|strcat|sprintf|gets|vsprintf)\s*\('),
    ("Dangerous Functions (Injection Risks)", "Command execution call (system/exec/popen)", "High",
     r'\b(?:system|popen|execve|execl|shell_exec|proc_open)\s*\(|Runtime\.getRuntime\(\)\.exec\s*\('),
    ("Dangerous Functions (Injection Risks)", "eval()-style dynamic code execution", "High",
     r'\beval\s*\('),
    ("Dangerous Functions (Injection Risks)", "Deserialization of potentially untrusted data", "Medium",
     r'\b(?:unserialize|pickle\.loads|ObjectInputStream)\s*\('),
    ("Dangerous Functions (Injection Risks)", "SQL query built via string concatenation", "Medium",
     r'(?i)\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\n;]{0,120}["\'][^\n]{0,80}\+\s*\w+'),

    # ---- Debug / Insecure Configuration -------------------------------------
    ("Debug/Insecure Configuration", "Debug mode enabled", "Low",
     r'(?i)\bdebug\s*=\s*(?:true|1)\b'),
    ("Debug/Insecure Configuration", "TLS/SSL certificate verification disabled", "High",
     r'(?i)\b(?:verify|ssl[_-]?verify|CURLOPT_SSL_VERIFYPEER)\s*[:=]\s*(?:false|0)\b'),
    ("Debug/Insecure Configuration", "Wildcard CORS / overly permissive origin", "Medium",
     r'(?i)Access-Control-Allow-Origin["\']?\s*[:=]\s*["\']\*["\']'),
]

PATTERNS = [
    (category, name, severity, re.compile(pattern))
    for category, name, severity, pattern in RAW_PATTERNS
]

# Category display order in the report
CATEGORY_ORDER = [
    "Hardcoded Credentials",
    "API Keys & Tokens",
    "Weak Cryptography & Hashing",
    "Custom/Suspicious Encryption",
    "Private Keys & Certificates",
    "Hardcoded URLs & Endpoints",
    "Revealing Developer Comments",
    "Dangerous Functions (Injection Risks)",
    "Debug/Insecure Configuration",
    "High-Entropy Strings (Possible Secrets)",
]

SEVERITY_RANK = {"High": 2, "Medium": 1, "Low": 0}

# --------------------------------------------------------------------------
# Entropy-based generic secret detector (catches secrets that don't match
# any named pattern above — e.g. an oddly-named variable holding a token)
# --------------------------------------------------------------------------

ASSIGNMENT_STRING_RE = re.compile(
    r'(?i)\b([A-Za-z_][A-Za-z0-9_]{2,30})\s*[:=]\s*["\']([A-Za-z0-9+/_\-=]{20,})["\']'
)
# variable names that commonly hold long-but-boring strings (not secrets)
ENTROPY_IGNORE_NAME = re.compile(r'(?i)^(url|path|class|style|id|name|file|format|pattern|regex|version|message|msg|text|label|title)$')


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def find_high_entropy_strings(line: str):
    findings = []
    for m in ASSIGNMENT_STRING_RE.finditer(line):
        var_name, value = m.group(1), m.group(2)
        if ENTROPY_IGNORE_NAME.match(var_name):
            continue
        ent = shannon_entropy(value)
        if ent >= 4.0 and len(value) >= 20:
            findings.append(f"Variable '{var_name}' assigned a high-entropy string (entropy={ent:.1f}, len={len(value)})")
    return findings


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

def is_probably_binary(sample: bytes) -> bool:
    if b"\x00" in sample:
        return True
    text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
    nontext = sample.translate(None, bytes(text_chars))
    return len(nontext) / max(len(sample), 1) > 0.30


def iter_target_files(target: Path, extensions, scan_all: bool):
    if target.is_file():
        yield target
        return
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith(".")]
        for fname in files:
            fpath = Path(root) / fname
            if not scan_all and fpath.suffix.lower() not in extensions:
                continue
            yield fpath


def scan_file(fpath: Path, base: Path):
    try:
        size = fpath.stat().st_size
    except OSError:
        return []
    if size == 0 or size > MAX_FILE_SIZE:
        return []

    try:
        with open(fpath, "rb") as fh:
            sample = fh.read(4096)
    except OSError:
        return []
    if is_probably_binary(sample):
        return []

    try:
        text = fpath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    try:
        rel = fpath.relative_to(base)
    except ValueError:
        rel = fpath

    results = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > MAX_LINE_LEN:
            continue

        for category, name, severity, regex in PATTERNS:
            if regex.search(line):
                snippet = line.strip()
                if len(snippet) > CONTEXT_CHARS:
                    snippet = snippet[:CONTEXT_CHARS] + " …"
                results.append({
                    "category": category,
                    "pattern": name,
                    "severity": severity,
                    "file": str(rel),
                    "line": lineno,
                    "snippet": snippet,
                })

        for desc in find_high_entropy_strings(line):
            snippet = line.strip()
            if len(snippet) > CONTEXT_CHARS:
                snippet = snippet[:CONTEXT_CHARS] + " …"
            results.append({
                "category": "High-Entropy Strings (Possible Secrets)",
                "pattern": desc,
                "severity": "Medium",
                "file": str(rel),
                "line": lineno,
                "snippet": snippet,
            })
    return results


# --------------------------------------------------------------------------
# Report generation
# --------------------------------------------------------------------------

def md_escape(s: str) -> str:
    return s.replace("|", "\\|")


def build_report(all_findings, target: Path, files_scanned: int) -> str:
    by_category = defaultdict(list)
    for f in all_findings:
        by_category[f["category"]].append(f)

    total = len(all_findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append("# Static Analysis Findings Report")
    lines.append("")
    lines.append(f"- **Target:** `{target}`")
    lines.append(f"- **Generated:** {now}")
    lines.append(f"- **Files scanned:** {files_scanned}")
    lines.append(f"- **Total findings:** {total}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Category | Findings |")
    lines.append("|---|---|")
    for cat in CATEGORY_ORDER:
        count = len(by_category.get(cat, []))
        if count:
            lines.append(f"| {cat} | {count} |")
    lines.append("")

    if total == 0:
        lines.append("No findings.")
        return "\n".join(lines)

    for cat in CATEGORY_ORDER:
        findings = by_category.get(cat)
        if not findings:
            continue
        lines.append(f"## {cat} ({len(findings)})")
        lines.append("")
        by_pattern = defaultdict(list)
        for f in findings:
            by_pattern[(f["pattern"], f["severity"])].append(f)
        ordered = sorted(
            by_pattern.items(),
            key=lambda kv: (-SEVERITY_RANK[kv[0][1]], kv[0][0]),
        )
        for (pattern_name, severity), items in ordered:
            lines.append(f"### {pattern_name} — Severity: {severity} ({len(items)})")
            lines.append("")
            for it in items:
                lines.append(f"- `{it['file']}:{it['line']}`")
                lines.append("  ```")
                lines.append(f"  {md_escape(it['snippet'])}")
                lines.append("  ```")
            lines.append("")

    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Multi-language static scanner for hardcoded secrets, weak crypto, and other low-hanging security issues."
    )
    ap.add_argument("target", help="File or directory to scan (source code, decompiled output, etc.)")
    ap.add_argument("-o", "--output", default="findings.md", help="Output Markdown file (default: findings.md)")
    ap.add_argument("--all", action="store_true", help="Scan every text file, not just known source-code extensions")
    ap.add_argument("--ext", nargs="*", default=None, help="Override the list of file extensions to scan (e.g. --ext .c .h .java)")
    ap.add_argument("--no-banner", action="store_true", help="Suppress the startup banner (useful for scripts/CI)")
    args = ap.parse_args()

    if not args.no_banner:
        print_banner()

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"Error: target '{target}' does not exist", file=sys.stderr)
        sys.exit(1)

    extensions = {e.lower() for e in args.ext} if args.ext else DEFAULT_EXTENSIONS
    base = target if target.is_dir() else target.parent

    all_findings = []
    files_scanned = 0
    for fpath in iter_target_files(target, extensions, args.all):
        findings = scan_file(fpath, base)
        files_scanned += 1
        all_findings.extend(findings)

    report = build_report(all_findings, target, files_scanned)
    out_path = Path(args.output)
    out_path.write_text(report, encoding="utf-8")

    print(f"Scanned {files_scanned} file(s). Found {len(all_findings)} potential issue(s).")
    print(f"Report written to: {out_path.resolve()}")


if __name__ == "__main__":
    main()
