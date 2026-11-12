#!/usr/bin/env python3
"""Argus - crawl a web app, mine its JavaScript, and flag low-hanging fruit.

Finds: endpoints, hardcoded creds/tokens/keys, weak or home-grown crypto,
developer comments, exposed source maps. Auth-aware: works out which endpoints
actually need a session, and asks for one if you didn't supply it.

Sends GET requests only. Use it on targets you are authorised to test.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import json
import math
import os
import random
import re
import sys
import threading
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from http.cookiejar import CookiePolicy
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse

try:
    import requests
    import urllib3
except ImportError:
    sys.exit("Argus needs requests:  pip install requests")

VERSION = "1.0.0"
MAX_BODY = 4_000_000
SEVERITIES = ["critical", "high", "medium", "low", "info"]

C = {"critical": "\033[1;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m",
     "info": "\033[90m", "ok": "\033[32m", "dim": "\033[90m", "b": "\033[1m", "x": "\033[0m"}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C = {k: "" for k in C}


_PRINT = threading.Lock()


def out(msg):
    with _PRINT:
        sys.stdout.write(msg + "\n")
        sys.stdout.flush()

BANNER = r"""
    _    ____   ____ _   _ ____
   / \  |  _ \ / ___| | | / ___|
  / _ \ | |_) | |  _| | | \___ \
 / ___ \|  _ <| |_| | |_| |___) |
/_/   \_\_| \_\\____|\___/|____/
"""


def print_banner():
    eyes = "(o)  " * 7
    out(f"\n{C['high']}{eyes.rstrip()}{C['x']}")
    for line in BANNER.strip("\n").splitlines():
        out(f"{C['b']}{line}{C['x']}")
    out(f"{C['high']}{eyes.rstrip()}{C['x']}")
    out(f"{C['dim']} the hundred-eyed web recon scanner  v{VERSION}")
    out(f" endpoints | JS | secrets | weak crypto | dev comments  -  GET-only, authorised targets only{C['x']}\n")


def rx(p, f=0):
    return re.compile(p, f)


# --------------------------------------------------------------------------- #
# Detection rules
# --------------------------------------------------------------------------- #
SECRET_RULES = [
    ("aws-access-key", "AWS access key ID", "high", rx(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16})\b")),
    ("aws-secret-key", "AWS secret access key", "critical",
     rx(r"""(?i)aws[\w .-]{0,25}?(?:secret|sk)[\w .-]{0,15}?['"=: ]+['"]?([A-Za-z0-9/+=]{40})['"]?""")),
    ("google-api-key", "Google API key", "medium", rx(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
    ("github-token", "GitHub token", "critical", rx(r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("gitlab-token", "GitLab personal access token", "critical", rx(r"\b(glpat-[A-Za-z0-9_\-]{20})\b")),
    ("slack-token", "Slack token", "high", rx(r"\b(xox[abprs]-[A-Za-z0-9-]{10,72})\b")),
    ("slack-webhook", "Slack webhook URL", "medium",
     rx(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)")),
    ("stripe-secret", "Stripe live secret key", "critical", rx(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b")),
    ("stripe-publishable", "Stripe publishable key", "info", rx(r"\b(pk_live_[0-9a-zA-Z]{24,})\b")),
    ("sendgrid-key", "SendGrid API key", "high", rx(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b")),
    ("mailgun-key", "Mailgun API key", "high", rx(r"\b(key-[0-9a-zA-Z]{32})\b")),
    ("twilio-key", "Twilio API key SID", "high", rx(r"\b(SK[0-9a-fA-F]{32})\b")),
    ("firebase-db", "Firebase database URL", "info", rx(r"\b(https://[a-z0-9-]+\.firebaseio\.com)\b")),
    ("private-key", "Private key block", "critical",
     rx(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)")),
    ("jwt", "JSON Web Token", "medium",
     rx(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_\-]*)\b")),
    ("creds-in-url", "Credentials embedded in URL", "high",
     rx(r"""[a-zA-Z][a-zA-Z0-9+.\-]{1,10}://([^/\s:@'"]{1,64}:[^/\s:@'"]{3,64})@[^/\s'"]+""")),
    ("hardcoded-auth-header", "Hardcoded Authorization header", "high",
     rx(r"""(?i)['"]?authorization['"]?\s*[:=]\s*['"`]\s*(?:bearer|basic|token)\s+([A-Za-z0-9._~+/=\-]{16,})['"`]""")),
    ("generic-secret", "Hardcoded credential / secret assignment", "high",
     rx(r"""(?i)(?<![\w.\-])['"]?([\w.\-]{0,40}(?:passw(?:or)?d|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|"""
        r"""auth[_-]?token|client[_-]?secret|private[_-]?key|token)[\w.\-]{0,40})['"]?\s*[:=]\s*['"]([^'"\s]{6,120})['"]""")),
]

INFO_RULES = [
    ("internal-ip", "Internal IP address", "low",
     rx(r"\b((?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3})\b")),
    ("email", "Email address", "info", rx(r"\b([A-Za-z0-9._%+-]{2,40}@[A-Za-z0-9-]{2,40}(?:\.[A-Za-z0-9-]{2,40}){1,3})\b")),
]

CRYPTO_RULES = [
    ("weak-hash-md5", "MD5 used", "medium",
     rx(r"""(?i)(?:CryptoJS\.MD5|\bmd5\s*\(|createHash\(\s*['"]md5['"]|hashlib\.md5|getInstance\(\s*['"]MD5['"]|digest\(\s*['"]MD5)"""),
     "MD5 is broken for passwords, signatures and integrity checks"),
    ("weak-hash-sha1", "SHA-1 used", "low",
     rx(r"""(?i)(?:CryptoJS\.SHA1|\bsha1\s*\(|createHash\(\s*['"]sha1['"]|hashlib\.sha1|digest\(\s*['"]SHA-1['"])"""),
     "SHA-1 is collision-prone; fine only for non-security uses"),
    ("weak-cipher", "Weak/legacy cipher (DES, 3DES, RC4, Blowfish, Rabbit)", "high",
     rx(r"""(?i)(?:CryptoJS\.(?:DES|TripleDES|RC4|RC4Drop|Rabbit)\b|createCipher(?:iv)?\(\s*['"](?:des|des3|des-ede3|rc4|bf|blowfish)[\w-]*['"]|\bnew\s+(?:DES|RC4|Blowfish)\()"""),
     "Legacy cipher with known practical weaknesses"),
    ("ecb-mode", "ECB block mode", "high",
     rx(r"(?i)(?:CryptoJS\.mode\.ECB|aes-\d{3}-ecb|/ECB/|MODE_ECB)"),
     "ECB leaks plaintext patterns and is malleable"),
    ("static-key", "Hardcoded encryption key in crypto call", "high",
     rx(r"""(?i)CryptoJS\.(?:AES|DES|TripleDES|Rabbit|RC4)\.(?:en|de)crypt\([^;]{0,200}?,\s*(?:CryptoJS\.enc\.\w+\.parse\()?\s*['"]([^'"]{4,64})['"]"""),
     "Anyone who reads the JS can decrypt/forge the data"),
    ("static-iv", "Hardcoded IV / salt / nonce", "medium",
     rx(r"""(?i)\b(?:iv|salt|nonce)\s*[:=]\s*(?:CryptoJS\.enc\.\w+\.parse\()?\s*['"]([A-Za-z0-9+/=]{8,64})['"]"""),
     "Static IV/salt/nonce defeats the purpose of using one"),
    ("insecure-random", "Math.random() feeding a security-sensitive value", "medium",
     rx(r"""(?i)\b\w*(?:token|secret|passw\w*|nonce|session\w*|csrf|otp|salt|apikey|api_key)\w*\s*[:=][^;\n]{0,80}Math\.random\(\)"""),
     "Math.random() is predictable; use crypto.getRandomValues()"),
    ("b64-as-crypto", "Base64 used where encryption/obfuscation is implied", "low",
     rx(r"""(?i)(?:passw|token|secret|cred|auth)\w*[^;\n]{0,40}\b(?:btoa|atob)\(|\b(?:btoa|atob)\([^)]{0,60}(?:passw|token|secret|cred)"""),
     "Base64 is encoding, not encryption"),
    ("tls-verify-off", "TLS certificate verification disabled", "medium",
     rx(r"(?i)(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|InsecureSkipVerify\s*:\s*true)"),
     "Enables MITM"),
    ("jwt-alg-none", "JWT 'none' algorithm referenced", "high",
     rx(r"""(?i)['"]alg['"]\s*:\s*['"]none['"]"""), "Check whether the server accepts unsigned tokens"),
    ("custom-xor", "Possible home-grown XOR cipher", "medium",
     rx(r"fromCharCode\([^)]{0,80}\^[^)]{0,80}\)|charCodeAt\([^)]{0,40}\)\s*\^\s*\w|\^\s*\w+\.charCodeAt\("),
     "Repeating-key XOR is trivially broken"),
    ("custom-hash", "Possible hand-rolled hash (djb2 / Java hashCode / FNV / murmur)", "low",
     rx(r"\(\s*\w+\s*<<\s*5\s*\)\s*[-+]\s*\w+|0x811c9dc5|\b16777619\b|0x5bd1e995|\*\s*33\s*\^"),
     "Non-cryptographic hash; check it is not used for passwords/tokens/signatures"),
    ("custom-crypto-name", "Function named like a custom crypto routine", "low",
     rx(r"""(?i)\b(?:function\s+|(?:const|let|var)\s+)((?:my|custom|simple|own|home|basic|easy|quick|secret)\w*(?:encrypt|decrypt|hash|cipher|scramble|obfuscat)\w*)\b"""),
     "Home-grown crypto is usually broken; read the implementation"),
    ("rot13", "ROT13 / Caesar-style transform", "low",
     rx(r"(?i)\brot-?13\b|fromCharCode\([^)]{0,60}\+\s*13\b"), "Obfuscation, not protection"),
]

LIB_HINT = rx(r"(?i)(jquery|bootstrap|lodash|underscore|moment|react(?:-dom)?\.|angular|vue(?:\.|-)|crypto-?js|polyfill|vendor|core-js|sentry|gtag|analytics)")
WEAK_CREDS = {"admin", "password", "passw0rd", "root", "toor", "test", "guest", "123456", "12345678", "qwerty",
              "letmein", "changeme", "default", "secret", "welcome", "pass", "user", "demo", "1234",
              "admin123", "password1", "password123"}
SKIP_NAME = rx(r"(?i)(csrf|xsrf|nonce|tokenizer|tokenize|token_?type|(?:url|uri|path|label|text|placeholder|message|msg|title|type|field|input|regex|pattern|length|policy|hint|error|expire\w*|expiry|lifetime|header|prefix|endpoint|route|param|storage|name)$)")
PLACEHOLDER = rx(r"(?i)^(?:undefined|null|true|false|none|string|number|object|function|text|x{4,}|\*{3,}|your[_-].*|example.*|placeholder.*)$|\$\{|\{\{|process\.env|^<|^%s$")

COMMENT_KW = rx(r"(?i)\b(todo|fixme|hack|xxx|bug|password|passwd|pwd|secret|token|api[_ -]?key|credentials?|creds?|admin|debug|temp(?:orary)?|"
                r"remove\s+(?:before|this|me)|internal|staging|backdoor|workaround|insecure|vulnerab\w*|hardcod\w*|deprecated|"
                r"test\s+(?:user|account|creds)|localhost|\bdev\b|prod(?:uction)?)\b|https?://(?:127\.|10\.|192\.168\.)")
CRED_KW = rx(r"(?i)(passw|secret|token|api[_ -]?key|cred|backdoor|private)")
JS_LINE_COMMENT = rx(r"(?<![:\w\"'`\\/])//(?![#@])\s?([^\n\r]{4,300})")
JS_BLOCK_COMMENT = rx(r"/\*(?![!*]\s*(?:@license|license))(.{4,600}?)\*/", re.S)
LICENSE_LIKE = rx(r"(?i)^\s*(?:@license|license|copyright|\(c\)|!|\*?\s*@preserve|sourceMappingURL)")

# --------------------------------------------------------------------------- #
# Endpoint / script extraction
# --------------------------------------------------------------------------- #
_U = r"""(?P<u>[^`'"\s]{1,300})"""
CALLSITES = [
    rx(r"""(?:fetch|axios|\$http|\$)\s*\(\s*[`'"]""" + _U + r"""[`'"]"""),
    rx(r"""(?:axios|\$http|http|\$|request|api|client|apiClient|this\.http)\.(?P<m>get|post|put|delete|patch|head|getJSON)\s*(?:<[^>]*>)?\s*\(\s*[`'"]""" + _U + r"""[`'"]""", re.I),
    rx(r"""\.open\(\s*['"](?P<m>[A-Za-z]+)['"]\s*,\s*[`'"]""" + _U + r"""[`'"]"""),
    rx(r"""\b(?:url|uri|endpoint|baseURL|baseUrl|apiUrl|API_URL|api_base|action|href)\s*[:=]\s*[`'"]""" + _U + r"""[`'"]"""),
]
_URLCH = r"""[^`'"\s<>\\]"""
STR_URL = rx(r"""[`'"]((?:https?:)?//[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}(?::\d+)?(?:/""" + _URLCH +
             r"""*)?|/[A-Za-z0-9_~%.\-]""" + _URLCH + r"""{1,250})[`'"]""")
JS_REF = rx(r"""[`'"]((?:https?:)?//[^`'"\s]+?\.m?js(?:\?[^`'"\s]*)?|[./]*[\w@~%\-./]+?\.m?js(?:\?[^`'"\s]*)?)[`'"]""")
SOURCEMAP = rx(r"[#@]\s*sourceMappingURL=([^\s'\"*]+)")
WEBPACK_CHUNK = rx(r"""["']((?:[\w\-./]+/)?)["']\s*\+\s*\(?[^+]{0,60}?\)?\s*\+\s*["']([.\-]?)["']\s*\+\s*(\{[^{}]{8,}\})\s*\[[^\]]+\]\s*\+\s*["'](\.chunk)?\.js["']""")
CHUNK_ITEM = rx(r"""(\w+|"[^"]+")\s*:\s*"([^"]+)\"""")
TEMPLATED = rx(r"\$\{|\{\{|\{[\w.]+\}|/:[A-Za-z_]\w*|<[\w:]+>|%7B|%24%7B")
NOISE_HOSTS = {"www.w3.org", "schema.org", "json-schema.org", "xmlpull.org", "ns.adobe.com", "purl.org",
               "reactjs.org", "fb.me", "git.io", "www.apple.com", "localhost"}
STATIC_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".woff", ".woff2", ".ttf", ".eot",
              ".otf", ".mp3", ".mp4", ".webm", ".avi", ".mov", ".zip", ".gz", ".tar", ".tgz", ".rar", ".7z",
              ".exe", ".dmg", ".css", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx")
DESTRUCTIVE = rx(r"(?i)(log[-_]?out|sign[-_]?out|delete|remove|destroy|unsubscribe|revoke|deactivate|purge|wipe)")

# Auth-wall detection
LOGIN_RX = rx(r"(?i)(log[-_]?in|sign[-_]?in|sso|oauth|authorize|/auth\b|saml|session/new|adfs|/cas/)")
UNAUTH_BODY = rx(r"(?i)\b(unauthori[sz]ed|unauthenticated|not\s+authenticated|authentication\s+(?:is\s+)?required|login\s+required|"
                 r"please\s+log\s*in|missing\s+(?:auth\w*|token)|invalid\s+(?:or\s+expired\s+)?(?:token|session|credentials)|"
                 r"token\s+(?:is\s+)?(?:required|missing|expired)|jwt\s+(?:expired|malformed|must\s+be\s+provided)|"
                 r"access\s+denied|forbidden)\b")
SESSION_NAME = rx(r"(?i)(sess|\bsid\b|auth|token|jwt|login|remember|sso)")
TOKEN_HEADERS = {"authorization", "x-auth-token", "x-access-token", "x-refresh-token", "refresh-token", "x-api-key",
                 "x-session-id", "x-jwt", "token", "x-csrf-token", "x-xsrf-token"}
DISCLOSURE_HEADERS = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")
PASSWORD_FORM = rx(r"""(?i)<input[^>]+type\s*=\s*['"]?password""")
REDIRECTS = (301, 302, 303, 307, 308)


# --------------------------------------------------------------------------- #
# Data classes and helpers
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    category: str
    url: str
    value: str
    evidence: str
    line: int = 0
    note: str = ""


@dataclass
class Endpoint:
    url: str
    methods: set = field(default_factory=set)
    sources: set = field(default_factory=set)
    params: set = field(default_factory=set)
    status: int | None = None
    content_type: str = ""
    size: int = 0
    auth: str = "untested"       # public | required | likely | optional | rejected | forbidden | unknown
    auth_reason: str = ""
    templated: bool = False
    skipped: str = ""
    depth: int = 0
    headers: dict = field(default_factory=dict)


@dataclass
class Resp:
    url: str
    status: int = 0
    headers: dict = field(default_factory=dict)
    text: str = ""
    ctype: str = ""
    size: int = 0
    chain: list = field(default_factory=list)
    error: str = ""


class _NoCookies(CookiePolicy):
    """We control auth explicitly; never let a jar leak a session between requests."""
    netscape, rfc2965, hide_cookie2 = True, False, False
    def set_ok(self, *a): return False
    def return_ok(self, *a): return False
    def domain_return_ok(self, *a): return False
    def path_return_ok(self, *a): return False


class Auth:
    def __init__(self):
        self.cookie = ""
        self.headers: dict[str, str] = {}

    @property
    def present(self):
        return bool(self.cookie or self.headers)

    def as_headers(self):
        h = dict(self.headers)
        if self.cookie:
            h["Cookie"] = self.cookie
        return h

    def ingest(self, raw: str) -> bool:
        raw = raw.strip()
        if not raw:
            return False
        if raw.lower().startswith("cookie:"):
            self.cookie = raw.split(":", 1)[1].strip()
        elif raw.lower().startswith("bearer "):
            self.headers["Authorization"] = raw
        elif re.fullmatch(r"eyJ[\w-]+\.[\w-]+\.[\w-]*", raw):
            self.headers["Authorization"] = "Bearer " + raw
        elif re.match(r"^[A-Za-z][\w-]*:\s*\S", raw):
            k, v = raw.split(":", 1)
            self.headers[k.strip()] = v.strip()
        elif "=" in raw:
            self.cookie = f"{self.cookie}; {raw}" if self.cookie else raw
        else:
            return False
        return True


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    return -sum(v / len(s) * math.log2(v / len(s)) for v in counts.values())


def key_of(u: str) -> str:
    p = urlparse(u)
    qs = sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)})
    return f"{p.scheme}://{p.netloc.lower()}{p.path or '/'}" + ("?" + "&".join(qs) if qs else "")


def norm(base: str, ref: str) -> str | None:
    ref = ref.strip()
    if not ref or ref.startswith(("javascript:", "mailto:", "tel:", "data:", "blob:", "#", "about:", "sms:")):
        return None
    try:
        u = urldefrag(urljoin(base, ref))[0]
    except ValueError:
        return None
    p = urlparse(u)
    return u if p.scheme in ("http", "https") and p.netloc else None


def plausible(s: str) -> bool:
    if not 3 <= len(s) <= 300:
        return False
    t = re.sub(r"\$\{[^}]*\}|\{[^}/]*\}", "X", s)
    if re.search(r"""[\s\\^|*<>()\[\]'"`;]""", t) or re.fullmatch(r"/[\w.-]{1,2}", t):
        return False
    if re.search(r"\.(?:png|jpe?g|gif|svg|ico|woff2?|ttf|eot|css|mp[34]|webp)(?:\?|$)", t, re.I):
        return False
    if t.startswith(("//", "http")):
        host = urlparse("http:" + t if t.startswith("//") else t).hostname or ""
        if host in NOISE_HOSTS or "." not in host:
            return False
    return True


def extract_endpoints(text: str):
    seen = set()
    for r in CALLSITES:
        for m in r.finditer(text):
            u, meth = m.group("u"), (m.groupdict().get("m") or "ANY").upper()
            meth = "GET" if meth == "GETJSON" else meth
            if plausible(u) or (not u.startswith(("/", "http", "//")) and "/" in u and plausible("/" + u)):
                if (u, meth) not in seen:
                    seen.add((u, meth))
                    yield u, meth
    for m in STR_URL.finditer(text):
        u = m.group(1)
        if plausible(u) and not any(u == s[0] for s in seen):
            seen.add((u, "ANY"))
            yield u, "ANY"


def chunk_names(text: str):
    for m in WEBPACK_CHUNK.finditer(text):
        prefix, sep, mp, suffix = m.group(1), m.group(2), m.group(3), m.group(4) or ""
        for k, v in CHUNK_ITEM.findall(mp)[:500]:
            yield f"{prefix}{k.strip(chr(34))}{sep}{v}{suffix}.js"


def kind_of(ctype: str, url: str) -> str:
    p = urlparse(url).path.lower()
    if p.endswith(".map"):
        return "map"
    if "javascript" in ctype or "ecmascript" in ctype or p.endswith((".js", ".mjs", ".jsx")):
        return "js"
    if "json" in ctype or p.endswith(".json"):
        return "json"
    if "html" in ctype:
        return "html"
    if "xml" in ctype or p.endswith(".xml"):
        return "xml"
    if ctype.startswith("text/") or p.endswith(".txt"):
        return "text"
    return "other"


def jwt_note(tok: str) -> tuple[str, str]:
    try:
        dec = lambda p: json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        h, p = (dec(x) for x in tok.split(".")[:2])
        bits = [f"alg={h.get('alg')}", "claims=" + ",".join(list(p)[:8])]
        if isinstance(p.get("exp"), (int, float)):
            bits.append("expires " + datetime.fromtimestamp(p["exp"], timezone.utc).strftime("%Y-%m-%d"))
        elif "exp" not in p:
            bits.append("no exp claim")
        return "; ".join(bits), str(h.get("alg", "")).lower()
    except Exception:
        return "", ""


def similar(a: str, b: str) -> bool:
    n = lambda t: re.sub(r"[0-9a-fA-F]{16,}|\d+", "#", t)
    na, nb = n(a), n(b)
    if na == nb:
        return True
    la, lb = len(na), len(nb)
    return bool(la and lb and abs(la - lb) / max(la, lb) < 0.03)


# --------------------------------------------------------------------------- #
# Auth classification: does this response mean "log in first"?
# --------------------------------------------------------------------------- #
def classify_auth(r: Resp, url: str) -> tuple[str, str]:
    if r.error or r.status == 0:
        return "unknown", r.error or "no response"
    req_is_login = bool(LOGIN_RX.search(urlparse(url).path))
    if r.status == 401:
        return "required", "401 Unauthorized" + (f" ({r.headers['WWW-Authenticate'][:40]})" if "WWW-Authenticate" in r.headers else "")
    if r.status == 429 or (r.status == 503 and "Retry-After" in r.headers):
        return "unknown", "rate limited; auth state not determined (lower --rps and re-run)"
    if r.status == 407:
        return "required", "407 Proxy Authentication Required"
    if r.status == 403:
        return "likely", "403 Forbidden (auth, authorization or WAF)"
    if r.chain and not req_is_login:
        for _, hop in r.chain:
            if LOGIN_RX.search(hop):
                return "required", f"redirected to login ({urlparse(hop).path or hop})"
    if r.status in REDIRECTS:
        loc = r.chain[-1][1] if r.chain else ""
        if LOGIN_RX.search(loc) and not req_is_login:
            return "required", f"redirected to IdP/login ({urlparse(loc).netloc})"
        return "public", f"{r.status} redirect"
    if r.status == 200 and r.text:
        if PASSWORD_FORM.search(r.text) and not req_is_login:
            return ("required", "login form served in place of content") if r.chain else \
                   ("likely", "login form served at a non-login URL")
        if "json" in r.ctype and len(r.text) < 600 and UNAUTH_BODY.search(r.text):
            return "required", "JSON body signals auth failure despite HTTP 200"
    if 400 <= r.status < 500 and UNAUTH_BODY.search(r.text[:600]):
        return "likely", f"{r.status} with auth-failure message"
    if r.status >= 500:
        return "unknown", f"HTTP {r.status}"
    return "public", "no auth wall detected"


def compare_auth(authed: Resp, anon: Resp, url: str) -> tuple[str, str]:
    a, ar = classify_auth(authed, url)
    n, nr = classify_auth(anon, url)
    if authed.status == 403:
        return "forbidden", "403 even with the session (authorization/WAF); may need a higher-privilege account"
    if a in ("required", "likely"):
        return "rejected", f"session rejected ({ar})"
    if n in ("required", "likely"):
        return "required", f"{nr}; reachable with supplied session"
    if a == "unknown":
        return "unknown", ar
    if authed.status == anon.status and similar(authed.text, anon.text):
        return "public", "same response with and without session"
    return "optional", "answers without auth but content differs with session"


# --------------------------------------------------------------------------- #
# Static analysis
# --------------------------------------------------------------------------- #
def snip(text, s, e, pad=70):
    return re.sub(r"\s+", " ", text[max(0, s - pad):min(len(text), e + pad)]).strip()


def judge_generic(m) -> tuple[str, str, str] | None:
    name, val = m.group(1), m.group(2)
    if SKIP_NAME.search(name) or PLACEHOLDER.search(val) or len(set(val)) <= 2:
        return None
    if val.startswith(("http", "/")) or re.fullmatch(r"[a-z]+(?:[_\-.][a-z]+)+|[A-Z_]+|[a-z]+(?:[A-Z][a-z]+)+", val):
        return None   # looks like an identifier/storage key/UI string, not a secret
    low = val.lower()
    if low in WEAK_CREDS:
        return "high", "default/weak credential", f"{name}={val}"
    ent = entropy(val)
    if ent >= 3.5 and len(val) >= 20:
        return "high", f"high-entropy value (entropy {ent:.1f})", f"{name}={val}"
    if val.isalpha():
        return "low", "alphabetic value; may be a UI string", f"{name}={val}"
    return "medium", f"entropy {ent:.1f}", f"{name}={val}"


class Analyzer:
    def __init__(self, all_comments=False):
        self.all_comments = all_comments

    def run(self, url, text, kind, html_comments=None, secrets=True):
        text = re.sub(r"data:[\w/+.\-]+;base64,[A-Za-z0-9+/=]{200,}", "data:<blob>", text[:MAX_BODY])
        out, lib = [], bool(LIB_HINT.search(url))

        if secrets:
            for rid, title, sev, r in SECRET_RULES + INFO_RULES:
                n = 0
                for m in r.finditer(text):
                    note, val = "", m.group(m.lastindex) if m.lastindex else m.group(0)
                    s2 = sev
                    if rid == "generic-secret":
                        j = judge_generic(m)
                        if not j:
                            continue
                        s2, note, val = j
                    elif rid == "jwt":
                        note, alg = jwt_note(val)
                        s2 = "high" if alg == "none" else sev
                    elif rid == "email":
                        tld = val.rsplit(".", 1)[-1].lower()
                        if not tld.isalpha() or tld in {"png", "jpg", "jpeg", "gif", "svg", "webp", "js", "css", "json", "map", "ico"}:
                            continue
                    cat = "info" if rid in ("internal-ip", "email", "firebase-db", "stripe-publishable") else "secret"
                    out.append(Finding(rid, title, s2, cat, url, val, snip(text, m.start(), m.end()),
                                       text.count("\n", 0, m.start()) + 1, note))
                    n += 1
                    if n >= 25:
                        break

        if kind == "js":
            for rid, title, sev, r, why in CRYPTO_RULES:
                n = 0
                for m in r.finditer(text):
                    val = m.group(m.lastindex) if m.lastindex else m.group(0)
                    s2, note = ("info", why + " (likely bundled third-party library)") if lib else (sev, why)
                    out.append(Finding(rid, title, s2, "crypto", url, val[:120], snip(text, m.start(), m.end()),
                                       text.count("\n", 0, m.start()) + 1, note))
                    n += 1
                    if n >= 10:
                        break

        comments = []
        if kind == "html" and html_comments:
            comments = [(c, 0) for c in html_comments]
        elif kind == "js":
            minified = len(text) / (text.count("\n") + 1) > 500
            pats = [JS_BLOCK_COMMENT] + ([] if minified else [JS_LINE_COMMENT])
            comments = [(m.group(1), text.count("\n", 0, m.start()) + 1) for p in pats for m in p.finditer(text)]
        n = 0
        for c, line in comments:
            c = re.sub(r"\s+", " ", c).strip()
            if len(c) < 4 or LICENSE_LIKE.match(c) or re.match(r"(?i)\[if |<!\[endif", c):
                continue
            if not (self.all_comments or COMMENT_KW.search(c)):
                continue
            out.append(Finding("dev-comment", "Developer comment", "medium" if CRED_KW.search(c) else "low",
                               "comment", url, c[:250], c[:250], line))
            n += 1
            if n >= 40:
                break
        return out


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.scripts, self.inline, self.comments, self.forms = [], [], [], [], []
        self._form, self._in_script, self._buf = None, False, []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag in ("a", "area") and a.get("href"):
            self.links.append(a["href"])
        elif tag == "link" and a.get("href"):
            rel = a.get("rel", "").lower()
            if a.get("as") == "script" or "modulepreload" in rel:
                self.scripts.append(a["href"])
            elif "stylesheet" not in rel and "icon" not in rel:
                self.links.append(a["href"])
        elif tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self._in_script, self._buf = True, []
        elif tag in ("iframe", "frame", "embed") and a.get("src"):
            self.links.append(a["src"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "get").upper(), "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None:
            self._form["inputs"].append({"name": a.get("name", ""), "type": a.get("type", tag)})
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""), re.I)
            if m:
                self.links.append(m.group(1))
        for k in ("data-url", "data-href", "data-src", "data-endpoint", "data-api"):
            if a.get(k):
                self.links.append(a[k])

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self.inline.append("".join(self._buf))
            self._in_script = False
        elif tag == "form":
            self._form = None

    def handle_data(self, d):
        if self._in_script:
            self._buf.append(d)

    def handle_comment(self, d):
        self.comments.append(d)


# --------------------------------------------------------------------------- #
# Rate control
# --------------------------------------------------------------------------- #
def parse_retry_after(v):
    if not v:
        return None
    try:
        return min(float(v), 120.0)
    except ValueError:
        try:
            return max(0.0, min((parsedate_to_datetime(v) - datetime.now(timezone.utc)).total_seconds(), 120.0))
        except Exception:
            return None


class Throttle:
    """Global, adaptive request pacer shared by every thread.

    - Spaces requests at `rps` (with a little jitter so traffic isn't metronomic).
    - On 429 / 503+Retry-After: halves the rate and pauses ALL threads (honours Retry-After,
      otherwise exponential backoff up to 60s).
    - After a run of clean responses it speeds back up, never beyond the configured rps.
    """
    def __init__(self, rps: float, floor: float = 0.2):
        self.max_rps = self.rps = max(rps, floor)
        self.floor = floor
        self.lock = threading.Lock()
        self.next_at = self.pause_until = 0.0
        self.consecutive = self.ok_streak = self.total_hits = 0

    def wait(self):
        with self.lock:
            now = time.monotonic()
            t = max(self.next_at, self.pause_until, now)
            self.next_at = t + random.uniform(0.9, 1.3) / self.rps
        if t > now:
            time.sleep(t - now)

    def penalize(self, retry_after=None) -> float:
        with self.lock:
            self.total_hits += 1
            self.consecutive += 1
            self.ok_streak = 0
            self.rps = max(self.floor, self.rps / 2)
            pause = retry_after if retry_after is not None else min(60.0, 2.0 ** self.consecutive)
            self.pause_until = max(self.pause_until, time.monotonic() + pause)
            return pause

    def success(self):
        with self.lock:
            self.consecutive = 0
            self.ok_streak += 1
            if self.ok_streak >= 25 and self.rps < self.max_rps:
                self.rps = min(self.max_rps, self.rps * 1.25)
                self.ok_streak = 0


# --------------------------------------------------------------------------- #
# The crawler
# --------------------------------------------------------------------------- #
class Argus:
    def __init__(self, a):
        self.a = a
        self.root = a.url
        p = urlparse(self.root)
        self.host = (p.hostname or "").lower()
        self.hosts = {self.host} | {h.lower() for h in (a.scope or [])}
        self.base_domain = self.host[4:] if self.host.startswith("www.") else self.host
        self.auth = Auth()
        for c in a.cookie:
            self.auth.ingest(c if "=" in c else "Cookie: " + c)
        if a.token:
            self.auth.ingest(a.token if a.token.lower().startswith("bearer ") else "Bearer " + a.token)
        for h in a.header:
            self.auth.ingest(h)
        self.extra = {"User-Agent": a.user_agent or f"Argus/{VERSION}", "Accept": "*/*"}
        self.lock = threading.RLock()
        self.local = threading.local()
        self.endpoints: dict[str, Endpoint] = {}
        self.findings: dict[tuple, Finding] = {}
        self.forms, self.errors = [], []
        self.cookies: dict[tuple, dict] = {}
        self.tokens: list[dict] = []
        self.hdr_hosts: set[str] = set()
        self.external = defaultdict(int)
        self.queued, self.gated = set(), set()
        self.queue: list[tuple] = []
        self.js_count = self.rejected = self.prompts = self.requests = 0
        self.declined = False
        rps = a.rps if a.delay <= 0 else min(a.rps, 1.0 / a.delay)
        self.throttle = Throttle(rps)
        self.blocked = False
        self.analyzer = Analyzer(a.all_comments)
        if a.insecure:
            urllib3.disable_warnings()

    # ---- output ---------------------------------------------------------- #
    def say(self, msg):
        if not self.a.quiet:
            out(msg)

    def log_fetch(self, status, state, url):
        col = {"public": C["ok"], "required": C["high"], "likely": C["medium"], "rejected": C["high"],
               "optional": C["low"], "forbidden": C["medium"]}.get(state, C["dim"])
        self.say(f"{C['dim']}[{status or 'ERR'}]{C['x']} {col}{state:<8}{C['x']} {url}")

    # ---- scope / http ---------------------------------------------------- #
    def in_scope(self, url):
        h = (urlparse(url).hostname or "").lower()
        return h in self.hosts or (self.a.subdomains and h.endswith("." + self.base_domain))

    def session(self):
        s = getattr(self.local, "s", None)
        if s is None:
            s = requests.Session()
            s.cookies.set_policy(_NoCookies())
            ad = requests.adapters.HTTPAdapter(pool_connections=4, pool_maxsize=4, max_retries=1)
            s.mount("http://", ad)
            s.mount("https://", ad)
            self.local.s = s
        return s

    def fetch(self, url, use_auth) -> Resp:
        s, cur, chain = self.session(), url, []
        for _ in range(6):
            headers = dict(self.extra)
            if use_auth and self.in_scope(cur):          # never send creds off-scope
                headers.update(self.auth.as_headers())
            try:
                for attempt in range(self.a.retries + 1):
                    if self.blocked:
                        return Resp(cur, error="stopped: target keeps rate-limiting us", chain=chain)
                    self.throttle.wait()
                    with self.lock:
                        self.requests += 1
                    r = s.get(cur, headers=headers, timeout=self.a.timeout, verify=not self.a.insecure,
                              allow_redirects=False, stream=True)
                    if r.status_code == 429 or (r.status_code == 503 and "Retry-After" in r.headers):
                        pause = self.throttle.penalize(parse_retry_after(r.headers.get("Retry-After")))
                        self.say(f"{C['medium']}[rate]{C['x']} {r.status_code} from {urlparse(cur).netloc} - "
                                 f"pausing {pause:.0f}s, now {self.throttle.rps:.1f} req/s "
                                 f"(retry {attempt + 1}/{self.a.retries})")
                        if self.throttle.consecutive >= 8:
                            self.blocked = True
                        if attempt < self.a.retries and not self.blocked:
                            r.close()
                            continue
                    else:
                        self.throttle.success()
                    break
            except requests.RequestException as e:
                return Resp(cur, error=type(e).__name__ + ": " + str(e)[:120], chain=chain)
            hdrs = dict(r.headers)
            rh = getattr(r.raw, "headers", None)
            cookies = rh.getlist("Set-Cookie") if hasattr(rh, "getlist") else ([hdrs["Set-Cookie"]] if "Set-Cookie" in hdrs else [])
            self.mine_headers(cur, hdrs, cookies)
            if r.status_code in REDIRECTS and r.headers.get("Location"):
                nxt = urljoin(cur, r.headers["Location"])
                chain.append((r.status_code, nxt))
                r.close()
                if self.in_scope(nxt):
                    cur = nxt
                    continue
                return Resp(cur, r.status_code, dict(r.headers), "", "", 0, chain)
            raw, n = [], 0
            for c in r.iter_content(65536):
                raw.append(c)
                n += len(c)
                if n >= MAX_BODY:
                    break
            r.close()
            body = b"".join(raw)
            ctype = r.headers.get("Content-Type", "").split(";")[0].strip().lower()
            texty = kind_of(ctype, cur) != "other"
            text = ""
            if texty:
                try:
                    text = body.decode("utf-8")
                except UnicodeDecodeError:
                    text = body.decode(r.encoding or "latin-1", "replace")
            return Resp(cur, r.status_code, dict(r.headers), text, ctype, len(body), chain)
        return Resp(cur, status=310, chain=chain, error="too many redirects")

    # ---- response headers, cookies, tokens ------------------------------- #
    def mine_headers(self, url, h, cookies):
        if not self.in_scope(url):
            return
        host = urlparse(url).netloc
        low = {k.lower(): v for k, v in h.items()}

        def add(rule, title, sev, cat, value, note="", once=False):
            if once:                       # server-wide facts: report once per host, not once per URL
                with self.lock:
                    if (host, rule, value) in self.hdr_hosts:
                        return
                    self.hdr_hosts.add((host, rule, value))
            self.add_finding(Finding(rule, title, sev, cat, url, value[:200], f"{rule}: {value}"[:250], 0, note))

        for raw in cookies:
            name, _, rest = raw.partition("=")
            value, _, attrs = rest.partition(";")
            name, value, al = name.strip(), value.strip(), attrs.lower()
            ss = re.search(r"samesite\s*=\s*(\w+)", al)
            info = {"name": name, "value": value, "host": host, "url": url, "attrs": attrs.strip(),
                    "httponly": "httponly" in al, "secure": "secure" in al, "samesite": ss.group(1) if ss else None}
            with self.lock:
                fresh = (host, name) not in self.cookies
                self.cookies.setdefault((host, name), info)
            if not fresh:
                continue
            if SESSION_NAME.search(name):
                if not info["httponly"]:
                    add("cookie-no-httponly", f"Session-like cookie '{name}' lacks HttpOnly", "medium", "cookie", name,
                        "readable from JS, so any XSS can steal it")
                if not info["secure"] and url.startswith("https://"):
                    add("cookie-no-secure", f"Session-like cookie '{name}' lacks Secure", "medium", "cookie", name,
                        "can be sent over plain HTTP")
                if not info["samesite"]:
                    add("cookie-no-samesite", f"Session-like cookie '{name}' has no SameSite", "low", "cookie", name,
                        "relies on browser default for CSRF protection")
            for f in self.analyzer.run(f"{url} (Set-Cookie {name})", value, "text"):
                self.add_finding(f)

        for k, v in low.items():
            if k in TOKEN_HEADERS and v:
                with self.lock:
                    new = not any(t["header"] == k and t["value"] == v and t["host"] == host for t in self.tokens)
                    if new:
                        self.tokens.append({"header": k, "value": v, "host": host, "url": url})
                if new:
                    csrf = "csrf" in k or "xsrf" in k
                    add("token-in-header", f"Token set in '{k}' response header", "info" if csrf else "medium", "token", v)
                    for f in self.analyzer.run(f"{url} (header {k})", v, "text"):
                        self.add_finding(f)
            elif k in DISCLOSURE_HEADERS:
                add("tech-disclosure", f"'{k}' discloses the stack", "low", "header", v, "fingerprinting aid", once=True)
        if re.search(r"\d+\.\d+", low.get("server", "")):
            add("server-version", "Server header discloses a version", "low", "header", low["server"], "check it against known CVEs", once=True)
        if "x-debug-token" in low or "x-debug-token-link" in low:
            add("debug-header", "Debug profiler header exposed", "medium", "header",
                low.get("x-debug-token-link") or low["x-debug-token"], "profiler pages often leak config and requests", once=True)
        acao, acac = low.get("access-control-allow-origin", ""), low.get("access-control-allow-credentials", "").lower()
        if acao == "null":
            add("cors-null-origin", "CORS allows the 'null' origin", "medium", "header", f"ACAO: {acao}", "sandboxed iframes can read responses")
        elif acao == "*" and acac == "true":
            add("cors-wildcard-credentials", "CORS wildcard with credentials header", "medium", "header",
                "ACAO: * + ACAC: true", "invalid combo that signals a sloppy CORS config; test origin reflection manually")
        for m in re.finditer(r"<([^>]+)>\s*;[^,]*rel=\"?(?:preload|prefetch|modulepreload|next|prev)", low.get("link", "")):
            self.ref(url, m.group(1), f"Link header @ {url}", 1)
        sm = low.get("sourcemap") or low.get("x-sourcemap")
        if sm:
            self.ref(url, sm, f"SourceMap header @ {url}", 1, kind="script")

    def check_security_headers(self, resp):
        host = urlparse(resp.url).netloc
        low = {k.lower(): v for k, v in resp.headers.items()}
        with self.lock:
            if host in self.hdr_hosts:
                return
            self.hdr_hosts.add(host)
        csp, miss = low.get("content-security-policy", ""), []
        if resp.url.startswith("https://") and "strict-transport-security" not in low:
            miss.append(("hsts", "Strict-Transport-Security"))
        if not csp:
            miss.append(("csp", "Content-Security-Policy"))
        if "x-frame-options" not in low and "frame-ancestors" not in csp:
            miss.append(("clickjacking", "X-Frame-Options / frame-ancestors"))
        if low.get("x-content-type-options", "").lower() != "nosniff":
            miss.append(("nosniff", "X-Content-Type-Options"))
        for rid, name in miss:
            self.add_finding(Finding(f"missing-{rid}", f"Missing {name}", "info", "header", resp.url, name, name, 0,
                                     "checked once per host; usually low impact alone"))

    # ---- discovery ------------------------------------------------------- #
    def discover(self, url, src, depth, method="ANY", kind="page", templated=False):
        key, path = key_of(url), urlparse(url).path.lower()
        with self.lock:
            ep = self.endpoints.get(key)
            if ep is None:
                ep = self.endpoints[key] = Endpoint(url=url, depth=depth, templated=templated)
            ep.methods.add(method)
            ep.sources.add(src)
            ep.params.update(k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True))
            if key in self.queued or ep.templated or ep.skipped or method not in ("GET", "ANY"):
                return
            if not self.in_scope(url):
                self.external[urlparse(url).netloc] += 1
                if not (kind == "script" and self.a.third_party_js):
                    ep.skipped = "out of scope"
                    return
            if path.endswith(STATIC_EXT):
                ep.skipped = "static asset"
                return
            if not self.a.allow_destructive and DESTRUCTIVE.search(path):
                ep.skipped = "skipped: looks state-changing (--allow-destructive)"
                return
            if kind in ("script", "guess"):
                if self.js_count >= self.a.max_js:
                    ep.skipped = "max-js reached"
                    return
                self.js_count += 1
            elif depth > self.a.depth:
                ep.skipped = "beyond --depth"
                return
            if len(self.queued) >= self.a.max_pages:
                ep.skipped = "max-pages reached"
                return
            self.queued.add(key)
            self.queue.append((url, depth, kind))

    def ref(self, base, raw, src, depth, method="ANY", kind="page"):
        u = norm(base, raw)
        if u:
            self.discover(u, src, depth, method, kind, bool(TEMPLATED.search(raw)))

    def add_finding(self, f: Finding):
        k = (f.rule, f.value, f.url)
        with self.lock:
            if k in self.findings:
                return
            self.findings[k] = f
        if f.severity in ("critical", "high"):
            self.say(f"  {C[f.severity]} {f.severity.upper()} {C['x']} {f.title}: {f.value[:70]}  {C['dim']}{f.url[:90]}{C['x']}")

    # ---- mining ---------------------------------------------------------- #
    def mine_text(self, url, text, ck, depth, refs=True, secrets=True):
        for f in self.analyzer.run(url, text, "js" if ck == "js" else ck, secrets=secrets):
            self.add_finding(f)
        for raw, meth in extract_endpoints(text):
            self.ref(self.root, raw, url, depth + 1, meth, "api")
        if ck == "js" and refs:
            self.mine_js_refs(url, text, depth)
        if url.lower().endswith("robots.txt"):
            for m in re.finditer(r"(?im)^\s*(?:allow|disallow|sitemap)\s*:\s*(\S+)", text):
                self.ref(url, re.split(r"[*$]", m.group(1))[0], "robots.txt", depth + 1)
        if ck == "xml":
            for m in list(re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", text))[:500]:
                self.ref(url, m.group(1), "sitemap", depth + 1)

    def mine_js_refs(self, url, text, depth):
        for n, m in enumerate(JS_REF.finditer(text)):
            if n >= 120:
                break
            r = m.group(1)
            self.ref(url if r.startswith(("./", "../")) else self.root, r, url, depth, kind="script")
        if self.a.guess:
            for name in chunk_names(text):
                for pre in ("/", "/_next/") if "chunks" in name else ("/",):
                    self.ref(self.root, pre + name, url, depth, kind="guess")
        sm = SOURCEMAP.search(text[-3000:])
        if sm and sm.group(1).startswith("data:"):
            head, _, b64 = sm.group(1).partition(",")
            if "base64" in head:
                try:
                    self.mine_map(url + " (inline sourcemap)", base64.b64decode(b64).decode("utf-8", "replace"), depth)
                except Exception:
                    pass
        elif sm:
            self.ref(url, sm.group(1), url, depth, kind="script")
        elif self.a.guess and self.in_scope(url) and not url.split("?")[0].endswith(".map"):
            self.ref(url, urlparse(url).path.rsplit("/", 1)[-1] + ".map", f"guess:{url}", depth, kind="guess")

    def mine_map(self, url, text, depth) -> bool:
        try:
            m = json.loads(text)
            srcs, cont = m.get("sources", []), m.get("sourcesContent") or []
        except (ValueError, AttributeError):
            return False
        self.add_finding(Finding("sourcemap-exposed", "Source map exposes original source", "medium", "info", url,
                                 f"{len(srcs)} source files", ", ".join(srcs[:25]),
                                 note="Original source, internal paths and comments are readable"))
        for i, s in enumerate(srcs):
            if i < len(cont) and cont[i] and "node_modules" not in s:
                self.mine_text(f"{url}!/{s.lstrip('./')}", cont[i], "js", depth, refs=False)
        return True

    def mine_html(self, resp, depth):
        url, p = resp.url, PageParser()
        try:
            p.feed(resp.text)
            p.close()
        except Exception:
            pass
        for f in self.analyzer.run(url, resp.text, "html", html_comments=p.comments):
            self.add_finding(f)
        for href in p.links:
            self.ref(url, href, url, depth + 1)
        for src in p.scripts:
            self.ref(url, src, url, depth, kind="script")
        for i, code in enumerate(p.inline, 1):
            if code.strip():
                self.mine_text(f"{url}#inline-{i}", code, "js", depth, secrets=False)
        for fm in p.forms:
            act = norm(url, fm["action"] or url)
            if not act:
                continue
            with self.lock:
                self.forms.append({"page": url, "action": act, "method": fm["method"], "inputs": fm["inputs"]})
            if act.startswith("http://") and any(i["type"] == "password" for i in fm["inputs"]):
                self.add_finding(Finding("password-over-http", "Password form submits over plain HTTP", "medium",
                                         "info", url, act, act))
            self.ref(url, fm["action"] or url, f"form@{url}", depth + 1, fm["method"] if fm["method"] in ("GET", "POST") else "GET")

    # ---- per-URL work ---------------------------------------------------- #
    def process(self, item):
        url, depth, kind = item
        key = key_of(url)
        use_auth = self.auth.present
        resp = self.fetch(url, use_auth)
        anon = self.fetch(url, False) if (use_auth and self.a.baseline and not resp.error and kind != "guess") else None
        ep = self.endpoints[key]
        if resp.error:
            ep.skipped = f"error: {resp.error}"
            self.log_fetch(0, "error", url)
            return
        ck = kind_of(resp.ctype, resp.url)
        if kind == "guess" and (resp.status != 200 or ck not in ("js", "map") or
                                (ck == "js" and resp.text.lstrip()[:15].lower().startswith(("<!doctype", "<html")))):
            with self.lock:
                self.endpoints.pop(key, None)
            return
        ep.status, ep.content_type, ep.size, ep.headers = resp.status, resp.ctype, resp.size, resp.headers
        if anon is not None and not anon.error:
            state, reason = compare_auth(resp, anon, url)
        else:
            state, reason = classify_auth(resp, url)
            if use_auth and resp.status == 403:
                state, reason = "forbidden", "403 even with the session (authorization/WAF)"
            elif use_auth and state in ("required", "likely"):
                state, reason = "rejected", f"session rejected ({reason})"
        ep.auth, ep.auth_reason = state, reason
        with self.lock:
            if state in ("required", "likely", "rejected"):
                self.gated.add(key)
                self.rejected += state == "rejected"
            else:
                self.gated.discard(key)
        self.log_fetch(resp.status, state, url)

        if ck == "html":
            if resp.status == 200:
                self.check_security_headers(resp)
            self.mine_html(resp, depth)
        elif ck == "map":
            if not self.mine_map(resp.url, resp.text, depth) and kind == "guess":
                with self.lock:
                    self.endpoints.pop(key, None)
        elif ck in ("js", "json", "xml", "text") and resp.text:
            self.mine_text(resp.url, resp.text, ck, depth)

    def safe_process(self, item):
        if self.blocked:
            return
        try:
            self.process(item)
        except Exception as e:      # one bad page must not kill the crawl
            with self.lock:
                self.errors.append(f"{item[0]}: {type(e).__name__}: {e}")

    # ---- the smart auth bit ---------------------------------------------- #
    def maybe_prompt(self) -> bool:
        if self.blocked or self.a.no_prompt or self.declined or self.prompts >= 3 or not sys.stdin.isatty():
            return False
        with self.lock:
            gated = [k for k in self.gated if k in self.endpoints]
        have = self.auth.present
        if not gated or (have and self.rejected < 3):
            return False
        print(f"\n{C['b']}[auth]{C['x']} " + (
            f"The supplied session was rejected by {len(gated)} endpoint(s) - it may have expired."
            if have else f"{len(gated)} endpoint(s) appear to require authentication:"))
        for k in gated[:8]:
            e = self.endpoints[k]
            print(f"   {C['dim']}{e.status}{C['x']} {e.url}  {C['dim']}({e.auth_reason}){C['x']}")
        if len(gated) > 8:
            print(f"   ... and {len(gated) - 8} more")
        print("Paste a cookie string (a=b; c=d), a token, or 'Header: value'. One per line; blank line to finish.")
        print("Leave empty to continue without authentication.")
        new = Auth()
        while True:
            try:
                line = input("auth> ")
            except EOFError:
                break
            if not line.strip():
                break
            if not new.ingest(line):
                print("   couldn't parse that - expected a cookie string, JWT, or 'Header: value'")
        if not new.present:
            self.declined = True
            print("Continuing without authentication.\n")
            return False
        self.auth, self.prompts, self.rejected = new, self.prompts + 1, 0
        with self.lock:
            for k in gated:
                self.queue.append((self.endpoints[k].url, self.endpoints[k].depth, "page"))
            self.gated.clear()
        print("Re-testing gated endpoints with the new session...\n")
        return True

    def crawl(self):
        self.discover(self.root, "seed", 0)
        o = urlparse(self.root)
        for path in ("/robots.txt", "/sitemap.xml"):
            self.discover(f"{o.scheme}://{o.netloc}{path}", "seed", 0)
        while True:
            while self.queue:
                with self.lock:
                    batch, self.queue = self.queue, []
                with cf.ThreadPoolExecutor(self.a.threads) as ex:
                    list(ex.map(self.safe_process, batch))
            if not self.maybe_prompt():
                break


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _json_default(o):
    return sorted(o) if isinstance(o, set) else str(o)


def build_report(ar: Argus, started: str):
    fs = sorted(ar.findings.values(), key=lambda f: (SEVERITIES.index(f.severity), f.category, f.url))
    eps = sorted(ar.endpoints.values(), key=lambda e: (e.auth != "required", e.url))
    return {
        "tool": f"argus {VERSION}", "target": ar.root, "started": started,
        "finished": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "stats": {"requests": ar.requests, "endpoints": len(eps), "findings": len(fs),
                  "auth_required": sum(e.auth == "required" for e in eps),
                  "cookies": len(ar.cookies), "token_headers": len(ar.tokens),
                  "rate_limit_hits": ar.throttle.total_hits, "stopped_early": ar.blocked,
                  "authenticated_scan": ar.auth.present},
        "findings": [asdict(f) for f in fs],
        "endpoints": [{k: (sorted(v) if isinstance(v, set) else v) for k, v in asdict(e).items()} for e in eps],
        "cookies": sorted(ar.cookies.values(), key=lambda c: (c["host"], c["name"])), "tokens": ar.tokens,
        "forms": ar.forms, "external_hosts": dict(ar.external), "errors": ar.errors,
    }


def write_markdown(rep, path):
    cell = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
    L = [f"# Argus report: {rep['target']}", "",
         f"- Started {rep['started']}, finished {rep['finished']}",
         "- " + ", ".join(f"{k}: {v}" for k, v in rep["stats"].items()), "", "## Findings", "",
         "| Severity | Type | Value | Where | Note |", "|---|---|---|---|---|"]
    for f in rep["findings"]:
        L.append(f"| {f['severity']} | {cell(f['title'])} | `{cell(f['value'][:90])}` | {cell(f['url'])}:{f['line']} | {cell(f['note'])} |")
    L += ["", "## Cookies and tokens set by the server", "",
          "| Name | Host | HttpOnly | Secure | SameSite | Value |", "|---|---|---|---|---|---|"]
    L += [f"| {cell(c['name'])} | {cell(c['host'])} | {c['httponly']} | {c['secure']} | {c['samesite'] or '-'} | `{cell(c['value'][:60])}` |"
          for c in rep["cookies"]]
    L += [f"- header `{t['header']}` at {t['url']}: `{cell(t['value'][:80])}`" for t in rep["tokens"]]
    L += ["", "## Endpoints needing authentication", ""]
    L += [f"- `{e['url']}`: {e['auth']} - {e['auth_reason']}" for e in rep["endpoints"] if e["auth"] in ("required", "likely", "rejected")] or ["_none detected_"]
    L += ["", "## All endpoints", "", "| Status | Auth | Methods | URL | Found in |", "|---|---|---|---|---|"]
    for e in rep["endpoints"]:
        L.append(f"| {e['status'] or e['skipped'] or '-'} | {e['auth']} | {','.join(e['methods'])} | {cell(e['url'])} | {cell(', '.join(e['sources'][:2]))} |")
    L += ["", "## Forms", ""] + [f"- {f['method']} `{f['action']}` ({', '.join(i['name'] or i['type'] for i in f['inputs'])})" for f in rep["forms"]]
    with open(path, "w") as fh:
        fh.write("\n".join(L) + "\n")


def print_summary(rep, ar: Argus):
    fs = rep["findings"]
    counts = {s: sum(f["severity"] == s for f in fs) for s in SEVERITIES}
    print(f"\n{C['b']}== Argus summary =={C['x']}  {rep['stats']['requests']} requests, "
          f"{rep['stats']['endpoints']} endpoints, {len(fs)} findings")
    print("   " + "  ".join(f"{C[s]} {s} {counts[s]} {C['x']}" for s in SEVERITIES))
    by_auth = defaultdict(int)
    for e in rep["endpoints"]:
        if e["status"]:
            by_auth[e["auth"]] += 1
    print("   auth: " + ", ".join(f"{k}={v}" for k, v in sorted(by_auth.items())))
    if rep["cookies"] or rep["tokens"]:
        print(f"   server-issued: {len(rep['cookies'])} cookie(s), {len(rep['tokens'])} token header(s)")
        for c in rep["cookies"][:8]:
            fl = [("HttpOnly" if c["httponly"] else "!HttpOnly"), ("Secure" if c["secure"] else "!Secure"),
                  (f"SameSite={c['samesite']}" if c["samesite"] else "!SameSite")]
            print(f"     {c['name']}={c['value'][:28]}  {C['dim']}{' '.join(fl)}{C['x']}")
        for t in rep["tokens"][:5]:
            print(f"     {t['header']}: {t['value'][:40]}")
    top = [f for f in fs if f["severity"] in ("critical", "high", "medium")]
    for f in top[:40]:
        print(f"  {C[f['severity']]} {f['severity']:<8} {C['x']} {f['title']}: {f['value'][:60]}  {C['dim']}{f['url'][:80]}:{f['line']}{C['x']}")
    if len(top) > 40:
        print(f"  ... {len(top) - 40} more in the report")
    if ar.throttle.total_hits:
        print(f"\n{C['medium']}[!]{C['x']} Rate-limited {ar.throttle.total_hits} time(s); Argus slowed itself down automatically. "
              "Use a lower --rps next time." + (" The target kept blocking, so the crawl STOPPED EARLY; "
              "results are partial. Wait a while (or check for an IP ban) and re-run." if ar.blocked else ""))
    if ar.gated and not ar.auth.present:
        print(f"\n{C['medium']}[!]{C['x']} {len(ar.gated)} endpoint(s) need authentication and were not tested with a session. "
              "Re-run with --cookie / --token / -H.")


def main():
    ap = argparse.ArgumentParser(prog="argus", description="Crawl a web app, mine its JS, flag low-hanging fruit.")
    ap.add_argument("url")
    ap.add_argument("-c", "--cookie", action="append", default=[], help="cookie string 'a=b; c=d' (repeatable)")
    ap.add_argument("-t", "--token", help="bearer token / JWT")
    ap.add_argument("-H", "--header", action="append", default=[], help="extra header 'Name: value' (repeatable)")
    ap.add_argument("-d", "--depth", type=int, default=3, help="link depth from the seed (default 3)")
    ap.add_argument("--max-pages", type=int, default=500)
    ap.add_argument("--max-js", type=int, default=300, help="cap on script/source-map fetches")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--rps", type=float, default=5.0, help="max requests/second across all threads (default 5)")
    ap.add_argument("--delay", type=float, default=0.0, help="minimum seconds between requests (caps --rps)")
    ap.add_argument("--retries", type=int, default=4, help="retries per request on 429/503+Retry-After (default 4)")
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--subdomains", action="store_true", help="treat subdomains of the target as in scope")
    ap.add_argument("--scope", action="append", help="extra in-scope hostname (repeatable)")
    ap.add_argument("--third-party-js", action="store_true", help="also fetch & analyse scripts on out-of-scope hosts")
    ap.add_argument("--no-baseline", dest="baseline", action="store_false", help="skip the unauthenticated comparison request")
    ap.add_argument("--no-prompt", action="store_true", help="never ask for credentials interactively")
    ap.add_argument("--no-guess", dest="guess", action="store_false", help="don't guess .map files / webpack chunk URLs")
    ap.add_argument("--allow-destructive", action="store_true", help="also GET urls like /logout, /delete/...")
    ap.add_argument("--all-comments", action="store_true", help="report every comment, not just interesting ones")
    ap.add_argument("-k", "--insecure", action="store_true", help="don't verify TLS certificates")
    ap.add_argument("--user-agent")
    ap.add_argument("-o", "--out", default="argus-report", help="output prefix (writes .json and .md)")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--no-banner", action="store_true")
    a = ap.parse_args()
    if "://" not in a.url:
        a.url = "https://" + a.url

    if not (a.quiet or a.no_banner):
        print_banner()
    ar = Argus(a)
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"{C['b']}Argus {VERSION}{C['x']}  target={a.url}  auth={'yes' if ar.auth.present else 'none'}  "
          f"rate<={ar.throttle.max_rps:g}/s  GET-only, scope={sorted(ar.hosts)}{' +subdomains' if a.subdomains else ''}")
    try:
        ar.crawl()
    except KeyboardInterrupt:
        print("\ninterrupted - writing what we have")
    rep = build_report(ar, started)
    with open(a.out + ".json", "w") as fh:
        json.dump(rep, fh, indent=2, default=_json_default)
    write_markdown(rep, a.out + ".md")
    print_summary(rep, ar)
    print(f"\nreports: {a.out}.json, {a.out}.md")


if __name__ == "__main__":
    main()