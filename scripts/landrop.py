#!/usr/bin/env python3
"""
landrop - share files + text between your laptop, desktop and phone over the LAN.

Run it on any machine:   python3 landrop.py
Open the printed URL on your other devices (phone: scan the QR if `qrcode` is installed).

- Zero dependencies (stdlib only). `pip install qrcode` is optional, for the terminal QR.
- Streams uploads straight to disk, so big files don't eat RAM.
- Resumable downloads (HTTP Range).
- Token auth via cookie, so random people on your wifi can't browse your files.
- Plain HTTP: fine on a trusted home network, don't run it on public wifi.
"""
import argparse
import hmac
import json
import mimetypes
import os
import re
import secrets
import socket
import sys
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlparse

COOKIE = "landrop"
CHUNK = 1 << 20  # 1 MiB
CLIP_MAX = 1 << 20

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>landrop</title>
<style>
  :root { --bg:#fafafa; --fg:#1a1a1a; --card:#fff; --line:#ddd; --acc:#2f6fed; --mute:#777; --ok:#1f9d55; --err:#d33; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#111214; --fg:#e8e8e8; --card:#1b1c1f; --line:#2c2e33; --acc:#6c9bff; --mute:#8b8f98; --ok:#4ade80; --err:#ff6b6b; }
  }
  * { box-sizing: border-box; }
  body { margin:0; font:16px/1.4 system-ui,sans-serif; background:var(--bg); color:var(--fg); }
  main { max-width:760px; margin:0 auto; padding:16px; }
  h1 { font-size:1.2rem; margin:8px 0 16px; }
  h2 { font-size:.85rem; text-transform:uppercase; letter-spacing:.06em; color:var(--mute); margin:24px 0 8px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px; }
  #drop { border:2px dashed var(--line); text-align:center; padding:28px 12px; cursor:pointer; border-radius:12px; color:var(--mute); }
  #drop.over { border-color:var(--acc); color:var(--acc); }
  .up { display:flex; gap:10px; align-items:center; margin-top:8px; font-size:.9rem; }
  .up span { flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .up progress { width:120px; }
  .up.ok span { color:var(--ok); } .up.err span { color:var(--err); }
  .file { display:flex; gap:10px; align-items:center; padding:10px 0; border-bottom:1px solid var(--line); }
  .file:last-child { border-bottom:0; }
  .file .info { flex:1; min-width:0; display:flex; flex-direction:column; }
  .file a { color:var(--acc); text-decoration:none; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .file small { color:var(--mute); }
  button { font:inherit; padding:8px 12px; border-radius:8px; border:1px solid var(--line); background:var(--card); color:var(--fg); cursor:pointer; }
  button.pri { background:var(--acc); border-color:var(--acc); color:#fff; }
  textarea { width:100%; min-height:90px; font:inherit; padding:10px; border-radius:8px; border:1px solid var(--line); background:var(--bg); color:var(--fg); resize:vertical; }
  .row { display:flex; gap:8px; margin-top:8px; }
</style>
</head>
<body>
<main>
  <h1>landrop</h1>

  <div id="drop" class="card">Drop files here or tap to choose</div>
  <input id="pick" type="file" multiple hidden>
  <div id="ups"></div>

  <h2>Shared text</h2>
  <div class="card">
    <textarea id="clip" placeholder="Paste a link, snippet, or note here"></textarea>
    <div class="row">
      <button class="pri" id="send">Send</button>
      <button id="copy">Copy</button>
    </div>
  </div>

  <h2>Files</h2>
  <div class="card" id="files">Loading...</div>
</main>
<script>
const $ = s => document.querySelector(s);
const fmt = n => { const u=['B','KB','MB','GB','TB']; let i=0; while (n>=1024 && i<4) { n/=1024; i++; } return (i ? n.toFixed(1) : n) + ' ' + u[i]; };

function upload(file) {
  return new Promise(done => {
    const row = document.createElement('div'); row.className = 'up';
    const label = document.createElement('span'); label.textContent = file.name;
    const bar = document.createElement('progress'); bar.max = 100; bar.value = 0;
    row.append(label, bar); $('#ups').prepend(row);
    const x = new XMLHttpRequest();
    x.open('PUT', '/api/upload?name=' + encodeURIComponent(file.name));
    x.upload.onprogress = e => { if (e.lengthComputable) bar.value = e.loaded / e.total * 100; };
    x.onload = () => {
      if (x.status === 200) { row.classList.add('ok'); setTimeout(() => row.remove(), 2500); }
      else { row.classList.add('err'); label.textContent += ' - failed (' + x.status + ')'; }
      refresh(); done();
    };
    x.onerror = () => { row.classList.add('err'); label.textContent += ' - network error'; done(); };
    x.send(file);
  });
}
async function uploadAll(files) { for (const f of files) await upload(f); }

const drop = $('#drop'), pick = $('#pick');
drop.onclick = () => pick.click();
pick.onchange = () => { uploadAll([...pick.files]); pick.value = ''; };
['dragenter','dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave','drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', e => uploadAll([...e.dataTransfer.files]));

async function refresh() {
  const r = await fetch('/api/files');
  if (!r.ok) return;
  const items = await r.json();
  const box = $('#files'); box.replaceChildren();
  if (!items.length) { box.textContent = 'Nothing here yet.'; return; }
  for (const f of items) {
    const row = document.createElement('div'); row.className = 'file';
    const info = document.createElement('div'); info.className = 'info';
    const a = document.createElement('a'); a.href = '/files/' + encodeURIComponent(f.name); a.textContent = f.name;
    const meta = document.createElement('small'); meta.textContent = fmt(f.size) + '  ·  ' + new Date(f.mtime * 1000).toLocaleString();
    info.append(a, meta);
    const del = document.createElement('button'); del.textContent = 'Delete';
    del.onclick = async () => {
      if (!confirm('Delete ' + f.name + '?')) return;
      await fetch('/api/files/' + encodeURIComponent(f.name), { method: 'DELETE' });
      refresh();
    };
    row.append(info, del); box.append(row);
  }
}

const clip = $('#clip');
async function pullClip() {
  if (document.activeElement === clip) return;
  const r = await fetch('/api/clip'); if (!r.ok) return;
  clip.value = (await r.json()).text;
}
$('#send').onclick = async () => {
  await fetch('/api/clip', { method: 'PUT', body: clip.value });
  $('#send').textContent = 'Sent'; setTimeout(() => $('#send').textContent = 'Send', 1200);
};
$('#copy').onclick = async () => {
  try { await navigator.clipboard.writeText(clip.value); }
  catch { clip.select(); document.execCommand('copy'); }
  $('#copy').textContent = 'Copied'; setTimeout(() => $('#copy').textContent = 'Copy', 1200);
};

refresh(); pullClip();
setInterval(refresh, 5000); setInterval(pullClip, 5000);
</script>
</body>
</html>
"""


def _eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def clean_name(raw: str) -> str:
    """Turn whatever the client sent into a safe, flat filename."""
    name = raw.replace("\\", "/").split("/")[-1]
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip().lstrip(".")
    name = name[:200] or "file"
    if name.endswith(".part"):
        name += "_"
    return name


def reserve_path(root: str, name: str) -> str:
    """Atomically claim a free filename (name, name (1).ext, ...)."""
    stem, ext = os.path.splitext(name)
    n = 0
    while True:
        cand = name if n == 0 else f"{stem} ({n}){ext}"
        path = os.path.join(root, cand)
        try:
            os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            return path
        except FileExistsError:
            n += 1


class Handler(BaseHTTPRequestHandler):
    server_version = "landrop"

    def log_message(self, fmt, *args):
        sys.stderr.write("  %-15s %s\n" % (self.address_string(), fmt % args))

    # ---------- helpers ----------
    def _send(self, code, body=b"", ctype="text/plain; charset=utf-8", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _authed(self) -> bool:
        jar = SimpleCookie(self.headers.get("Cookie", ""))
        m = jar.get(COOKIE)
        return bool(m) and _eq(m.value, self.server.token)

    def _existing(self, raw_name):
        """Resolve a name from the URL to an existing file in root, or None."""
        name = unquote(raw_name)
        if not name or name in (".", "..") or name != os.path.basename(name) or "\\" in name:
            return None
        path = os.path.join(self.server.root, name)
        return path if os.path.isfile(path) else None

    # ---------- GET ----------
    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)

        # Login via ?t=TOKEN -> set cookie, redirect to clean URL
        if "t" in q:
            if _eq(q["t"][0], self.server.token):
                cookie = f"{COOKIE}={self.server.token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000"
                return self._send(303, headers={"Location": "/", "Set-Cookie": cookie})
            return self._send(403, b"bad token\n")

        if not self._authed():
            return self._send(401, b"Unauthorized. Open the full link printed in the terminal.\n")

        if url.path == "/":
            return self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        if url.path == "/api/files":
            return self._json(self._list())
        if url.path == "/api/clip":
            return self._json(self.server.clip)
        if url.path.startswith("/files/"):
            return self._download(url.path[len("/files/"):])
        self._send(404, b"not found\n")

    do_HEAD = do_GET

    def _list(self):
        out = []
        with os.scandir(self.server.root) as it:
            for e in it:
                if e.is_file() and not e.name.endswith(".part"):
                    st = e.stat()
                    out.append({"name": e.name, "size": st.st_size, "mtime": st.st_mtime})
        out.sort(key=lambda f: f["mtime"], reverse=True)
        return out

    def _download(self, raw_name):
        path = self._existing(raw_name)
        if not path:
            return self._send(404, b"not found\n")
        size = os.path.getsize(path)
        name = os.path.basename(path)
        start, end, code = 0, size - 1, 200

        rng = self.headers.get("Range", "")
        m = re.fullmatch(r"bytes=(\d*)-(\d*)", rng.strip())
        if m and (m.group(1) or m.group(2)):
            if m.group(1):
                start = int(m.group(1))
                end = int(m.group(2)) if m.group(2) else size - 1
            else:  # suffix range: last N bytes
                start = max(0, size - int(m.group(2)))
            end = min(end, size - 1)
            if start > end or start >= size:
                return self._send(416, headers={"Content-Range": f"bytes */{size}"})
            code = 206

        ascii_name = name.encode("ascii", "replace").decode().replace('"', "_")
        self.send_response(code)
        self.send_header("Content-Type", mimetypes.guess_type(name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(end - start + 1))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("X-Content-Type-Options", "nosniff")
        # always attachment: an uploaded .html must never render on this origin
        self.send_header("Content-Disposition",
                         f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name)}")
        if code == 206:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.end_headers()
        if self.command == "HEAD":
            return
        try:
            with open(path, "rb") as f:
                f.seek(start)
                left = end - start + 1
                while left > 0:
                    buf = f.read(min(CHUNK, left))
                    if not buf:
                        break
                    self.wfile.write(buf)
                    left -= len(buf)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # ---------- PUT (upload / clipboard) ----------
    def do_PUT(self):
        if not self._authed():
            return self._send(401, b"unauthorized\n")
        url = urlparse(self.path)
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._send(411, b"length required\n")

        if url.path == "/api/clip":
            if length > CLIP_MAX:
                return self._send(413, b"too big\n")
            text = self.rfile.read(length).decode("utf-8", "replace")
            self.server.clip = {"text": text, "ts": time.time()}
            return self._json({"ok": True})

        if url.path != "/api/upload":
            return self._send(404, b"not found\n")

        limit = self.server.max_bytes
        if limit and length > limit:
            return self._send(413, b"file too large\n")

        name = clean_name(parse_qs(url.query).get("name", [""])[0])
        dest = reserve_path(self.server.root, name)
        tmp = dest + ".part"
        left = length
        try:
            with open(tmp, "wb") as f:
                while left > 0:
                    buf = self.rfile.read(min(CHUNK, left))
                    if not buf:
                        break
                    f.write(buf)
                    left -= len(buf)
            if left:
                raise ConnectionError("client disconnected mid-upload")
            os.replace(tmp, dest)
        except Exception:
            for p in (tmp, dest):
                try:
                    os.remove(p)
                except OSError:
                    pass
            return self._send(400, b"upload failed\n")
        self._json({"ok": True, "name": os.path.basename(dest)})

    # ---------- DELETE ----------
    def do_DELETE(self):
        if not self._authed():
            return self._send(401, b"unauthorized\n")
        path = urlparse(self.path).path
        if not path.startswith("/api/files/"):
            return self._send(404, b"not found\n")
        target = self._existing(path[len("/api/files/"):])
        if not target:
            return self._send(404, b"not found\n")
        os.remove(target)
        self._json({"ok": True})


def lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is actually sent
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description="Share files between your devices over the LAN.")
    ap.add_argument("-d", "--dir", default="./landrop-files", help="folder to share (default: ./landrop-files)")
    ap.add_argument("-p", "--port", type=int, default=8000)
    ap.add_argument("--host", default="0.0.0.0", help="bind address (use 127.0.0.1 to test locally)")
    ap.add_argument("--token", default=None, help="fixed access token (default: random each run)")
    ap.add_argument("--max-mb", type=int, default=0, help="reject uploads bigger than this (0 = no limit)")
    args = ap.parse_args()

    root = os.path.abspath(args.dir)
    os.makedirs(root, exist_ok=True)

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    srv.daemon_threads = True
    srv.root = root
    srv.token = args.token or secrets.token_urlsafe(9)
    srv.max_bytes = args.max_mb * 1024 * 1024
    srv.clip = {"text": "", "ts": 0}

    ip = lan_ip() if args.host == "0.0.0.0" else args.host
    url = f"http://{ip}:{args.port}/?t={srv.token}"
    print(f"\n  landrop serving {root}\n\n  Open on your other devices:\n  {url}\n")
    try:
        import qrcode  # optional
        qr = qrcode.QRCode(border=1)
        qr.add_data(url)
        qr.print_ascii(invert=True)
    except ImportError:
        print("  (pip install qrcode  ->  QR code here so you can scan it with your phone)\n")
    print("  Ctrl+C to stop.\n")

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  bye.")


if __name__ == "__main__":
    main()
