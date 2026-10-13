"""Phone web UI for the read-only CAN logger. stdlib only, one file, binds only to Wi-Fi/hotspot addresses."""
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
import zlib
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

try:
  from openpilot.common.swaglog import cloudlog as _log
except Exception:
  _log = logging.getLogger("canlog.webui")

LOCK_S = 60.0
MAX_FAILS = 5
COOKIE = "canlog_session"
COOKIE_AGE = 30 * 86400
EXT = ".canlog"
CHUNK = 64 * 1024
DEFAULT_ROOT = "/data/canlogs"


def log_root() -> str:
  return os.environ.get("CANLOG_ROOT") or DEFAULT_ROOT


# ---------------------------------------------------------------- network
def iface_ipv4_addrs(iface: str = "wlan0") -> set[str]:
  if not sys.platform.startswith("linux"):
    return {"127.0.0.1"}
  try:
    out = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", iface], capture_output=True, text=True, timeout=2).stdout
    addrs = set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", out))
    if addrs:
      return addrs
  except Exception:
    pass
  try:
    import fcntl
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
      res = fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', iface.encode()[:15]))
      return {socket.inet_ntoa(res[20:24])}
  except Exception:
    return set()


def current_addrs() -> set[str]:
  if os.environ.get("CANLOG_BIND_ANY") == "1":
    return {"0.0.0.0"}
  out: set[str] = set()
  for i in (os.environ.get("CANLOG_BIND_IFACE") or "wlan0").split(","):
    if i.strip():
      out |= iface_ipv4_addrs(i.strip())
  return out


# ---------------------------------------------------------------- icons
_icons: dict[int, bytes] = {}


def make_icon(size: int) -> bytes:
  if size in _icons:
    return _icons[size]
  bg, fg, dim = (17, 17, 17), (230, 230, 230), (90, 200, 120)
  pad = size * 0.2
  bars = [(0.25, 0.55), (0.42, 0.8), (0.59, 0.4), (0.76, 0.65)]  # (x center frac, height frac)
  bw = size * 0.1
  rows = bytearray()
  for y in range(size):
    rows.append(0)
    row = bytearray(bytes(bg) * size)
    if pad <= y <= size - pad:
      for xc, hf in bars:
        top = size - pad - (size - 2 * pad) * hf
        if y >= top:
          col = dim if hf > 0.7 else fg
          for x in range(int(size * xc - bw / 2), int(size * xc + bw / 2)):
            row[x * 3:x * 3 + 3] = bytes(col)
    rows += row

  def chunk(tag: bytes, d: bytes) -> bytes:
    return struct.pack(">I", len(d)) + tag + d + struct.pack(">I", zlib.crc32(tag + d) & 0xffffffff)
  png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)) +
         chunk(b"IDAT", zlib.compress(bytes(rows), 9)) + chunk(b"IEND", b""))
  _icons[size] = png
  return png


MANIFEST = {"name": "CAN Log", "short_name": "CAN Log", "start_url": "/", "display": "standalone", "background_color": "#111",
            "theme_color": "#111", "icons": [{"src": "/icon-180.png", "sizes": "180x180", "type": "image/png"}]}


# ---------------------------------------------------------------- auth
class Auth:
  def __init__(self) -> None:
    self.tokens: set[str] = set()
    self.fails: dict[str, list[float]] = {}  # ip -> [count, locked_until]
    self.lock = threading.Lock()

  @property
  def pin_path(self) -> str:
    return os.path.join(log_root(), "pin.json")

  def has_pin(self) -> bool:
    return os.path.isfile(self.pin_path)

  def set_pin(self, pin: str) -> None:
    os.makedirs(log_root(), exist_ok=True)
    salt = secrets.token_hex(16)
    tmp = self.pin_path + ".tmp"
    with open(tmp, "w") as f:
      json.dump({"salt": salt, "hash": hashlib.sha256((salt + pin).encode()).hexdigest()}, f)
    os.replace(tmp, self.pin_path)

  def check_pin(self, pin: str) -> bool:
    try:
      with open(self.pin_path) as f:
        d = json.load(f)
      return hmac.compare_digest(hashlib.sha256((d["salt"] + pin).encode()).hexdigest(), d["hash"])
    except Exception:
      return False

  def locked_for(self, ip: str) -> float:
    with self.lock:
      f = self.fails.get(ip)
      return max(0.0, f[1] - time.time()) if f else 0.0

  def record(self, ip: str, ok: bool) -> None:
    with self.lock:
      if ok:
        self.fails.pop(ip, None)
        return
      f = self.fails.setdefault(ip, [0, 0.0])
      if f[1] and f[1] <= time.time():
        f[0], f[1] = 0, 0.0
      f[0] += 1
      if f[0] >= MAX_FAILS:
        f[1] = time.time() + LOCK_S
        f[0] = 0

  def new_token(self) -> str:
    t = secrets.token_urlsafe(32)
    self.tokens.add(t)
    return t


class Ctx:
  def __init__(self, rec: Any) -> None:
    self.rec = rec
    self.auth = Auth()
    self.addrs: set[str] = set()
    self.any = False


# ---------------------------------------------------------------- diff helpers
def _frame(f: Any) -> tuple[Any, int, int, bytes]:
  if isinstance(f, dict):
    t, bus, addr, d = f.get("t"), f.get("bus"), f.get("addr"), f.get("data")
  else:
    t, bus, addr, d = f[0], f[1], f[2], f[3]
  if isinstance(d, str):
    d = bytes.fromhex(d)
  return t, int(bus), int(addr), bytes(d)  # type: ignore[arg-type]


def _fa(addr: int) -> str:
  return f"0x{addr:08X}"  # same spelling as decode.fmt_addr (the recorder's /api/live keys)


def watched_summary(frames: list, markers: list, watch: dict[int, str], decode_fn: Any, post_ns: int = 3_000_000_000) -> list[dict]:
  idx: dict[tuple[int, int], list[tuple[Any, bytes]]] = {}
  for f in frames:
    try:
      t, bus, addr, d = _frame(f)
    except Exception:
      continue
    if addr in watch:
      idx.setdefault((addr, bus), []).append((t, d))

  def dec(addr: int, p: tuple[Any, bytes] | None) -> dict | None:
    if p is None:
      return None
    try:
      v = dict(decode_fn(addr, p[1]))
    except Exception:
      v = {}
    return {"t": p[0], "data": p[1].hex().upper(), "decoded": {k: str(x) for k, x in v.items()}}
  out = []
  for mi, m in enumerate(markers):
    mt = m["t"] if isinstance(m, dict) else m[0]
    for (addr, bus), lst in sorted(idx.items()):
      before = next((p for p in reversed(lst) if p[0] <= mt), None)
      after = next((p for p in reversed(lst) if mt < p[0] <= mt + post_ns), None)  # last frame in this marker's post window
      out.append({"marker": mi, "id": _fa(addr), "name": watch[addr], "bus": bus,
                  "before": dec(addr, before), "after": dec(addr, after)})
  return out


def _watch() -> dict[int, str]:
  try:
    from openpilot.sunnypilot.canlog.decode import WATCH
    return dict(WATCH)
  except Exception:
    return {0x16A954FB: "Climate setpoint", 0x16A95493: "Heating active", 0x1B000010: "NMH_Gateway"}


# ---------------------------------------------------------------- handler
class Handler(BaseHTTPRequestHandler):
  ctx: Ctx
  server_version = "canlog"
  protocol_version = "HTTP/1.0"
  timeout = 30

  def log_message(self, fmt: str, *args: Any) -> None:
    logging.getLogger("canlog.webui").debug(fmt, *args)

  # --- helpers
  def _send(self, code: int, body: bytes, ctype: str, extra: dict[str, str] | None = None, cache: str = "no-store") -> None:
    self.send_response(code)
    self.send_header("Content-Type", ctype)
    self.send_header("Content-Length", str(len(body)))
    self.send_header("Cache-Control", cache)
    for k, v in (extra or {}).items():
      self.send_header(k, v)
    self.end_headers()
    self.wfile.write(body)

  def _json(self, obj: Any, code: int = 200, extra: dict[str, str] | None = None) -> None:
    self._send(code, json.dumps(obj, default=str).encode(), "application/json", extra)

  def _err(self, code: int, msg: str) -> None:
    self._json({"error": msg}, code)

  def _body(self) -> dict:
    n = int(self.headers.get("Content-Length") or 0)
    raw = self.rfile.read(min(n, 65536)).decode("utf-8", "replace") if n > 0 else ""
    if not raw:
      return {}
    try:
      d = json.loads(raw)
      return d if isinstance(d, dict) else {}
    except ValueError:
      return {k: v[0] for k, v in parse_qs(raw).items()}

  def _authed(self) -> bool:
    try:
      c = SimpleCookie(self.headers.get("Cookie", ""))
      return COOKIE in c and c[COOKIE].value in self.ctx.auth.tokens
    except Exception:
      return False

  def _allowed(self) -> bool:
    c = self.ctx
    return c.any or self.connection.getsockname()[0] in c.addrs

  @staticmethod
  def _cookie(token: str, age: int = COOKIE_AGE) -> dict[str, str]:
    return {"Set-Cookie": f"{COOKIE}={token}; Max-Age={age}; Path=/; HttpOnly; SameSite=Lax"}

  def _state(self) -> str:
    a = self.ctx.auth
    return "ok" if (a.has_pin() and self._authed()) else ("login" if a.has_pin() else "setpin")

  # --- dispatch
  def _route(self, method: str) -> None:
    if not self._allowed():
      return self._err(403, "forbidden")
    u = urlparse(self.path)
    path, q = u.path, {k: v[0] for k, v in parse_qs(u.query).items()}
    try:
      if method == "GET":
        if path == "/":
          st = self._state()
          html = PAGE.replace("__STATE__", st).replace("__TITLE__", "Set a PIN" if st == "setpin" else "Enter PIN")
          return self._send(200, html.encode(), "text/html; charset=utf-8")
        if path == "/manifest.webmanifest":
          return self._send(200, json.dumps(MANIFEST).encode(), "application/manifest+json", cache="max-age=3600")
        m = re.fullmatch(r"/icon-(180|192|512)\.png", path)
        if m:
          return self._send(200, make_icon(int(m.group(1))), "image/png", cache="max-age=86400")
      if path.startswith("/logs/"):
        if method != "GET":
          return self._err(404, "not found")
        if not self._authed():
          return self._send(401, b"unauthorized", "text/plain")
        return self._download(path[6:], q)
      if not path.startswith("/api/"):
        return self._err(404, "not found")
      if path in ("/api/auth", "/api/setpin", "/api/login"):
        return self._auth_api(path, method)
      if not self._authed():
        return self._err(401, "unauthorized")
      self._api(method, path, q)
    except (BrokenPipeError, ConnectionResetError):
      pass
    except Exception as e:
      logging.getLogger("canlog.webui").exception("handler error")
      try:
        self._err(500, str(e))
      except Exception:
        pass

  def do_GET(self) -> None: self._route("GET")  # noqa: E704
  def do_POST(self) -> None: self._route("POST")  # noqa: E704
  def do_DELETE(self) -> None: self._route("DELETE")  # noqa: E704

  def _auth_api(self, path: str, method: str) -> None:
    a, ip = self.ctx.auth, self.client_address[0]
    if path == "/api/auth" and method == "GET":
      return self._json({"state": self._state()})
    if method != "POST":
      return self._err(404, "not found")
    b = self._body()
    pin, pin2 = str(b.get("pin", "")), str(b.get("pin2", ""))
    if path == "/api/setpin":
      if a.has_pin():
        return self._err(403, "PIN already set")
      if not re.fullmatch(r"\d{4,12}", pin):
        return self._err(400, "PIN must be 4-12 digits")
      if pin != pin2:
        return self._err(400, "PINs do not match")
      a.set_pin(pin)
      return self._json({"ok": True}, extra=self._cookie(a.new_token()))
    wait = a.locked_for(ip)
    if wait > 0:
      return self._json({"error": "Too many attempts", "retry_s": round(wait)}, 429)
    if a.has_pin() and a.check_pin(pin):
      a.record(ip, True)
      return self._json({"ok": True}, extra=self._cookie(a.new_token()))
    a.record(ip, False)
    wait = a.locked_for(ip)
    if wait > 0:
      return self._json({"error": "Too many attempts", "retry_s": round(wait)}, 429)
    self._err(401, "Wrong PIN")

  # --- api
  def _api(self, method: str, path: str, q: dict[str, str]) -> None:
    rec, c = self.ctx.rec, self.ctx
    if method == "GET" and path == "/api/status":
      d = dict(rec.status())
      d.update(server_time=time.time(), addrs=sorted(c.addrs))
      return self._json(d)
    if method == "POST" and path == "/api/logout":
      try:
        c.auth.tokens.discard(SimpleCookie(self.headers.get("Cookie", ""))[COOKIE].value)
      except Exception:
        pass
      return self._json({"ok": True}, extra=self._cookie("", 0))
    if method == "POST" and path == "/api/start":
      return self._json({"ok": True, "session": rec.start_session()})
    if method == "POST" and path == "/api/stop":
      return self._json({"ok": True, "session": rec.stop_session()})
    if method == "POST" and path == "/api/marker":
      text = str(self._body().get("text", "")).strip()
      if not text or len(text) > 200:
        return self._err(400, "Marker text must be 1-200 characters")
      try:
        return self._json(rec.add_marker(text))
      except RuntimeError:
        return self._err(409, "Not recording")
    if method == "GET" and path == "/api/live":
      d = dict(rec.latest())
      d["names"] = {_fa(k): v for k, v in _watch().items()}
      d["server_time"] = time.time()
      return self._json(d)
    if method == "GET" and path == "/api/sessions":
      return self._json(rec.list_sessions())
    if method == "GET" and path == "/api/diff":
      return self._diff(q)
    if method == "GET" and path == "/api/verdict":
      return self._verdict(q)
    m = re.fullmatch(r"/api/sessions/([^/]+)", path)
    if method == "DELETE" and m:
      name = unquote(m.group(1))
      st = rec.status()
      if st.get("recording") and st.get("session") == name:
        return self._err(409, "Session is active")
      p = rec.session_path(name)
      if not p:
        return self._err(404, "unknown session")
      os.remove(p)
      return self._json({"ok": True})
    self._err(404, "not found")

  def _session(self, q: dict[str, str]) -> tuple[str, str] | None:
    rec = self.ctx.rec
    name = q.get("session", "latest")
    if name == "latest":
      ss = rec.list_sessions()
      if not ss:
        self._err(404, "no sessions")
        return None
      name = ss[0]["name"]
    p = rec.session_path(name)
    if not p:
      self._err(404, "unknown session")
      return None
    return name, p

  def _verdict(self, q: dict[str, str]) -> None:
    sp = self._session(q)
    if sp is None:
      return
    from openpilot.sunnypilot.canlog import analyze
    res = analyze.verdict(sp[1])
    res["session"] = sp[0]
    self._json(res)

  def _diff(self, q: dict[str, str]) -> None:
    sp = self._session(q)
    if sp is None:
      return
    name, p = sp
    try:
      pre, post = (max(0.0, min(60.0, float(q.get(k, 3)))) for k in ("pre", "post"))
      settle = max(0.0, min(600.0, float(q.get("settle", 2))))
    except ValueError:
      return self._err(400, "bad pre/post/settle")
    from openpilot.sunnypilot.canlog import analyze
    res = analyze.analyze_file(p, pre_s=pre, post_s=post, settle_s=settle)
    markers, results, frames = res["markers"], res["diff"], res["frames"]
    for r in results:
      r["changes"] = list(r.get("changes", []))[:60]
    w = _watch()
    try:
      from openpilot.sunnypilot.canlog.decode import decode as dec
    except Exception:
      def dec(a: int, d: bytes) -> dict: return {}
    self._json({"session": name, "pre": pre, "post": post, "results": results, "names": {_fa(k): v for k, v in w.items()},
                "watched": watched_summary(frames, markers, w, dec, post_ns=int(post * 1e9)),
                "states": res["states"][:30], "steps": res["steps"][:30], "profile": res["profile"].summary()})

  def _download(self, rel: str, q: dict[str, str]) -> None:
    rel = unquote(rel)
    if not rel.endswith(EXT) or "/" in rel or "\\" in rel or rel.startswith("."):
      return self._err(404, "not found")
    p = self.ctx.rec.session_path(rel[:-len(EXT)])
    if not p or not os.path.isfile(p):
      return self._err(404, "not found")
    gz = q.get("gz") == "1"
    self.send_response(200)
    self.send_header("Content-Type", "application/gzip" if gz else "text/plain; charset=utf-8")
    self.send_header("Content-Disposition", f'attachment; filename="{rel}{".gz" if gz else ""}"')
    self.send_header("Cache-Control", "no-store")
    size = os.path.getsize(p)  # snapshot: the active session keeps growing
    if not gz:
      self.send_header("Content-Length", str(size))
    self.end_headers()
    co = zlib.compressobj(6, zlib.DEFLATED, 31) if gz else None
    remaining = size
    with open(p, "rb") as f:
      while remaining > 0 and (b := f.read(min(CHUNK, remaining))):
        remaining -= len(b)
        self.wfile.write(co.compress(b) if co else b)
    if co:
      self.wfile.write(co.flush())


# ---------------------------------------------------------------- server
class _Srv(ThreadingHTTPServer):
  daemon_threads = True
  allow_reuse_address = True


class WebServer:
  def __init__(self, rec: Any, port: int = 8080) -> None:
    self.port = port
    self.ctx = Ctx(rec)
    self.servers: dict[str, tuple[_Srv, threading.Thread]] = {}
    self._stop = threading.Event()
    self._lock = threading.Lock()
    self._handler = type("BoundHandler", (Handler,), {"ctx": self.ctx})
    self.sync()
    threading.Thread(target=self._loop, daemon=True, name="canlog-web-sup").start()

  @property
  def addresses(self) -> list[tuple[str, int]]:
    with self._lock:
      return [(ip, s.server_address[1]) for ip, (s, _) in self.servers.items()]

  @property
  def ports(self) -> list[int]:
    return [p for _, p in self.addresses]

  def _loop(self) -> None:
    while not self._stop.wait(3.0):
      try:
        self.sync()
      except Exception as e:
        _log.warning("canlog webui supervisor: %r", e)

  def sync(self) -> None:
    want = current_addrs()
    with self._lock:
      if self._stop.is_set():
        return
      self.ctx.any = "0.0.0.0" in want
      self.ctx.addrs = want
      for ip in list(self.servers):
        if ip not in want:
          self._close(ip)
      for ip in want - set(self.servers):
        try:
          s = _Srv((ip, self.port), self._handler)
        except OSError as e:
          _log.warning("canlog webui bind %s:%s failed: %r", ip, self.port, e)
          continue
        t = threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.25}, daemon=True, name=f"canlog-web-{ip}")
        t.start()
        self.servers[ip] = (s, t)
        _log.info("canlog webui listening on %s:%s", ip, s.server_address[1])

  def _close(self, ip: str) -> None:
    s, _ = self.servers.pop(ip)
    s.shutdown()
    s.server_close()
    _log.info("canlog webui unbound %s", ip)

  def shutdown(self) -> None:
    self._stop.set()
    with self._lock:
      for ip in list(self.servers):
        self._close(ip)


def serve(rec: Any, port: int = 8080) -> WebServer:
  return WebServer(rec, port)




# ---------------------------------------------------------------- page
PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>CAN Log</title>
<link rel="manifest" href="/manifest.webmanifest">
<link rel="apple-touch-icon" href="/icon-180.png">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="CAN Log">
<meta name="theme-color" content="#111">
<style>
:root{--bg:#111;--card:#1b1b1d;--line:#2c2c30;--fg:#eee;--mut:#8b8b93;--grn:#2e9d57;--red:#d6453d;--blu:#3b82f6;--amb:#e0a526}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.35 -apple-system,system-ui,"Segoe UI",Roboto,sans-serif;padding:env(safe-area-inset-top) 0 0}
header{display:flex;align-items:center;gap:10px;padding:12px 16px;position:sticky;top:0;background:var(--bg);z-index:5;border-bottom:1px solid var(--line)}
header h1{font-size:20px;margin:0;flex:1}
.pill{padding:4px 12px;border-radius:99px;font-weight:700;font-size:13px;background:#3a3a3f;color:#ccc}
.pill.rec{background:var(--red);color:#fff;animation:pulse 1.2s infinite}
.pill.on{background:var(--grn);color:#fff}.pill.off{background:#4a4a52;color:#fff}
@keyframes pulse{50%{opacity:.45}}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--red);margin-right:4px}
.dot.on{background:#3ddc84}
.can{font-size:12px;color:var(--mut);white-space:nowrap}
main{padding:12px 16px calc(90px + env(safe-area-inset-bottom))}
section{display:none}section.on{display:block}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px;margin:0 0 12px}
button,input,select{font:inherit;color:var(--fg)}
button{min-height:56px;border:0;border-radius:12px;background:#2d2d33;padding:0 14px;font-weight:600;cursor:pointer}
button:disabled{opacity:.35}
button.big{width:100%;height:72px;font-size:22px;letter-spacing:.5px;background:var(--grn);color:#fff}
button.big.stop{background:var(--red)}
button.sm{min-height:44px;padding:0 12px;font-size:14px}
button.dng{background:#5a2420}
button.blu{background:var(--blu);color:#fff}
input,select{width:100%;min-height:56px;border-radius:12px;border:1px solid var(--line);background:#0c0c0d;padding:0 12px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.grid button{height:64px}
.row{display:flex;gap:8px;align-items:center}.row>*{flex:1}.row>button{flex:0 0 auto}
.stats{color:var(--mut);font-size:14px;margin-top:10px}
.hint{color:var(--mut);font-size:13px;margin:6px 0}
h2{font-size:16px;margin:14px 0 8px}h3{font-size:15px;margin:0 0 6px}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
.byte{display:inline-block;padding:1px 3px;border-radius:4px;margin-right:2px}
.byte.f{background:var(--amb);color:#000}
.chip{display:inline-block;background:#26262b;border-radius:8px;padding:2px 8px;margin:2px 4px 2px 0;font-size:13px}
.chip.mu{opacity:.5}
.busrow{border-top:1px solid var(--line);padding:6px 0}
.age{color:var(--mut);font-size:13px}.age.stale{color:var(--red)}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:5px 4px;border-top:1px solid var(--line);text-align:left;vertical-align:top}
.badge{font-size:11px;border-radius:6px;padding:1px 6px;font-weight:700}.badge.new{background:var(--grn)}.badge.gone{background:var(--red)}
.badge.rec{background:var(--blu);color:#fff;margin-left:6px;vertical-align:middle}
.w{font-weight:800;color:var(--blu)}
.toast{position:fixed;left:16px;right:16px;bottom:calc(84px + env(safe-area-inset-bottom));background:#333;border-radius:12px;padding:14px;text-align:center;z-index:60;display:none}
nav{position:fixed;left:0;right:0;bottom:0;display:flex;background:#161618;border-top:1px solid var(--line);padding-bottom:env(safe-area-inset-bottom);z-index:10}
nav button{flex:1;border-radius:0;background:none;color:var(--mut);min-height:60px}
nav button.on{color:#fff;box-shadow:inset 0 3px var(--blu)}
.spin{width:28px;height:28px;border:4px solid #333;border-top-color:var(--blu);border-radius:50%;animation:sp 1s linear infinite;margin:14px auto;display:none}
@keyframes sp{to{transform:rotate(360deg)}}
#auth{position:fixed;inset:0;background:var(--bg);z-index:50;display:none;padding:calc(30px + env(safe-area-inset-top)) 20px;overflow:auto}
body:not([data-auth=ok]) #auth{display:block}
a{color:var(--blu)}a.btn{display:inline-flex;align-items:center;min-height:44px;padding:0 12px;background:#2d2d33;border-radius:12px;color:var(--fg);text-decoration:none;font-size:14px;font-weight:600}
footer{color:var(--mut);font-size:12px;padding:10px 0}
.err{color:#ff7b72;min-height:20px}
.tcard h3{font-size:19px}.tcard p{margin:4px 0 12px;color:#c8c8cf}
.tcard button{width:100%;height:64px;font-size:20px;background:var(--blu);color:#fff}
.chk{display:flex;align-items:center;gap:14px;padding:14px 4px;border-top:1px solid var(--line);font-size:19px;line-height:1.25}
.chk input{width:34px;height:34px;min-height:0;flex:0 0 34px;accent-color:var(--grn)}
details.card>summary{font-weight:700;font-size:16px;cursor:pointer;min-height:32px}
details.sub{margin:8px 0}details.sub>summary{cursor:pointer;color:var(--blu);font-size:14px;min-height:32px}
.box{border-radius:12px;padding:14px;margin:0 0 12px}.box.bad{background:#3a1a18;border:1px solid var(--red)}
.box ul{margin:6px 0 0;padding-left:20px}
.ov{position:fixed;inset:0;z-index:40;background:var(--bg);display:none;flex-direction:column;padding:calc(10px + env(safe-area-inset-top)) 16px calc(12px + env(safe-area-inset-bottom));overflow:auto}
.ov.on{display:flex}
.ovtop{display:flex;align-items:center;gap:10px;justify-content:space-between}
.prog{height:6px;background:#2a2a2e;border-radius:3px;margin:8px 0 6px;overflow:hidden}.prog>div{height:100%;width:0;background:var(--blu)}
.mid{flex:1;display:flex;flex-direction:column;justify-content:center;align-items:center;text-align:center;gap:14px;padding:10px 0}
#rText{font-size:32px;font-weight:800;line-height:1.2}
#rHint{font-size:17px;color:var(--mut)}
.ring{position:relative;width:220px;height:220px}.ring svg{width:100%;height:100%;transform:rotate(-90deg)}
.ring circle{fill:none;stroke-width:14}.ring .bg{stroke:#2a2a2e}.ring .fg{stroke:var(--blu);stroke-linecap:round;stroke-dasharray:565.5;stroke-dashoffset:0}
#rNum{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:76px;font-weight:800;font-variant-numeric:tabular-nums}
#rClock{font-size:64px;font-weight:800;font-variant-numeric:tabular-nums}
#rBtns{display:flex;flex-direction:column;gap:10px}
button.giant{width:100%;min-height:120px;font-size:30px;font-weight:800;line-height:1.15;background:var(--grn);color:#fff;border:3px solid #fff;padding:10px 12px}
button.giant.alt{min-height:72px;font-size:22px;background:#3a3a40;border-color:#666}
.ovsec{display:flex;gap:8px;margin-top:12px}.ovsec button{flex:1}
#rBan{background:var(--red);color:#fff;border-radius:10px;padding:10px;font-weight:700;margin:8px 0 0;display:none}
#rPause{position:absolute;inset:0;background:rgba(17,17,17,.88);display:none;align-items:center;justify-content:center;font-size:40px;font-weight:800;pointer-events:none}
.vline{border-radius:12px;padding:14px;margin:0 0 10px;font-size:19px;font-weight:700;line-height:1.3;border-left:10px solid}
.vline.green{background:#173a25;border-color:var(--grn)}.vline.yellow{background:#3b3114;border-color:var(--amb)}.vline.red{background:#3a1a18;border-color:var(--red)}
.vline small{display:block;font-weight:400;font-size:14px;color:#cfcfd6;margin-top:4px}
</style></head>
<body data-auth="__STATE__">
<div id="auth"><h1 id="atitle">__TITLE__</h1>
<p class="hint" id="asub"></p>
<input id="pin" type="password" inputmode="numeric" autocomplete="current-password" maxlength="12" placeholder="PIN (4-12 digits)">
<div style="height:10px"></div>
<input id="pin2" type="password" inputmode="numeric" maxlength="12" placeholder="Repeat PIN">
<div style="height:10px"></div>
<button class="big" id="abtn" style="background:var(--blu)">Continue</button>
<p class="err" id="aerr"></p>
<p class="hint">Forgot PIN? Delete /data/canlogs/pin.json over SSH.</p></div>
<header><h1>CAN Log</h1><span class="pill" id="pill">IDLE</span><span class="can"><span class="dot" id="cdot"></span><span id="ctxt">no CAN</span></span></header>
<main>
<section id="t-test" class="on">
 <div id="tHome">
  <div class="card tcard"><h3>A. Climate buttons in the car <span class="badge rec">Recommended</span></h3>
   <p>Press Climate ON/OFF and Temp up/down in the car when told. About 15 minutes.</p><button data-start="A">Start</button></div>
  <div class="card tcard"><h3>B. Remote start from the VW app</h3>
   <p>Car asleep. Send a remote climate START and STOP from the app. About 6 minutes.</p><button data-start="B">Start</button></div>
  <div class="card tcard"><h3>C. Wake-up only (key fob)</h3>
   <p>Car asleep. Unlock with the fob and watch what wakes up. About 2 minutes.</p><button data-start="C">Start</button></div>
  <details class="card" id="manual"><summary>Manual mode</summary>
   <div style="height:10px"></div>
   <button class="big" id="rec">START LOGGING</button>
   <div class="stats" id="stats"></div>
   <h2>Markers</h2>
   <div class="grid" id="mgrid"></div>
   <div class="row" style="margin-top:10px"><input id="mtxt" maxlength="200" placeholder="Custom marker text"><button id="madd">Add marker</button></div>
   <div class="hint" id="mhint"></div>
   <div class="card" style="margin-top:10px"><h3>This session</h3><div id="mlist" class="hint">No markers yet</div></div>
  </details>
 </div>
 <div id="tPre" style="display:none">
  <h2 id="pTitle" style="font-size:22px"></h2>
  <div class="hint">Tick every box to continue.</div>
  <div class="card" id="pList"></div>
  <div class="box bad" id="pErr" style="display:none"></div>
  <button class="giant" id="pGo" disabled>START TEST</button>
  <div style="height:10px"></div>
  <button class="sm" id="pBack" style="width:100%">Back</button>
 </div>
 <div id="tVerdict" style="display:none">
  <h2 id="vTitle" style="font-size:22px">Test result</h2>
  <div class="spin" id="vSpin"></div>
  <div id="vOut"></div>
 </div>
</section>
<section id="t-live"><div id="live"><div class="hint">Waiting for data...</div></div></section>
<section id="t-res">
 <div class="card"><select id="rsess"></select>
 <div class="row" style="margin-top:8px"><input id="rpre" type="number" step="0.5" min="0" value="3" aria-label="pre seconds"><input id="rpost" type="number" step="0.5" min="0" value="3" aria-label="post seconds"><button id="rrun">Run diff</button></div>
 <div class="hint">Seconds before / after each marker. App (remote) commands can take a while to reach the car: use a long "after" (30-60 s).</div>
 <div class="row" style="margin-top:8px"><input id="rsettle" type="number" step="1" min="0" value="2" aria-label="settle seconds"></div>
 <div class="hint">Settle: seconds after Climate ON/OFF ignored for state candidates (the first half of each period is always ignored).</div></div>
 <div class="spin" id="spin"></div><div id="rout"></div>
</section>
<section id="t-files"><div class="hint">Downloads open in a new tab (Safari); use Share from there.</div><div id="files"></div></section>
<footer><div id="addrs"></div><div>Forgot PIN? Delete /data/canlogs/pin.json over SSH.</div><button class="sm" id="lock" style="margin-top:8px">Lock</button></footer>
</main>
<div class="ov" id="run">
 <div class="ovtop"><span class="pill" id="rPill">Climate status: -</span><span class="age" id="rStep"></span></div>
 <div class="prog"><div id="rProg"></div></div>
 <div id="rBan"></div>
 <div class="mid">
  <div id="rText"></div>
  <div class="ring" id="rRing"><svg viewBox="0 0 200 200"><circle class="bg" cx="100" cy="100" r="90"/><circle class="fg" id="rArc" cx="100" cy="100" r="90"/></svg><div id="rNum"></div></div>
  <div id="rClock"></div>
  <div id="rHint"></div>
 </div>
 <div id="rBtns"></div>
 <div class="ovsec"><button class="sm" id="rUndo">Undo last marker</button><button class="sm" id="rPauseBtn">Pause</button><button class="sm dng" id="rAbort">Abort test</button></div>
 <div id="rPause">PAUSED</div>
</div>
<div class="toast" id="toast"></div>
<nav id="nav"><button data-t="test" class="on">Test</button><button data-t="live">Live</button><button data-t="res">Results</button><button data-t="files">Files</button></nav>
<script>
"use strict";
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let st={}, names={}, tab="test", prevLive={}, flashT={}, timers=[], authState=document.body.dataset.auth;
function toast(m,ms){const t=$("toast");t.textContent=m;t.style.display="block";clearTimeout(toast.h);toast.h=setTimeout(()=>t.style.display="none",ms||2200)}
async function api(p,o){
  const r=await fetch(p,Object.assign({credentials:"same-origin",headers:{"Content-Type":"application/json"}},o||{}));
  if(r.status===401&&p!=="/api/login"){setAuth("login");throw new Error("auth")}
  let d={};try{d=await r.json()}catch(e){}
  if(!r.ok){const e=new Error(d.error||r.statusText);e.status=r.status;throw e}
  return d}
function post(p,b){return api(p,{method:"POST",body:JSON.stringify(b||{})})}
function setAuth(s){
  authState=s;document.body.dataset.auth=s;
  if(s==="ok"){startPolling();return}
  stopPolling();
  $("atitle").textContent=s==="setpin"?"Set a PIN":"Enter PIN";
  $("pin2").style.display=s==="setpin"?"block":"none";
  $("asub").textContent=s==="setpin"?"Choose a 4-12 digit PIN to protect this page.":"";
  $("pin").value="";$("pin2").value=""}
$("abtn").onclick=async()=>{
  $("aerr").textContent="";
  try{
    if(authState==="setpin")await post("/api/setpin",{pin:$("pin").value,pin2:$("pin2").value});
    else await post("/api/login",{pin:$("pin").value});
    setAuth("ok")
  }catch(e){$("aerr").textContent=e.message+(e.status===429?" - try again in a minute":"")}};
$("pin").onkeydown=$("pin2").onkeydown=e=>{if(e.key==="Enter")$("abtn").click()};
$("lock").onclick=async()=>{try{await post("/api/logout")}catch(e){}setAuth("login")};
function goTab(t){tab=t;
  document.querySelectorAll("nav button").forEach(b=>b.classList.toggle("on",b.dataset.t===t));
  document.querySelectorAll("section").forEach(s=>s.classList.toggle("on",s.id==="t-"+t));
  if(t==="files"||t==="res")loadSessions();if(t==="live")pollLive()}
$("nav").onclick=e=>{const t=e.target.dataset&&e.target.dataset.t;if(t)goTab(t)};
// ---------------------------------------------------------------- manual mode
const MK=["Climate ON","Climate OFF","Temp up","Temp down"];
$("mgrid").innerHTML=MK.map(m=>`<button data-m="${esc(m)}" class="mk">${esc(m)}</button>`).join("");
async function addMarker(text){
  try{const m=await post("/api/marker",{text});toast("Marker added @ "+Number(m.rel_s).toFixed(1)+" s");
    (st._mk=st._mk||[]).push(m);renderMarkers()}catch(e){if(e.message!=="auth")toast(e.message)}}
$("mgrid").onclick=e=>{if(e.target.dataset.m)addMarker(e.target.dataset.m)};
$("madd").onclick=()=>{const v=$("mtxt").value.trim();if(v){addMarker(v);$("mtxt").value=""}};
$("rec").onclick=async()=>{
  if(T&&!confirm("A guided test is running. Stop logging anyway?"))return;
  try{await post(st.recording?"/api/stop":"/api/start");st._mk=[];pollStatus()}catch(e){if(e.message!=="auth")toast(e.message)}};
function renderMarkers(){const l=st._mk||[];
  $("mlist").innerHTML=l.length?l.map(m=>`<div>${Number(m.rel_s).toFixed(1)} s &nbsp; ${esc(m.text)}</div>`).join(""):"No markers yet"}
function renderStatus(){
  const s=st,r=!!s.recording;
  $("pill").textContent=r?"REC":"IDLE";$("pill").className="pill"+(r?" rec":"");
  $("cdot").className="dot"+(s.can_alive?" on":"");$("ctxt").textContent=s.can_alive?"CAN live":"no CAN";
  const b=$("rec");b.textContent=r?"STOP LOGGING":"START LOGGING";b.className="big"+(r?" stop":"");
  document.querySelectorAll(".mk,#madd").forEach(x=>x.disabled=!r);$("mtxt").disabled=!r;
  $("mhint").textContent=r?"":"Start logging to add markers.";
  const d=Math.floor(s.duration_s||0),bc=s.bus_counts||{};
  $("stats").innerHTML=esc(s.session||"no session")+" &middot; "+String(Math.floor(d/60)).padStart(2,"0")+":"+String(d%60).padStart(2,"0")+
   " &middot; "+(s.frames||0)+" frames &middot; "+((s.bytes||0)/1048576).toFixed(1)+" MB<br>"+
   Object.keys(bc).map(k=>"bus"+k+": "+bc[k]).join(" &middot; ")+" &middot; free "+((s.free_bytes||0)/1073741824).toFixed(1)+" GB"+
   (s.last_error?`<br><span class="err">${esc(s.last_error)}</span>`:"");
  renderMarkers();
  $("addrs").textContent="Reach this page at: "+(s.addrs||[]).map(a=>"http://"+a+":"+location.port).join("  ")}
async function pollStatus(){try{const m=st._mk;st=await api("/api/status");st._mk=st.recording?(m&&m.length>=(st.markers||[]).length?m:st.markers||[]):[];renderStatus();resumeOnce()}catch(e){}}
// ---------------------------------------------------------------- live tab
function hexBytes(id,bus,hex){
  const k=id+"/"+bus,p=prevLive[k]||"",now=Date.now();let o="";
  for(let i=0;i<hex.length;i+=2){const b=hex.substr(i,2);
    if(p&&p.substr(i,2)!==b)flashT[k+i]=now;
    o+=`<span class="byte${now-(flashT[k+i]||0)<600?" f":""}">${b}</span>`}
  prevLive[k]=hex;return o}
async function pollLive(){
  try{const d=await api("/api/live");names=d.names||names;
    const ids=Object.keys(d).filter(k=>k.startsWith("0x"));
    const all=Array.from(new Set(Object.keys(names).concat(ids)));
    $("live").innerHTML=all.map(id=>{const buses=d[id]||{};
      return `<div class="card"><h3>${esc(names[id]||id)} <span class="age mono">${esc(id)}</span></h3>`+
      (Object.keys(buses).sort().map(b=>{const v=buses[b],stale=v.age_s>2;
        return `<div class="busrow"><b>bus ${esc(b)}</b> <span class="age${stale?" stale":""}">${Number(v.age_s).toFixed(2)} s${stale?" stale":""}</span> <span class="age">x${v.count}</span><br>`+
        `<span class="mono">${hexBytes(id,b,String(v.data))}</span><br>`+
        Object.entries(v.decoded||{}).map(([k,x])=>`<span class="chip">${esc(k)}: ${esc(x)}</span>`).join("")+`</div>`}).join("")||`<div class="hint">no frames yet</div>`)+`</div>`}).join("")
  }catch(e){}}
// ---------------------------------------------------------------- files / results
let sessions=[];
const q=s=>encodeURIComponent(s);
async function loadSessions(){
  try{sessions=await api("/api/sessions")}catch(e){return}
  $("files").innerHTML=sessions.map(s=>{const n=q(s.name),mk=Array.isArray(s.markers)?s.markers.length:s.markers;
    return `<div class="card"><b>${esc(s.name)}</b><div class="hint">${(s.bytes/1048576).toFixed(1)} MB &middot; ${mk} markers &middot; ${new Date(s.mtime*1000).toLocaleString()}</div>`+
    `<a class="btn" target="_blank" href="/logs/${n}.canlog">Download</a> <a class="btn" target="_blank" href="/logs/${n}.canlog?gz=1">Download .gz</a> `+
    `<button class="sm blu" data-verdict="${esc(s.name)}">Verdict</button> <button class="sm" data-diff="${esc(s.name)}">Diff</button> <button class="sm dng" data-del="${esc(s.name)}">Delete</button></div>`}).join("")||`<div class="hint">No sessions</div>`;
  const cur=$("rsess").value;
  $("rsess").innerHTML=sessions.map(s=>`<option value="${esc(s.name)}">${esc(s.name)}</option>`).join("");
  if(cur&&sessions.some(s=>s.name===cur))$("rsess").value=cur}
$("files").onclick=async e=>{const t=e.target;
  if(t.dataset.diff){$("rsess").value=t.dataset.diff;goTab("res");runDiff()}
  if(t.dataset.verdict){goTab("test");showVerdict(t.dataset.verdict)}
  if(t.dataset.del&&confirm("Delete "+t.dataset.del+"?")){
    try{await api("/api/sessions/"+q(t.dataset.del),{method:"DELETE"});loadSessions()}catch(er){if(er.message!=="auth")toast(er.message)}}};
$("rrun").onclick=runDiff;
function chipsFor(c){
  const v=x=>typeof x==="number"?x.toString(16).padStart(2,"0"):x;
  const arr=c.bytes||[],a=arr.filter(b=>!b.noisy),n=arr.filter(b=>b.noisy);
  const ch=(b,mu)=>`<span class="chip mono${mu?" mu":""}"${b.why?` title="${esc(b.why)}"`:""}>b${b.i}: ${esc(v(b.last_before))}&rarr;${esc(v(b.first_after))}</span>`;
  return a.map(b=>ch(b)).join("")+(n.length?`<a href="#" class="tg">show ${n.length} noisy</a><span style="display:none">${n.map(b=>ch(b,1)).join("")}</span>`:"")}
function stateCards(d,nm){
  const id=c=>`<td>${c.bus}</td><td class="mono ${nm[c.addr_hex]?"w":""}">${esc(c.addr_hex)}${c.mux?" mux "+esc(c.mux):""}${(nm[c.addr_hex]||c.name)?"<br>"+esc(nm[c.addr_hex]||c.name):""}</td><td class="mono">b${c.i}</td>`;
  const S=d.states||[],T=d.steps||[],P=d.profile||{};
  const ss=S.map(c=>`<tr>${id(c)}<td class="mono">ON ${esc(c.on_vals.join(","))}<br>OFF ${esc(c.off_vals.join(","))}</td><td>${c.on_periods}/${c.off_periods}${c.cyclic?' <span class="age">cyclic</span>':""}</td></tr>`).join("");
  const ts=T.map(c=>`<tr>${id(c)}<td class="mono">${c.dirs.map((s,k)=>(s>0?"up":"dn")+" "+(c.deltas[k]>0?"+":"")+c.deltas[k]).join(", ")}</td><td>${c.matched}/${c.steps}${c.inverted?' <span class="age">inv</span>':""}</td></tr>`).join("");
  return `<div class="card"><h3>State candidates <span class="age">ON vs OFF</span></h3>`+
    (ss?`<table>${ss}</table>`:`<div class="hint">None. Needs Climate ON and Climate OFF markers, each held for a few seconds.</div>`)+
    `<div class="hint">${P.ids||0} ids, ${P.cyclic||0} cyclic/mux, ${P.counter_bytes||0} counter bytes ignored.</div></div>`+
    `<div class="card"><h3>Step candidates <span class="age">Temp up / down</span></h3>`+
    (ts?`<table>${ts}</table>`:`<div class="hint">None. Needs Temp up / Temp down markers.</div>`)+`</div>`}
async function runDiff(){
  const s=$("rsess").value||"latest";$("rout").innerHTML="";$("spin").style.display="block";
  try{const d=await api(`/api/diff?session=${q(s)}&pre=${q($("rpre").value)}&post=${q($("rpost").value)}&settle=${q($("rsettle").value)}`);
    const nm=d.names||names,W=d.watched||[];
    $("rout").innerHTML=`<div class="hint">${esc(d.session)}</div>`+(d.results.length?d.results.map((r,i)=>{
      const m=r.marker||{};const rel=m.rel_s!=null?Number(m.rel_s).toFixed(1)+" s":"";
      const w=W.filter(x=>x.marker===i).map(x=>{const f=p=>p?Object.entries(p.decoded||{}).map(([k,v])=>k+"="+v).join(", ")||p.data:"-";
        return `<div class="hint"><b class="w">${esc(nm[x.id]||x.id)}</b> bus ${x.bus}: ${esc(f(x.before))} &rarr; ${esc(f(x.after))}</div>`}).join("");
      return `<div class="card"><h3>${esc(m.text||"marker")} <span class="age">${rel}</span></h3>${w}<table>`+
       (r.changes||[]).map(c=>{const wn=nm[c.addr_hex];
        return `<tr><td>${c.bus}</td><td class="mono ${wn?"w":""}">${esc(c.addr_hex)}${(wn||c.name)?"<br>"+esc(wn||c.name):""}</td><td>${chipsFor(c)}`+
        (c.new_id?` <span class="badge new">new</span>`:"")+(c.gone_id?` <span class="badge gone">gone</span>`:"")+(c.kind?` <span class="age">${esc(c.kind)}</span>`:"")+`</td></tr>`}).join("")+`</table></div>`}).join(""):`<div class="hint">No markers in this session.</div>`)+stateCards(d,nm)
  }catch(e){if(e.message!=="auth")$("rout").innerHTML=`<div class="err">${esc(e.message)}</div>`}
  $("spin").style.display="none"}
$("rout").onclick=e=>{if(e.target.classList.contains("tg")){e.preventDefault();e.target.nextSibling.style.display="inline";e.target.style.display="none"}};
// ---------------------------------------------------------------- guided tests
// step kinds: wait (auto-advance), act (one button + marker), ask (buttons, optional jump), confirm (button, clock, no auto-advance)
const WAITTXT="Wait — don't touch anything";
function buildSteps(id){
  const S=[],W=(s,t,x)=>S.push(Object.assign({k:"wait",s,t:t||WAITTXT},x||{}));
  const A=(t,b,m,n,x)=>S.push(Object.assign({k:"act",t,b,m,n},x||{}));
  if(id==="A"){
    W(60,"Baseline: don't touch anything");
    for(let i=0;i<6;i++){A("Press CLIMATE ON in the car now","I PRESSED CLIMATE ON","Climate ON",1);W(20);A("Press CLIMATE OFF in the car now","I PRESSED CLIMATE OFF","Climate OFF",1);W(20)}
    for(const [t,b,m] of [["UP","UP","Temp up"],["UP","UP","Temp up"],["DOWN","DOWN","Temp down"],["DOWN","DOWN","Temp down"]]){
      A(`Press TEMPERATURE ${t} once`,`I PRESSED TEMP ${b}`,m,1);W(20)}
    S.push({k:"ask",t:"Optional: send a remote climate START from the VW app now",bs:[{l:"I SENT IT",m:"Remote START sent"},{l:"SKIP",go:"tail"}]});
    S.push({k:"confirm",t:"Tap when the app says it worked",b:"APP SAYS IT WORKED",m:"Remote START confirmed",cd:120});
    W(30,"Almost done: don't touch anything",{id:"tail"});
  }else if(id==="B"){
    W(60,"Baseline: don't touch anything");
    A("Open the VW app. Don't send anything.","I OPENED THE APP","App opened");W(60);
    A("Send remote climate START now","I SENT START","Remote START sent");
    S.push({k:"confirm",t:"Tap when the app confirms",b:"APP CONFIRMED START",m:"Remote START confirmed"});W(60);
    A("Send remote climate STOP now","I SENT STOP","Remote STOP sent");
    S.push({k:"confirm",t:"Tap when the app confirms",b:"APP CONFIRMED STOP",m:"Remote STOP confirmed"});W(60,"Last wait: don't touch anything");
  }else{
    W(30,"Baseline: don't touch anything");
    A("Unlock the car with the key fob now","I PRESSED UNLOCK","Fob unlock");W(60);
  }
  return S}
const TESTS={
  A:{name:"A. Climate buttons in the car",alive:true,pre:["Comma plugged into the car","Car switched on","Always Offroad is ON (Settings → Device)","Phone connected to the comma"]},
  B:{name:"B. Remote start from the VW app",alive:false,pre:["Car locked and asleep (untouched for 5+ minutes)","Phone connected to the comma","Max Time Offroad is 0"]},
  C:{name:"C. Wake-up only (key fob)",alive:false,pre:["Car locked and asleep (untouched for 5+ minutes)","Phone connected to the comma","Max Time Offroad is 0"]}};
const LSK="canlog_test_v1";
let T=null, STEPS=[], busy=false, pendingId=null, AC=null, WL=null, resumed=false, liveBusy=false;
function save(){try{if(T)localStorage.setItem(LSK,JSON.stringify(T));else localStorage.removeItem(LSK)}catch(e){}}
function loadT(){try{return JSON.parse(localStorage.getItem(LSK)||"null")}catch(e){return null}}
function prime(){try{AC=AC||new (window.AudioContext||window.webkitAudioContext)();if(AC.state==="suspended")AC.resume()}catch(e){}}
document.addEventListener("pointerdown",prime,{passive:true});
function beep(n){try{prime();for(let i=0;i<(n||1);i++){const o=AC.createOscillator(),g=AC.createGain(),t0=AC.currentTime+i*.3;
  o.frequency.value=880;g.gain.value=.3;o.connect(g);g.connect(AC.destination);o.start(t0);o.stop(t0+.2)}}catch(e){}
  try{navigator.vibrate&&navigator.vibrate(150)}catch(e){}}
async function wake(){try{if(T&&navigator.wakeLock&&!WL){WL=await navigator.wakeLock.request("screen");WL.addEventListener("release",()=>{WL=null})}}catch(e){WL=null}}
function unwake(){try{WL&&WL.release()}catch(e){}WL=null}
const fmt=s=>{s=Math.max(0,Math.floor(s));return Math.floor(s/60)+":"+String(s%60).padStart(2,"0")};
function showHome(){$("tHome").style.display="";$("tPre").style.display="none";$("tVerdict").style.display="none"}
document.querySelectorAll("[data-start]").forEach(b=>b.onclick=()=>showPre(b.dataset.start));
function showPre(id){
  pendingId=id;const t=TESTS[id];$("pTitle").textContent=t.name;$("pErr").style.display="none";
  $("pList").innerHTML=t.pre.map((x,i)=>`<label class="chk"><input type="checkbox" data-c="${i}"><span>${esc(x)}</span></label>`).join("");
  $("pGo").disabled=true;$("tHome").style.display="none";$("tVerdict").style.display="none";$("tPre").style.display="";window.scrollTo(0,0)}
$("pList").onchange=()=>{$("pGo").disabled=!Array.from($("pList").querySelectorAll("input")).every(c=>c.checked)};
$("pBack").onclick=showHome;
function startError(title,items){$("pErr").innerHTML=`<b>${esc(title)}</b><ul>${items.map(x=>`<li>${esc(x)}</li>`).join("")}</ul>`;$("pErr").style.display="block";$("pErr").scrollIntoView()}
$("pGo").onclick=()=>beginTest(pendingId);
async function beginTest(id){
  prime();$("pErr").style.display="none";const t=TESTS[id];let s;
  try{s=await api("/api/status")}catch(e){if(e.message!=="auth")startError("Cannot reach the comma",["Is your phone still connected to the comma's Wi-Fi / hotspot?","Reload this page and try again."]);return}
  if(!s.can_alive){
    if(t.alive)return startError("No CAN data from the car",["Is the comma plugged into the car (OBD / harness)?","Is the car switched on (ignition / READY)?","Is Always Offroad ON (Settings → Device)? Otherwise the comma may be asleep or off.","Wait a few seconds and try again."]);
    if(!confirm("No CAN data right now. That is normal if the car is asleep. Start logging anyway?"))return}
  if(s.recording){if(!confirm("A recording is already running. Stop it and start this test?"))return;try{await post("/api/stop")}catch(e){}}
  let r;
  try{r=await post("/api/start")}catch(e){if(e.message!=="auth")startError("Could not start logging: "+e.message,["Is there free space on the comma? (see Manual mode)","Check the comma is awake and the canlog service is running."]);return}
  T={id,session:r.session,idx:0,cnt:{},last:null,dl:0,t0:0,pat:0};
  STEPS=buildSteps(id);enterStep(0);$("run").classList.add("on");wake();showHome();pollStatus()}
function enterStep(i){
  const s=STEPS[i],now=Date.now();T.idx=i;T.t0=now;T.pat=0;T.dl=now+((s.s||s.cd||0)*1000);save();showStep()}
function nextStep(go){
  let i=T.idx+1;
  if(go){const j=STEPS.findIndex(x=>x.id===go);if(j>=0)i=j}
  if(i>=STEPS.length)return finishTest(false);
  enterStep(i)}
function showStep(){
  const s=STEPS[T.idx],n=STEPS.length;
  $("rStep").textContent=`Step ${T.idx+1} of ${n}`;$("rProg").style.width=(T.idx/n*100)+"%";
  $("rText").textContent=s.t;
  $("rRing").style.display=s.k==="wait"?"block":"none";
  $("rClock").style.display=s.k==="confirm"?"block":"none";
  $("rHint").textContent=s.k==="wait"?"Logging is running":(s.k==="confirm"?(s.cd?"Time left to get the answer":"Time since you sent it"):"");
  let h="";
  if(s.k==="act")h=`<button class="giant" data-a="0">${esc(s.b)}</button>`;
  else if(s.k==="confirm")h=`<button class="giant" data-a="0">${esc(s.b)}</button>`;
  else if(s.k==="ask")h=s.bs.map((b,i)=>`<button class="giant${i?" alt":""}" data-a="${i}">${esc(b.l)}</button>`).join("");
  $("rBtns").innerHTML=h;
  $("rUndo").disabled=!T.last;$("rPauseBtn").textContent=T.pat?"Resume":"Pause";
  tick()}
async function mark(m,numbered){
  let text=m;
  if(numbered){T.cnt[m]=(T.cnt[m]||0)+1;text=m+" #"+T.cnt[m]}
  try{await post("/api/marker",{text});T.last={idx:T.idx,base:numbered?m:null};save();return true}
  catch(e){if(numbered)T.cnt[m]--;if(e.message!=="auth")toast("Marker NOT saved: "+e.message+". Is logging running?",4000);return false}}
$("rBtns").onclick=async e=>{
  const b=e.target.closest("button[data-a]");if(!b||!T||busy||T.pat)return;
  const s=STEPS[T.idx],a=s.k==="ask"?s.bs[+b.dataset.a]:s;busy=true;
  try{if(a.m&&!await mark(a.m,a.n))return;nextStep(a.go)}finally{busy=false}};
$("rUndo").onclick=async()=>{
  if(!T||!T.last||busy)return;busy=true;
  try{await post("/api/marker",{text:"UNDO previous"});const l=T.last;if(l.base)T.cnt[l.base]--;T.last=null;toast("Last marker undone");enterStep(l.idx)}
  catch(er){if(er.message!=="auth")toast("Undo failed: "+er.message)}finally{busy=false}};
$("rPauseBtn").onclick=()=>{
  if(!T)return;const now=Date.now();
  if(T.pat){const d=now-T.pat;T.dl+=d;T.t0+=d;T.pat=0}else T.pat=now;
  save();$("rPauseBtn").textContent=T.pat?"Resume":"Pause";tick()};
$("rAbort").onclick=()=>{if(T&&confirm("Abort the test? Logging stops and the file is kept."))finishTest(true)};
async function finishTest(abort){
  const sess=T.session;
  try{await post("/api/stop")}catch(e){if(e.message!=="auth")toast("Could not stop logging: "+e.message,4000)}
  T=null;STEPS=[];save();unwake();$("run").classList.remove("on");pollStatus();goTab("test");
  if(abort){showHome();toast("Test aborted. Log kept: "+sess,4000)}
  else{beep(3);showVerdict(sess)}}
function ringSet(frac){$("rArc").style.strokeDashoffset=String(565.5*(1-Math.max(0,Math.min(1,frac))))}
function tick(){
  if(!T||!STEPS.length)return;
  const s=STEPS[T.idx],now=Date.now(),ref=T.pat||now;
  if(!T.pat&&s.k==="wait"&&now>=T.dl&&!busy){beep(1);nextStep();return}
  if(s.k==="wait"){const r=Math.max(0,T.dl-ref);$("rNum").textContent=Math.ceil(r/1000);ringSet(r/(s.s*1000))}
  else if(s.k==="confirm"){const c=s.cd?(T.dl-ref)/1000:(ref-T.t0)/1000;
    $("rClock").textContent=(c<0?"+":"")+fmt(Math.abs(c))}
  $("rPause").style.display=T.pat?"flex":"none";
  const ban=$("rBan"),bad=st&&st.recording===false?"Logging is NOT running! Abort the test and start again.":(st&&st.can_alive===false&&TESTS[T.id].alive?"No CAN data right now. Check the comma is still connected to the car.":"");
  ban.style.display=bad?"block":"none";ban.textContent=bad}
setInterval(tick,250);
function climatePill(d){
  const p=$("rPill");let best=null;
  const k=Object.keys(d).find(k=>k.startsWith("0x")&&parseInt(k,16)===0x3B5);
  if(k){const bs=d[k];const b=bs["1"]||bs[Object.keys(bs).sort((x,y)=>bs[x].age_s-bs[y].age_s)[0]];if(b&&b.age_s<3&&b.decoded&&typeof b.decoded.climate_on_candidate==="boolean")best=b.decoded.climate_on_candidate}
  p.textContent="Climate status: "+(best===null?"-":best?"ON":"OFF")+" (candidate)";
  p.className="pill"+(best===null?"":best?" on":" off")}
async function pollTestLive(){if(!T||liveBusy||document.hidden)return;liveBusy=true;try{climatePill(await api("/api/live"))}catch(e){}liveBusy=false}
function resumeOnce(){
  if(resumed||authState!=="ok")return;resumed=true;const x=loadT();if(!x||!TESTS[x.id])return;
  if(!st.recording||st.session!==x.session){try{localStorage.removeItem(LSK)}catch(e){}
    toast("The test ended while this page was closed. Showing its result.",4000);showVerdict(x.session);return}
  T=x;STEPS=buildSteps(T.id);if(T.idx>=STEPS.length){finishTest(false);return}
  $("run").classList.add("on");showStep();wake()}
// ---------------------------------------------------------------- verdict
const LV={green:"LOOKS RIGHT",yellow:"MAYBE",red:"NO"};
async function showVerdict(sess){
  $("tHome").style.display="none";$("tPre").style.display="none";$("tVerdict").style.display="";
  $("vOut").innerHTML="";$("vSpin").style.display="block";$("vTitle").textContent="Analysing "+sess+" ...";window.scrollTo(0,0);
  let v;
  try{v=await api("/api/verdict?session="+q(sess))}
  catch(e){$("vSpin").style.display="none";$("vTitle").textContent="Test result";if(e.message!=="auth")$("vOut").innerHTML=`<div class="box bad">Could not analyse: ${esc(e.message)}</div><button class="sm" id="vDone" style="width:100%">Done</button>`;bindDone();return}
  $("vSpin").style.display="none";$("vTitle").textContent="Test result";
  const ev=c=>c.events.length?`<table><tr><th>Marker</th><th>at</th><th>Result</th><th>Changed after</th></tr>`+c.events.map(e=>
    `<tr><td>${esc(e.text)}</td><td>${e.rel_s} s</td><td>${e.ok===null?esc(e.note):(e.ok?"yes":"no")+(e.note?" ("+esc(e.note)+")":"")}</td><td>${e.flip_s===null?"-":e.flip_s+" s"}</td></tr>`).join("")+`</table>`:`<div class="hint">No matching markers.</div>`;
  let h=v.candidates.map(c=>`<div class="vline ${c.level}"><span class="badge" style="background:#0006">${LV[c.level]}</span> ${esc(c.summary)}</div>`+
    `<details class="sub"><summary>Details: ${esc(c.label)} (${esc(c.addr_hex)}, bus ${c.bus}, ${c.frames} frames)</summary>${ev(c)}</details>`).join("");
  const bs=Object.keys(v.buses||{});
  h+=`<div class="card"><h3>What was recorded</h3><div>${v.markers} markers, ${v.log_seconds} s of log</div>`+
    (bs.length?bs.map(b=>`<div class="hint">Bus ${b}: ${v.buses[b].frames} frames, ${v.buses[b].ids} different ids</div>`).join(""):`<div class="err">No CAN frames in this log at all.</div>`)+
    (v.notes||[]).map(n=>`<div class="hint">${esc(n)}</div>`).join("")+`</div>`;
  const sc=(v.states||[]).map(c=>`<tr><td>bus ${c.bus}</td><td class="mono">${esc(c.addr_hex)}${c.mux?" mux "+esc(c.mux):""} b${c.i}</td><td class="mono">ON ${esc(c.on_vals.join(","))} / OFF ${esc(c.off_vals.join(","))}</td></tr>`).join("");
  const tc=(v.steps||[]).map(c=>`<tr><td>bus ${c.bus}</td><td class="mono">${esc(c.addr_hex)}${c.mux?" mux "+esc(c.mux):""} b${c.i}</td><td class="mono">${c.matched}/${c.steps} ${c.inverted?"inverted":""}</td></tr>`).join("");
  h+=`<details class="sub"><summary>Details: other bytes that follow the buttons</summary><div class="hint">Climate ON/OFF</div>${sc?`<table>${sc}</table>`:`<div class="hint">None found.</div>`}<div class="hint">Temp up/down</div>${tc?`<table>${tc}</table>`:`<div class="hint">None found.</div>`}</details>`;
  h+=`<div class="row" style="margin:12px 0"><a class="btn" style="min-height:56px" target="_blank" href="/logs/${q(v.session)}.canlog?gz=1">Download log (.gz)</a><button id="vDiff">Run diff</button></div>`+
    `<button class="giant alt" id="vDone">DONE</button>`;
  $("vOut").innerHTML=h;bindDone();
  $("vDiff").onclick=async()=>{goTab("res");await loadSessions();$("rsess").value=v.session;runDiff()}}
function bindDone(){const b=$("vDone");if(b)b.onclick=showHome}
// ---------------------------------------------------------------- polling
function startPolling(){stopPolling();pollStatus();timers=[setInterval(()=>{if(!document.hidden&&tab==="live")pollLive()},500),setInterval(()=>{if(!document.hidden){pollStatus();pollTestLive()}},1000)]}
function stopPolling(){timers.forEach(clearInterval);timers=[]}
document.addEventListener("visibilitychange",()=>{if(!document.hidden&&authState==="ok"){pollStatus();if(tab==="live")pollLive();if(T){wake();tick()}}});
setAuth(authState);
</script></body></html>
"""
