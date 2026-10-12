import os
import shutil
import socket
import threading
import time
from datetime import datetime

from openpilot.sunnypilot.canlog import config
from openpilot.sunnypilot.canlog.decode import WATCH, decode, fmt_addr

Frame = tuple[int, bytes, int]


class Recorder:
  def __init__(self, log_root: str | None = None):
    self.log_root = log_root or config.log_root()
    self._lock = threading.Lock()
    self._stop = threading.Event()
    self._f = None
    self._name: str | None = None
    self._path: str | None = None
    self._start_mono_ns = 0
    self._start_t = 0.0
    self._frames = 0
    self._bytes = 0
    self._bus_counts = {"0": 0, "1": 0, "2": 0}
    self._markers: list[dict] = []
    self._last_mono_ns = 0
    self._last_event_t = 0.0
    self._last_flush = 0.0
    self._last_error: str | None = None
    self._latest: dict[int, dict[int, dict]] = {}
    self._sess_cache: dict[str, tuple[float, int, int]] = {}
    try:
      os.makedirs(self.log_root, exist_ok=True)
    except OSError as e:
      self._last_error = f"mkdir: {e}"
    self._remove_flag()

  @property
  def _flag(self) -> str:
    return config.keep_awake_path(self.log_root)

  def _remove_flag(self) -> None:
    try:
      os.remove(self._flag)
    except OSError:
      pass

  @property
  def recording(self) -> bool:
    return self._f is not None

  def _now_ns(self) -> int:
    return self._last_mono_ns or time.monotonic_ns()

  def _write(self, line: str) -> None:
    try:
      self._f.write(line)
    except OSError as e:
      self._last_error = f"write: {e}"
      self._close_locked()
      config.get_log().warning("canlog: write failed, session closed: %s", e)
      return
    self._bytes += len(line)

  def start_session(self) -> str:
    with self._lock:
      if self._f is not None:
        return self._name  # type: ignore[return-value]
      os.makedirs(self.log_root, exist_ok=True)
      now = datetime.now()
      stem = now.strftime("%Y-%m-%d_%H-%M-%S")
      name, n = stem, 0
      while os.path.exists(os.path.join(self.log_root, name + config.EXT)):
        n += 1
        name = f"{stem}_{n}"
      path = os.path.join(self.log_root, name + config.EXT)
      with open(self._flag, "w"):
        pass
      self._f = open(path, "x", buffering=1024 * 1024, encoding="utf-8", newline="\n")
      self._name, self._path = name, path
      self._start_mono_ns = self._now_ns()
      self._start_t = self._last_flush = time.monotonic()
      self._frames = self._bytes = 0
      self._bus_counts = {"0": 0, "1": 0, "2": 0}
      self._markers = []
      self._write(f"# canlog v1 started={now.isoformat(timespec='seconds')} mono_ns={self._start_mono_ns} device={socket.gethostname()}\n")
      self._f.flush()
      config.get_log().info("canlog: started %s", name)
      return name

  def _close_locked(self) -> str | None:
    name = self._name
    if self._f is not None:
      try:
        self._f.flush()
        self._f.close()
      except OSError as e:
        self._last_error = f"close: {e}"
    self._f = None
    self._name = self._path = None
    self._remove_flag()
    return name

  def stop_session(self) -> str | None:
    with self._lock:
      if self._f is None:
        return None
      name = self._close_locked()
      config.get_log().info("canlog: stopped %s", name)
      return name

  def shutdown(self) -> None:
    self._stop.set()
    self.stop_session()
    self._remove_flag()

  def add_marker(self, text: str) -> dict:
    text = " ".join(str(text).split())
    with self._lock:
      if self._f is None:
        raise RuntimeError("not recording")
      t = self._now_ns()
      m = {"t": t, "rel_s": max(0.0, (t - self._start_mono_ns) / 1e9),
           "wall": datetime.now().isoformat(timespec="seconds"), "text": text}
      self._write(f"M {t} {text}\n")
      self._f.flush()
      self._markers.append(m)
      return m

  def _handle_event(self, mono_ns: int, frames: list[Frame]) -> None:
    now = time.monotonic()
    with self._lock:
      self._last_mono_ns = mono_ns
      self._last_event_t = now
      for addr, data, src in frames:
        if src >= 128:
          continue
        data = bytes(data)
        if addr in WATCH:
          e = self._latest.setdefault(addr, {}).setdefault(src, {"count": 0})
          e.update(t=mono_ns, mono=now, data=data.hex().upper(), count=e["count"] + 1)
        if self._f is not None:
          self._write(f"F {mono_ns} {src} {addr:08X} {data.hex().upper()}\n")
          if self._f is None:
            break  # write failed and closed the session
          self._frames += 1
          k = str(src)
          self._bus_counts[k] = self._bus_counts.get(k, 0) + 1

  def _tick(self) -> None:
    now = time.monotonic()
    with self._lock:
      if self._f is None:
        return
      if now - self._last_flush < 1.0:
        return
      try:
        self._f.flush()
      except OSError as e:
        self._last_error = f"flush: {e}"
        self._close_locked()
        return
      self._last_flush = now
      reason = None
      if now - self._start_t > config.MAX_SESSION_S:
        reason = f"session longer than {config.MAX_SESSION_S // 3600} h"
      try:
        if shutil.disk_usage(self.log_root).free < config.MIN_FREE_BYTES:
          reason = "free space below 3 GiB"
      except OSError:
        pass
      if reason is None and self._bytes > config.MAX_FILE_BYTES:
        reason = "session file exceeds 2 GiB"
      if reason:
        self._write(f"M {self._now_ns()} AUTO-STOP: {reason}\n")
        self._last_error = f"AUTO-STOP: {reason}"
        self._close_locked()
        config.get_log().warning("canlog: AUTO-STOP: %s", reason)

  def run(self) -> None:
    while not self._stop.is_set():
      try:
        from openpilot.cereal import messaging
        sock = messaging.sub_sock("can", timeout=100)
        while not self._stop.is_set():
          for ev in messaging.drain_sock(sock, wait_for_one=True):
            self._handle_event(ev.logMonoTime, [(c.address, bytes(c.dat), c.src) for c in ev.can])
          self._tick()
      except Exception as e:
        self._last_error = f"{type(e).__name__}: {e}"
        try:
          config.get_log().exception("canlog: messaging error")
        except Exception:
          pass
        self._stop.wait(1.0)

  def status(self) -> dict:
    with self._lock:
      rec = self._f is not None
      try:
        free = shutil.disk_usage(self.log_root).free
      except OSError:
        free = 0
      return {
        "recording": rec, "session": self._name, "frames": self._frames if rec else 0,
        "bytes": self._bytes if rec else 0,
        "duration_s": (time.monotonic() - self._start_t) if rec else 0.0,
        "markers": list(self._markers) if rec else [],
        "bus_counts": dict(self._bus_counts) if rec else {"0": 0, "1": 0, "2": 0},
        "can_alive": bool(self._last_event_t) and (time.monotonic() - self._last_event_t) < 2.0,
        "free_bytes": free, "log_root": self.log_root, "last_error": self._last_error,
      }

  def latest(self) -> dict:
    now = time.monotonic()
    out: dict = {}
    with self._lock:
      for addr, buses in self._latest.items():
        d = {}
        for bus, e in buses.items():
          d[str(bus)] = {"t": e["t"], "age_s": now - e["mono"], "data": e["data"],
                         "decoded": decode(addr, bytes.fromhex(e["data"])), "count": e["count"]}
        out[fmt_addr(addr)] = d
    return out

  def list_sessions(self) -> list[dict]:
    res = []
    try:
      names = os.listdir(self.log_root)
    except OSError:
      return res
    for fn in names:
      if not fn.endswith(config.EXT):
        continue
      p = os.path.join(self.log_root, fn)
      try:
        st = os.stat(p)
      except OSError:
        continue
      c = self._sess_cache.get(p)
      if p == self._path:
        c = (st.st_mtime, st.st_size, len(self._markers))  # active session: no rescan of a growing file
      elif c is None or c[0] != st.st_mtime or c[1] != st.st_size:
        n = 0
        try:
          with open(p, "rb") as f:
            for line in f:
              if line.startswith(b"M "):
                n += 1
        except OSError:
          pass
        c = (st.st_mtime, st.st_size, n)
        self._sess_cache[p] = c
      res.append({"name": fn[:-len(config.EXT)], "file": os.path.abspath(p), "bytes": st.st_size,
                  "mtime": st.st_mtime, "markers": c[2]})
    res.sort(key=lambda r: r["mtime"], reverse=True)
    return res

  def session_path(self, name: str) -> str | None:
    if not name or ".." in name or "/" in name or "\\" in name or os.sep in name:
      return None
    p = os.path.join(self.log_root, name + config.EXT)
    return os.path.abspath(p) if os.path.isfile(p) else None
