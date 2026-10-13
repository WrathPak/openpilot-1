"""Run the CAN log web UI on a PC with a fake recorder: CANLOG_BIND_ANY=1 python -m openpilot.sunnypilot.canlog.tools.dev_webui [port]"""
import os
import random
import sys
import threading
import time
from typing import Any

from openpilot.sunnypilot.canlog import webui
from openpilot.sunnypilot.canlog.decode import decode, fmt_addr

IDS = {0x16A954FB: "Climate setpoint", 0x16A95493: "Heating active", 0x1B000010: "NMH_Gateway"}


class FakeRecorder:
  def __init__(self, root: str | None = None) -> None:
    self.root = root or os.environ.get("CANLOG_ROOT") or os.path.join(os.path.expanduser("~"), ".canlog_dev")
    os.makedirs(self.root, exist_ok=True)
    self.recording = False
    self.session: str | None = None
    self.t0 = 0.0
    self.markers: list[dict] = []
    self.lock = threading.Lock()

  def _path(self, name: str) -> str:
    return os.path.join(self.root, name + ".canlog")

  def start_session(self) -> str:
    self.session = time.strftime("session_%Y%m%d_%H%M%S")
    self.t0, self.markers, self.recording = time.time(), [], True
    with open(self._path(self.session), "w") as f:
      f.write("# fake canlog\n")
    return self.session

  def stop_session(self) -> str | None:
    self.recording = False
    return self.session

  def add_marker(self, text: str) -> dict:
    if not self.recording:
      raise RuntimeError("Not recording")
    rel = time.time() - self.t0
    m = {"t": int(rel * 1e9), "rel_s": round(rel, 2), "wall": time.strftime("%H:%M:%S"), "text": text}
    self.markers.append(m)
    with open(self._path(self.session or ""), "a") as f:
      f.write(f"M {m['t']} {text}\n")
    return m

  def status(self) -> dict:
    d = time.time() - self.t0 if self.recording else 0.0
    return {"recording": self.recording, "session": self.session, "frames": int(d * 800), "bytes": int(d * 800 * 40),
            "duration_s": d, "markers": list(self.markers), "bus_counts": {"0": int(d * 500), "1": 0, "2": int(d * 300)},
            "can_alive": True, "free_bytes": 20 * 1024 ** 3, "log_root": self.root, "last_error": None}

  def latest(self) -> dict:
    now = time.time()
    out: dict[str, Any] = {}
    for a in IDS:
      flip = int(now * 2) % 2
      out[fmt_addr(a)] = {str(b): {"t": int(now * 1e9), "age_s": random.random() * 0.2, "count": int(now) % 100000,
                                   "data": bytes([int(now) % 256, 0x31 if flip else 0x30, 0, 1, 2, 3, 4, 5]).hex().upper(),
                                   "decoded": {"setpoint": "%.1f C" % (20 + int(now) % 5)}} for b in (0, 2)}
    on = (int(now) // 10) % 2 == 1  # climate status candidate toggles every 10 s
    d3b5 = bytes([0x80 if on else 0x00, 1, 2, 3, 4, 5, 6, 7])
    out[fmt_addr(0x3B5)] = {"1": {"t": int(now * 1e9), "age_s": random.random() * 0.2, "count": int(now * 50) % 100000,
                                  "data": d3b5.hex().upper(), "decoded": decode(0x3B5, d3b5)}}
    d668 = bytes([0, 0, 0, int(now) % 256, 0, 0, 0, 0x10 if on else 0x00])[:8]
    out[fmt_addr(0x668)] = {"0": {"t": int(now * 1e9), "age_s": random.random() * 0.2, "count": int(now * 10) % 100000,
                                  "data": d668.hex().upper(), "decoded": decode(0x668, d668)}}
    return out

  def list_sessions(self) -> list[dict]:
    fs = sorted((f for f in os.listdir(self.root) if f.endswith(".canlog")), key=lambda f: -os.path.getmtime(os.path.join(self.root, f)))
    return [{"name": f[:-7], "file": f, "bytes": os.path.getsize(os.path.join(self.root, f)),
             "mtime": os.path.getmtime(os.path.join(self.root, f)), "markers": 0} for f in fs]

  def session_path(self, name: str) -> str | None:
    if not name or "/" in name or "\\" in name or name.startswith("."):
      return None
    p = self._path(name)
    return p if os.path.isfile(p) else None


def _install_fake_analyze() -> None:
  try:
    from openpilot.sunnypilot.canlog import analyze  # noqa: F401
    return
  except Exception:
    pass
  import types
  m = types.ModuleType("openpilot.sunnypilot.canlog.analyze")
  m.read_log = lambda p, windows=None: ({}, [(int(1e9 * i), 0, 0x16A954FB, bytes([i, 0, 0, 0])) for i in range(10)], [{"t": int(4.5e9), "text": "fake"}])  # type: ignore
  m.diff_around_markers = lambda f, mk, pre_s=3.0, post_s=3.0: [{"marker": {**mk[0], "rel_s": 4.5}, "changes": [  # type: ignore
    {"bus": 0, "addr": 0x16A954FB, "addr_hex": "0x16A954FB", "name": "", "new_id": False, "gone_id": False, "score": 5,
     "bytes": [{"i": 0, "last_before": 4, "first_after": 5, "noisy": False}, {"i": 1, "last_before": 0, "first_after": 9, "noisy": True}]}]}]
  m.diff_file = lambda p, pre_s=3.0, post_s=3.0: ({}, [{"t": int(4.5e9), "text": "fake"}], m.diff_around_markers([], [{"t": int(4.5e9), "text": "fake"}]), [])  # type: ignore
  m.analyze_file = lambda p, pre_s=3.0, post_s=3.0, settle_s=2.0, **kw: {  # type: ignore
    "markers": [{"t": int(4.5e9), "text": "fake"}], "diff": m.diff_around_markers([], [{"t": int(4.5e9), "text": "fake"}]), "frames": [],
    "states": [{"bus": 0, "addr": 0x300, "addr_hex": "0x00000300", "name": "", "mux": None, "i": 2, "cyclic": False,
                "on_vals": ["05"], "off_vals": ["00"], "on_periods": 2, "off_periods": 2, "score": 40}],
    "steps": [], "profile": types.SimpleNamespace(summary=lambda: {"ids": 1, "cyclic": 0, "counter_bytes": 0})}
  sys.modules[m.__name__] = m
  import openpilot.sunnypilot.canlog as pkg
  pkg.analyze = m  # type: ignore


def main() -> None:
  _install_fake_analyze()
  port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
  srv = webui.serve(FakeRecorder(), port)
  print("serving", srv.addresses, flush=True)
  try:
    while True:
      time.sleep(1)
  except KeyboardInterrupt:
    srv.shutdown()


if __name__ == "__main__":
  main()
