import argparse
import bisect
import json
import os
import sys
from collections import defaultdict

from openpilot.sunnypilot.canlog import config
from openpilot.sunnypilot.canlog.decode import WATCH, decode, fmt_addr, parse_addr

Frame = tuple[int, int, int, bytes]


def _parse_header(s: str) -> dict:
  header: dict = {}
  toks = s.split(" ")
  for tok in toks[2:]:
    if "=" in tok:
      k, v = tok.split("=", 1)
      header[k] = v
  if "mono_ns" in header:
    try:
      header["mono_ns"] = int(header["mono_ns"])
    except ValueError:
      del header["mono_ns"]
  header["version"] = toks[2] if len(toks) > 2 else "v1"
  return header


def read_markers(path: str) -> tuple[dict, list[dict]]:
  """Cheap scan: header + markers only (no frame parsing)."""
  header: dict = {}
  markers: list[dict] = []
  with open(path, "rb") as f:
    for ln in f:
      if ln[:2] == b"M ":
        p = ln.decode("utf-8", "replace").rstrip("\r\n").split(" ", 2)
        try:
          markers.append({"t": int(p[1]), "text": p[2] if len(p) > 2 else ""})
        except (ValueError, IndexError):
          pass
      elif ln[:8] == b"# canlog" and not header:
        header = _parse_header(ln.decode("utf-8", "replace").rstrip("\r\n"))
  return header, markers


def log_end(path: str) -> int | None:
  """Timestamp of the last complete frame (reads only the file's tail)."""
  with open(path, "rb") as f:
    f.seek(0, os.SEEK_END)
    f.seek(max(0, f.tell() - 65536))
    tail = f.read().split(b"\n")[:-1]  # drop the (possibly truncated) part after the last newline
  for ln in reversed(tail):
    if ln[:2] == b"F ":
      try:
        return int(ln.split(b" ")[1])
      except (ValueError, IndexError):
        continue
  return None


def read_log(path: str, windows: list[tuple[int, int]] | None = None,
             profile: "Profile | None" = None) -> tuple[dict, list[Frame], list[dict]]:
  """Stream-parse a .canlog. `windows` = [(t0, t1), ...] in mono ns keeps only frames inside any window.
  `profile`, if given, sees every frame of the log (windowed or not)."""
  header: dict = {}
  frames: list[Frame] = []
  markers: list[dict] = []
  if windows:
    merged: list[tuple[int, int]] = []
    for a, b in sorted(windows):
      if merged and a <= merged[-1][1]:
        merged[-1] = (merged[-1][0], max(merged[-1][1], b))
      else:
        merged.append((a, b))
    windows = merged
  else:
    windows = None
  with open(path, "rb") as f:
    for ln in f:
      complete = ln.endswith(b"\n")
      try:
        s = ln.decode("utf-8", "replace").rstrip("\r\n")
        if not s:
          continue
        if s[0] == "F":
          if not complete:
            continue  # truncated last line
          p = s.split(" ")
          if len(p) != 5 or len(p[4]) % 2:
            continue
          t = int(p[1])
          if profile is not None:
            fr = (t, int(p[2]), int(p[3], 16), bytes.fromhex(p[4]))
            profile.add(*fr)
          else:
            fr = None
          if windows is not None:
            i = bisect.bisect_right(windows, (t, float("inf"))) - 1
            if i < 0 or windows[i][1] < t:
              continue
          frames.append(fr or (t, int(p[2]), int(p[3], 16), bytes.fromhex(p[4])))
        elif s[0] == "M":
          p = s.split(" ", 2)
          markers.append({"t": int(p[1]), "text": p[2] if len(p) > 2 else ""})
        elif s.startswith("# canlog") and not header:
          header = _parse_header(s)
      except (ValueError, IndexError):
        continue
  return header, frames, markers


# ---------------------------------------------------------------- whole-log profile
MUX_MAX = 32          # byte0 with at most this many values that flips on most frames = mux selector / BAP channel
PAYLOAD_CAP = 512     # distinct payloads remembered per id (beyond that: not cyclic)
HIST_CAP = 8192       # (mux, byte, value) first-seen entries per id
SEQ_CAP = 20000       # payload transitions remembered per id for period detection
PERIOD_MAX = 64       # longest payload cycle looked for (BAP: 9-13 payloads)
COUNTER_MIN_CHANGES = 8
CYCLE_MIN_CHANGES = 8      # a cycle/mux keeps changing; a human-driven state toggling ON/OFF/ON/OFF must not qualify
CYCLE_MIN_RATE_HZ = 0.2
NOISE_MIN_DISTINCT = 8


def _hx(b: int) -> str:
  return f"{b:02X}"


def _pop(x: int) -> int:
  return bin(x).count("1")


def _vals(mask: int) -> list[str]:
  return [_hx(v) for v in range(256) if mask >> v & 1]


def _match(text: str, pat: str) -> bool:
  return text.strip().casefold().startswith(pat.strip().casefold())


SETTLE_FRAC = 0.5  # remote (app) commands can take many seconds to reach the car: only trust the 2nd half of a period


def state_periods(markers: list[dict], on_text: str = "Climate ON", off_text: str = "Climate OFF",
                  settle_s: float = 2.0, end_t: int | None = None) -> list[tuple[int, int, str]]:
  """[(start, end, "on"|"off")]: each on/off marker until the next on/off marker, skipping the first settle_s and
  the first half of the period (the last period ends at `end_t` when known), so slow command delivery doesn't blur the sets."""
  ev = sorted((m["t"], "on" if _match(m.get("text", ""), on_text) else "off") for m in markers
              if _match(m.get("text", ""), on_text) or _match(m.get("text", ""), off_text))
  out = []
  for j, (t, lab) in enumerate(ev):
    end = ev[j + 1][0] if j + 1 < len(ev) else (end_t + 1 if end_t is not None else 2 ** 63)
    start = t + max(int(settle_s * 1e9), int(SETTLE_FRAC * (end - t)) if end < 2 ** 63 else 0)
    if start < end:
      out.append((start, end, lab))
  return out


def _find_period(seq: list[tuple[int, bytes]]) -> int:
  """Smallest k such that >= 90 % of payload changes equal the payload k changes earlier (needs ~1.5 cycles)."""
  n = len(seq)
  for k in range(1, PERIOD_MAX + 1):
    if n - k < max(4, k // 2):
      break
    allow = int(0.1 * (n - k))
    miss = 0
    for j in range(k, n):
      if seq[j][1] != seq[j - k][1]:
        miss += 1
        if miss > allow:
          break
    else:
      return k
  return 0


class _Id:
  __slots__ = ("n", "first_t", "last_t", "last", "changes", "revisits", "b0_changes", "payloads", "hist", "seq",
               "period", "ch", "pos", "neg", "vals", "per", "lab", "mux", "cyclic", "bad")

  def __init__(self, t: int) -> None:
    self.n = self.changes = self.revisits = self.b0_changes = 0
    self.first_t = self.last_t = t
    self.last: bytes | None = None
    self.payloads: dict[bytes, int] | None = {}  # payload -> first t
    self.hist: dict[int, int] | None = {}  # (byte0 << 16 | i << 8 | value) -> first t
    self.seq: list[tuple[int, bytes]] | None = []  # (t, payload) at every payload change
    self.period = 0  # >0: the payload change sequence repeats every `period` changes
    self.ch: list[int] = []
    self.pos: list[int] = []
    self.neg: list[int] = []
    self.vals: list[int] = []  # per byte: bitmask of values seen
    self.per: dict[tuple[int, int, int], int] = {}  # (period, mux key or -1, byte) -> value bitmask
    self.lab = -1
    self.mux = self.cyclic = False
    self.bad: dict[int, str] = {}


class Profile:
  """One streaming pass over the whole log: per (bus, addr) payload history, mux/cyclic detection,
  counter/noise bytes and per-state-period value sets. Bounded memory (no frames kept)."""

  def __init__(self, markers: list[dict] | None = None, on_text: str = "Climate ON", off_text: str = "Climate OFF",
               settle_s: float = 2.0, end_t: int | None = None) -> None:
    self.ids: dict[tuple[int, int], _Id] = {}
    self.periods = state_periods(markers or [], on_text, off_text, settle_s, end_t)
    self._starts = [p[0] for p in self.periods]
    self.final = False

  @classmethod
  def from_frames(cls, frames: list[Frame], markers: list[dict] | None = None, **kw) -> "Profile":
    kw.setdefault("end_t", max((f[0] for f in frames), default=None))
    p = cls(markers, **kw)
    for f in sorted(frames, key=lambda f: f[0]):
      p.add(*f)
    return p.finalize()

  def _period(self, t: int) -> int:
    j = bisect.bisect_right(self._starts, t) - 1
    return j if j >= 0 and t < self.periods[j][1] else -1

  def add(self, t: int, bus: int, addr: int, data: bytes) -> None:
    s = self.ids.get((bus, addr))
    if s is None:
      s = self.ids[(bus, addr)] = _Id(t)
    s.n += 1
    s.last_t = t
    p = self._period(t) if self.periods else -1
    last = s.last
    if data == last and p == s.lab:
      return
    same_shape = last is not None and len(last) == len(data)
    if data != last:
      if len(s.vals) < len(data):
        k = len(data) - len(s.vals)
        s.ch += [0] * k
        s.pos += [0] * k
        s.neg += [0] * k
        s.vals += [0] * k
      if last is not None:
        s.changes += 1
        changed = [i for i, (a, b) in enumerate(zip(data, last)) if a != b]
        for i in changed:
          s.ch[i] += 1
          if (data[i] - last[i]) & 0xFF < 0x80:
            s.pos[i] += 1
          else:
            s.neg[i] += 1
        if data[:1] != last[:1]:
          s.b0_changes += 1
      # only bytes that changed can add new values (all bytes on a new length; keyed tables also on a new byte0)
      idx = changed if same_shape else range(len(data))
      kidx = idx if same_shape and data[0] == last[0] else range(len(data))
      pl = s.payloads
      if pl is not None:
        if data in pl:
          s.revisits += 1
        elif len(pl) < PAYLOAD_CAP:
          pl[data] = t
        else:
          s.payloads = None
      vals = s.vals
      for i in idx:
        vals[i] |= 1 << data[i]
      h = s.hist
      if h is not None and data:
        k0 = data[0] << 16
        for i in kidx:
          c = k0 | i << 8 | data[i]
          if c not in h:
            h[c] = t
        if len(h) > HIST_CAP or _pop(vals[0]) > MUX_MAX:
          s.hist = None
      if s.seq is not None:
        if len(s.seq) < SEQ_CAP:
          s.seq.append((t, data))
        else:
          s.seq = None
      s.last = data
    else:
      idx = kidx = range(len(data))
    if p >= 0 and data:
      if p != s.lab:
        idx = kidx = range(len(data))
      per = s.per
      for i in idx:
        per[(p, -1, i)] = per.get((p, -1, i), 0) | 1 << data[i]
      if s.hist is not None:
        k0 = data[0]
        for i in kidx:
          per[(p, k0, i)] = per.get((p, k0, i), 0) | 1 << data[i]
    s.lab = p

  def finalize(self) -> "Profile":
    for s in self.ids.values():
      nb0 = _pop(s.vals[0]) if s.vals else 0
      dur = max(s.last_t - s.first_t, 1) / 1e9
      busy = s.changes >= CYCLE_MIN_CHANGES and s.changes / dur >= CYCLE_MIN_RATE_HZ
      s.mux = busy and s.hist is not None and 2 <= nb0 <= MUX_MAX and s.b0_changes >= 0.5 * (s.n - 1)
      s.cyclic = s.mux or (busy and s.payloads is not None and s.revisits >= max(3, 0.3 * s.changes))
      s.period = _find_period(s.seq) if (s.cyclic and s.seq) else 0
      s.bad = {0: "mux"} if s.mux else {}
      if s.mux:
        continue  # other bytes are judged per mux value via the first-seen history
      for i, c in enumerate(s.ch):
        if c >= COUNTER_MIN_CHANGES and max(s.pos[i], s.neg[i]) >= 0.9 * c:
          s.bad[i] = "counter"
        elif c >= COUNTER_MIN_CHANGES and c >= 0.3 * (s.n - 1) and _pop(s.vals[i]) >= NOISE_MIN_DISTINCT:
          s.bad[i] = "noise"
    self.final = True
    return self

  def get(self, bus: int, addr: int) -> _Id | None:
    return self.ids.get((bus, addr))

  @staticmethod
  def seen_before(s: _Id, t: int, data: bytes, i: int) -> bool | None:
    """Was data[i] (for this mux value) seen at or before t anywhere in the log? None = unknown."""
    if s.hist is None or not data:
      return None
    ft = s.hist.get(data[0] << 16 | i << 8 | data[i])
    return ft is not None and ft <= t

  @staticmethod
  def cycle_unbroken(s: _Id, t0: int, t1: int) -> bool:
    """True unless a payload change in (t0, t1] differs from the same cycle position one period earlier and later
    (positions with no counterpart in the log, e.g. a short log's single partial cycle, count as unbroken)."""
    if not s.period or not s.seq:
      return False
    q, k = s.seq, s.period
    lo = bisect.bisect_right(q, t0, key=lambda e: e[0])
    for j in range(lo, len(q)):
      if q[j][0] > t1:
        break
      refs = [q[x][1] for x in (j - k, j + k) if 0 <= x < len(q)]
      if refs and q[j][1] not in refs:
        return False
    return True

  @staticmethod
  def payload_seen_before(s: _Id, t: int, data: bytes) -> bool | None:
    if s.payloads is None:
      return None
    ft = s.payloads.get(data)
    return ft is not None and ft <= t

  def summary(self) -> dict:
    return {"ids": len(self.ids), "mux": sum(s.mux for s in self.ids.values()),
            "cyclic": sum(s.cyclic for s in self.ids.values()),
            "counter_bytes": sum(v == "counter" for s in self.ids.values() for v in s.bad.values()),
            "noise_bytes": sum(v == "noise" for s in self.ids.values() for v in s.bad.values()),
            "periods": [{"start": a, "end": b if b < 2 ** 63 else None, "state": lab} for a, b, lab in self.periods]}


def analyze_file(path: str, pre_s: float = 3.0, post_s: float = 3.0, noise_pre_s: float = 10.0,
                 on_text: str = "Climate ON", off_text: str = "Climate OFF", up_text: str = "Temp up",
                 down_text: str = "Temp down", settle_s: float = 2.0) -> dict:
  """One pass: whole-log profile + frames near markers only. Returns header, markers, diff, states, steps, frames."""
  _, markers = read_markers(path)
  prof = Profile(markers, on_text, off_text, settle_s, log_end(path))
  span = int(max(pre_s, noise_pre_s) * 1e9)
  windows = [(m["t"] - span, m["t"] + int(post_s * 1e9)) for m in markers]
  header, frames, markers = read_log(path, windows=windows if windows else [(0, 0)], profile=prof)
  prof.finalize()
  return {"header": header, "markers": markers, "frames": frames, "profile": prof,
          "diff": diff_around_markers(frames, markers, pre_s, post_s, noise_pre_s, profile=prof),
          "states": state_candidates(frames, markers, on_text, off_text, settle_s=settle_s, profile=prof),
          "steps": step_candidates(frames, markers, up_text, down_text, pre_s, post_s, profile=prof)}


def diff_file(path: str, pre_s: float = 3.0, post_s: float = 3.0, noise_pre_s: float = 10.0) -> tuple[dict, list[dict], list[dict], list[Frame]]:
  """Memory-friendly diff: only frames near markers are loaded. Returns (header, markers, diff result, windowed frames)."""
  r = analyze_file(path, pre_s, post_s, noise_pre_s)
  return r["header"], r["markers"], r["diff"], r["frames"]


def _base(frames: list[Frame], header: dict | None) -> int:
  if header and isinstance(header.get("mono_ns"), int):
    return header["mono_ns"]
  return frames[0][0] if frames else 0


def list_frames(frames: list[Frame], addrs: set[int], header: dict | None = None) -> list[dict]:
  base = _base(frames, header)
  return [{"t": t, "rel_s": (t - base) / 1e9, "bus": bus, "addr": a, "data": d.hex().upper(), "decoded": decode(a, d)}
          for t, bus, a, d in frames if a in addrs]


def diff_around_markers(frames: list[Frame], markers: list[dict], pre_s: float = 3.0, post_s: float = 3.0,
                        noise_pre_s: float = 10.0, profile: Profile | None = None) -> list[dict]:
  """Bytes that change across each marker. With a whole-log `profile`, mux/cyclic ids only count values never
  seen before the marker (for the same byte0/mux value), and counter/noise bytes are marked noisy."""
  frames = sorted(frames, key=lambda f: f[0])
  times = [f[0] for f in frames]
  if profile is not None and not profile.final:
    profile.finalize()
  out = []
  for m in markers:
    t = m["t"]
    pre, post, npre = int(pre_s * 1e9), int(post_s * 1e9), int(noise_pre_s * 1e9)
    lo = bisect.bisect_left(times, t - max(pre, npre))
    hi = bisect.bisect_right(times, t + post)
    groups: dict[tuple[int, int], dict[str, list[bytes]]] = defaultdict(lambda: {"b": [], "a": [], "n": []})
    for ft, bus, addr, data in frames[lo:hi]:
      g = groups[(bus, addr)]
      if ft <= t:
        if ft >= t - pre:
          g["b"].append(data)
        if ft >= t - npre:
          g["n"].append(data)
      else:
        g["a"].append(data)
    changes = []
    for (bus, addr), g in groups.items():
      before, after = g["b"], g["a"]
      if not before and not after:
        continue
      s = profile.get(bus, addr) if profile is not None else None
      new_id = not before and bool(after) and (s is None or s.first_t > t)
      gone_id = bool(before) and not after and (s is None or s.last_t <= t)
      kind = ""
      stale = None  # cyclic/sparse: True when every payload after the marker already occurred before it
      if s is not None:
        sparse = not before and not new_id
        kind = "mux" if s.mux else ("cyclic" if s.cyclic else ("sparse" if sparse else ""))
        if kind and after:
          seen = [Profile.payload_seen_before(s, t, d) for d in after]
          stale = None if None in seen else all(seen)
          if Profile.cycle_unbroken(s, t, t + post):
            stale = True
      n = max(len(x) for x in before + after)
      bl = []
      for i in range(n):
        bv = {_hx(d[i]) for d in before if len(d) > i}
        av = {_hx(d[i]) for d in after if len(d) > i}
        lb = _hx(before[-1][i]) if before and len(before[-1]) > i else None
        fa = next((_hx(d[i]) for d in after if len(d) > i and _hx(d[i]) not in bv), None)  # first value not seen before
        if fa is None and after and len(after[0]) > i:
          fa = _hx(after[0][i])
        if not ((av - bv) or lb != fa):
          continue
        why = ""
        if not after and not gone_id:
          why = "paused"  # id is silent in the post window but comes back later in the log
        elif s is not None and i in s.bad:
          why = s.bad[i]
        elif kind:
          fresh = [Profile.seen_before(s, t, d, i) for d in after if len(d) > i]
          if stale or (fresh and None not in fresh and all(fresh)):
            why = "cycle"  # value already occurred earlier for this mux value, or the payload cycle is unbroken
        if not why and len({d[i] for d in g["n"] if len(d) > i}) >= 4:
          why = "busy"
        bl.append({"i": i, "last_before": lb, "first_after": fa, "before_vals": sorted(bv), "after_vals": sorted(av),
                   "noisy": bool(why), "why": why})
      if not bl and not (new_id or gone_id):
        continue
      bl.sort(key=lambda x: (x["noisy"], x["i"]))
      real = 0 if (new_id or gone_id) else sum(1 for x in bl if not x["noisy"])
      score = real * 10 + (20 if (new_id or gone_id) else 0) + (50 if addr in WATCH else 0)
      changes.append({"bus": bus, "addr": addr, "addr_hex": fmt_addr(addr), "name": WATCH.get(addr, ""),
                      "new_id": new_id, "gone_id": gone_id, "kind": kind, "bytes": bl, "score": score})
    changes.sort(key=lambda c: (-c["score"], c["bus"], c["addr"]))
    summary = []
    for c in changes[:15]:
      tag = " NEW" if c["new_id"] else (" GONE" if c["gone_id"] else "")
      bs = ", ".join(f"b{x['i']}:{x['last_before']}->{x['first_after']}{'~' if x['noisy'] else ''}" for x in c["bytes"][:8])
      summary.append(f"bus{c['bus']} {c['addr_hex']} score={c['score']}{tag} {bs}")
    out.append({"marker": dict(m), "changes": changes, "summary": summary})
  return out


def _cand(s: _Id | None, bus: int, addr: int, key: int, i: int) -> dict:
  return {"bus": bus, "addr": addr, "addr_hex": fmt_addr(addr), "name": WATCH.get(addr, ""),
          "mux": _hx(key) if key >= 0 else None, "i": i, "cyclic": bool(s and s.cyclic)}


def state_candidates(frames: list[Frame], markers: list[dict], on_text: str = "Climate ON", off_text: str = "Climate OFF",
                     settle_s: float = 2.0, profile: Profile | None = None, limit: int = 40) -> list[dict]:
  """Bytes whose value set during ON periods is disjoint from OFF periods (per mux value for mux ids).
  Periods run from each on/off marker + settle_s to the next on/off marker; counter/noise bytes are skipped.
  Without a profile one is built from `frames` (pass the whole log for best results)."""
  if profile is None or not profile.periods:
    profile = Profile.from_frames(frames, markers, on_text=on_text, off_text=off_text, settle_s=settle_s)
  elif not profile.final:
    profile.finalize()
  labs = [lab for _, _, lab in profile.periods]
  out = []
  for (bus, addr), s in profile.ids.items():
    acc: dict[tuple[int, int], list[int]] = {}
    for (p, key, i), mask in s.per.items():
      if (key >= 0) != s.mux or i in s.bad:
        continue
      a = acc.setdefault((key, i), [0, 0, 0, 0])
      j = 0 if labs[p] == "on" else 1
      a[j] |= mask
      a[2 + j] += 1
    hits = [(k, v) for k, v in acc.items() if v[0] and v[1] and not v[0] & v[1]]
    per_key: dict[int, int] = defaultdict(int)
    for (key, _), _v in hits:
      per_key[key] += 1
    for (key, i), (on, off, n_on, n_off) in hits:
      c = _cand(s, bus, addr, key, i)
      spread = _pop(on) + _pop(off) - 2
      # a state is usually one or two bytes of an otherwise steady message; whole-payload changes look random
      c.update({"on_vals": _vals(on), "off_vals": _vals(off), "on_periods": n_on, "off_periods": n_off,
                "score": 10 * (n_on + n_off) - 3 * spread - 2 * (per_key[key] - 1) + (50 if addr in WATCH else 0)})
      out.append(c)
  out = [c for c in out if c["score"] > 0]
  out.sort(key=lambda c: (-c["score"], c["bus"], c["addr"], c["i"]))
  return out[:limit]


def _s8(d: int) -> int:
  return ((d + 0x80) & 0xFF) - 0x80


def step_candidates(frames: list[Frame], markers: list[dict], up_text: str = "Temp up", down_text: str = "Temp down",
                    pre_s: float = 3.0, post_s: float = 3.0, profile: Profile | None = None, limit: int = 40) -> list[dict]:
  """Bytes that move one way on every up marker and the other way on every down marker (signed mod-256 delta
  of the last value before the marker vs the last value before the next marker or post_s). Counter/noise bytes are skipped."""
  steps = sorted((m["t"], 1 if _match(m.get("text", ""), up_text) else -1) for m in markers
                 if _match(m.get("text", ""), up_text) or _match(m.get("text", ""), down_text))
  if not steps:
    return []
  if profile is None:
    profile = Profile.from_frames(frames, markers)
  elif not profile.final:
    profile.finalize()
  frames = sorted(frames, key=lambda f: f[0])
  times = [f[0] for f in frames]
  mts = sorted(m["t"] for m in markers)
  acc: dict[tuple[int, int, int, int], list[tuple[int, int]]] = defaultdict(list)
  for t, sign in steps:
    j = bisect.bisect_right(mts, t)
    end = min(t + int(post_s * 1e9), mts[j] if j < len(mts) else 2 ** 63)
    bef: dict[tuple[int, int, int, int], int] = {}
    aft: dict[tuple[int, int, int, int], int] = {}
    for ft, bus, addr, data in frames[bisect.bisect_left(times, t - int(pre_s * 1e9)):bisect.bisect_left(times, end)]:
      s = profile.get(bus, addr)
      key = data[0] if (s is not None and s.mux and data) else -1
      dst = bef if ft <= t else aft
      for i, v in enumerate(data):
        if s is not None and i in s.bad:
          continue
        dst[(bus, addr, key, i)] = v
    for k, b in bef.items():
      if k in aft:
        acc[k].append((sign, _s8(aft[k] - b)))
  out = []
  for (bus, addr, key, i), ds in acc.items():
    orient = {(1 if d > 0 else -1) * sign for sign, d in ds if d}
    if len(orient) != 1 or any(d == 0 for _, d in ds) or len(ds) < min(2, len(steps)):
      continue
    s = profile.get(bus, addr)
    both = len({sign for sign, _ in ds}) == 2
    c = _cand(s, bus, addr, key, i)
    c.update({"deltas": [d for _, d in ds], "dirs": [sign for sign, _ in ds], "inverted": orient == {-1}, "both_dirs": both,
              "matched": len(ds), "steps": len(steps),
              "score": 10 * len(ds) + (20 if both else 0) - 5 * (len(steps) - len(ds)) + (50 if addr in WATCH else 0)})
    out.append(c)
  out.sort(key=lambda c: (-c["score"], c["bus"], c["addr"], c["i"]))
  return out[:limit]


def format_states_text(states: list[dict], steps: list[dict]) -> str:
  L = ["== State candidates (ON vs OFF value sets disjoint)"]
  if not states:
    L.append("   (none: need Climate ON / Climate OFF markers with settled periods)")
  for c in states:
    mux = f" mux={c['mux']}" if c["mux"] else ""
    L.append(f"   bus{c['bus']} {c['addr_hex']}{mux} b{c['i']} score={c['score']} ON={','.join(c['on_vals'])} "
             f"OFF={','.join(c['off_vals'])} periods={c['on_periods']}/{c['off_periods']}{' cyclic' if c['cyclic'] else ''} {c['name']}")
  L.append("== Step candidates (move with Temp up / Temp down)")
  if not steps:
    L.append("   (none)")
  for c in steps:
    mux = f" mux={c['mux']}" if c["mux"] else ""
    ds = " ".join(f"{'up' if s > 0 else 'dn'}:{d:+d}" for s, d in zip(c["dirs"], c["deltas"], strict=True))
    L.append(f"   bus{c['bus']} {c['addr_hex']}{mux} b{c['i']} score={c['score']} {c['matched']}/{c['steps']} [{ds}]"
             f"{' inverted' if c['inverted'] else ''} {c['name']}")
  return "\n".join(L)


def format_diff_text(result: list[dict]) -> str:
  lines = []
  for r in result:
    m = r["marker"]
    lines.append(f"== Marker t={m['t']} {m.get('text', '')}")
    if not r["changes"]:
      lines.append("   (no changes)")
      continue
    lines.append(f"   {'bus':>3} {'addr':<10} {'score':>5} {'flags':<5} {'name':<28} bytes (before->after, ~=noisy)")
    for c in r["changes"]:
      flags = "NEW" if c["new_id"] else ("GONE" if c["gone_id"] else c.get("kind", "")[:5])
      bs = " ".join(f"[{x['i']}]{x['last_before'] or '--'}->{x['first_after'] or '--'}{'~' if x['noisy'] else ''}" for x in c["bytes"])
      lines.append(f"   {c['bus']:>3} {c['addr_hex']:<10} {c['score']:>5} {flags:<5} {c['name'][:28]:<28} {bs}")
  return "\n".join(lines)


def format_frames_text(rows: list[dict]) -> str:
  lines = [f"{'rel_s':>10} {'bus':>3} {'addr':<10} {'data':<16} decoded"]
  for r in rows:
    dec = {k: v for k, v in r["decoded"].items() if k != "raw"}
    lines.append(f"{r['rel_s']:>10.3f} {r['bus']:>3} {fmt_addr(r['addr']):<10} {r['data']:<16} {dec if dec else ''}")
  return "\n".join(lines)


def resolve(arg: str) -> str:
  if arg == "latest":
    root = config.log_root()
    files = [os.path.join(root, f) for f in os.listdir(root) if f.endswith(config.EXT)] if os.path.isdir(root) else []
    if not files:
      raise FileNotFoundError(f"no {config.EXT} files in {root}")
    return max(files, key=os.path.getmtime)
  return arg


def summarize(header: dict, frames: list[Frame], markers: list[dict]) -> str:
  base = _base(frames, header)
  L = [f"header: {header}", f"frames: {len(frames)}"]
  by_bus: dict[int, int] = defaultdict(int)
  ids: dict[int, set[int]] = defaultdict(set)
  for _, bus, a, _ in frames:
    by_bus[bus] += 1
    ids[bus].add(a)
  for bus in sorted(by_bus):
    L.append(f"bus {bus}: {by_bus[bus]} frames, {len(ids[bus])} unique ids")
  L.append(f"markers: {len(markers)}")
  for m in markers:
    L.append(f"  +{(m['t'] - base) / 1e9:9.3f}s  {m['text']}")
  L.append("watched ids:")
  seen = False
  for addr, name in WATCH.items():
    for bus in sorted(by_bus):
      fr = [f for f in frames if f[2] == addr and f[1] == bus]
      if not fr:
        continue
      seen = True
      L.append(f"  {fmt_addr(addr)} bus{bus} ({name}) n={len(fr)}")
      L.append(f"    first: {decode(addr, fr[0][3])}")
      L.append(f"    last:  {decode(addr, fr[-1][3])}")
  if not seen:
    L.append("  (none seen)")
  return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
  ap = argparse.ArgumentParser(prog="canlog.analyze")
  ap.add_argument("file")
  ap.add_argument("--list", default=None)
  ap.add_argument("--diff", action="store_true")
  ap.add_argument("--pre", type=float, default=3.0)
  ap.add_argument("--post", type=float, default=3.0)
  ap.add_argument("--states", action="store_true", help="ON/OFF state candidates and Temp up/down step candidates")
  ap.add_argument("--on-text", default="Climate ON")
  ap.add_argument("--off-text", default="Climate OFF")
  ap.add_argument("--up-text", default="Temp up")
  ap.add_argument("--down-text", default="Temp down")
  ap.add_argument("--settle", type=float, default=2.0, help="seconds after an ON/OFF marker ignored for --states")
  ap.add_argument("--json", action="store_true")
  args = ap.parse_args(argv)
  try:
    path = resolve(args.file)
    _, markers = read_markers(path)
    prof = Profile(markers, args.on_text, args.off_text, args.settle, log_end(path))
    header, frames, markers = read_log(path, profile=prof)
  except (OSError, FileNotFoundError) as e:
    print(f"error: {e}", file=sys.stderr)
    return 1
  prof.finalize()
  if not (args.list or args.diff or args.states):
    if args.json:
      print(json.dumps({"header": header, "frames": len(frames), "markers": markers}))
    else:
      print(summarize(header, frames, markers))
    return 0
  payload: dict = {}
  if args.list:
    addrs = {parse_addr(x) for x in args.list.split(",") if x.strip()}
    payload["frames"] = list_frames(frames, addrs, header)
  if args.diff:
    payload["diff"] = diff_around_markers(frames, markers, args.pre, args.post, profile=prof)
  if args.states:
    payload["states"] = state_candidates(frames, markers, args.on_text, args.off_text, args.settle, profile=prof)
    payload["steps"] = step_candidates(frames, markers, args.up_text, args.down_text, args.pre, args.post, profile=prof)
    payload["profile"] = prof.summary()
  if args.json:
    print(json.dumps(payload))
  else:
    if "frames" in payload:
      print(format_frames_text(payload["frames"]))
    if "diff" in payload:
      print(format_diff_text(payload["diff"]))
    if "states" in payload:
      print(format_states_text(payload["states"], payload["steps"]))
  return 0


if __name__ == "__main__":
  sys.exit(main())
