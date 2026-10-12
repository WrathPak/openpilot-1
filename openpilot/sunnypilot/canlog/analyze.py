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


def read_log(path: str, windows: list[tuple[int, int]] | None = None) -> tuple[dict, list[Frame], list[dict]]:
  """Stream-parse a .canlog. `windows` = [(t0, t1), ...] in mono ns keeps only frames inside any window."""
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
          if windows is not None:
            i = bisect.bisect_right(windows, (t, float("inf"))) - 1
            if i < 0 or windows[i][1] < t:
              continue
          frames.append((t, int(p[2]), int(p[3], 16), bytes.fromhex(p[4])))
        elif s[0] == "M":
          p = s.split(" ", 2)
          markers.append({"t": int(p[1]), "text": p[2] if len(p) > 2 else ""})
        elif s.startswith("# canlog") and not header:
          header = _parse_header(s)
      except (ValueError, IndexError):
        continue
  return header, frames, markers


def diff_file(path: str, pre_s: float = 3.0, post_s: float = 3.0, noise_pre_s: float = 10.0) -> tuple[dict, list[dict], list[dict], list[Frame]]:
  """Memory-friendly diff: only frames near markers are loaded. Returns (header, markers, diff result, windowed frames)."""
  _, markers = read_markers(path)
  span = int(max(pre_s, noise_pre_s) * 1e9)
  windows = [(m["t"] - span, m["t"] + int(post_s * 1e9)) for m in markers]
  header, frames, markers = read_log(path, windows=windows if windows else [(0, 0)])
  return header, markers, diff_around_markers(frames, markers, pre_s, post_s, noise_pre_s), frames


def _base(frames: list[Frame], header: dict | None) -> int:
  if header and isinstance(header.get("mono_ns"), int):
    return header["mono_ns"]
  return frames[0][0] if frames else 0


def list_frames(frames: list[Frame], addrs: set[int], header: dict | None = None) -> list[dict]:
  base = _base(frames, header)
  return [{"t": t, "rel_s": (t - base) / 1e9, "bus": bus, "addr": a, "data": d.hex().upper(), "decoded": decode(a, d)}
          for t, bus, a, d in frames if a in addrs]


def _hx(b: int) -> str:
  return f"{b:02X}"


def diff_around_markers(frames: list[Frame], markers: list[dict], pre_s: float = 3.0, post_s: float = 3.0,
                        noise_pre_s: float = 10.0) -> list[dict]:
  frames = sorted(frames, key=lambda f: f[0])
  times = [f[0] for f in frames]
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
      new_id = not before and bool(after)
      gone_id = bool(before) and not after
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
        noisy = len({d[i] for d in g["n"] if len(d) > i}) >= 4
        bl.append({"i": i, "last_before": lb, "first_after": fa, "before_vals": sorted(bv), "after_vals": sorted(av), "noisy": noisy})
      if not bl and not (new_id or gone_id):
        continue
      bl.sort(key=lambda x: (x["noisy"], x["i"]))
      real = 0 if (new_id or gone_id) else sum(1 for x in bl if not x["noisy"])
      score = real * 10 + (20 if (new_id or gone_id) else 0) + (50 if addr in WATCH else 0)
      changes.append({"bus": bus, "addr": addr, "addr_hex": fmt_addr(addr), "name": WATCH.get(addr, ""),
                      "new_id": new_id, "gone_id": gone_id, "bytes": bl, "score": score})
    changes.sort(key=lambda c: (-c["score"], c["bus"], c["addr"]))
    summary = []
    for c in changes[:15]:
      tag = " NEW" if c["new_id"] else (" GONE" if c["gone_id"] else "")
      bs = ", ".join(f"b{x['i']}:{x['last_before']}->{x['first_after']}{'~' if x['noisy'] else ''}" for x in c["bytes"][:8])
      summary.append(f"bus{c['bus']} {c['addr_hex']} score={c['score']}{tag} {bs}")
    out.append({"marker": dict(m), "changes": changes, "summary": summary})
  return out


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
      flags = "NEW" if c["new_id"] else ("GONE" if c["gone_id"] else "")
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
  ap.add_argument("--json", action="store_true")
  args = ap.parse_args(argv)
  try:
    header, frames, markers = read_log(resolve(args.file))
  except (OSError, FileNotFoundError) as e:
    print(f"error: {e}", file=sys.stderr)
    return 1
  if not (args.list or args.diff):
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
    payload["diff"] = diff_around_markers(frames, markers, args.pre, args.post)
  if args.json:
    print(json.dumps(payload))
  else:
    if "frames" in payload:
      print(format_frames_text(payload["frames"]))
    if "diff" in payload:
      print(format_diff_text(payload["diff"]))
  return 0


if __name__ == "__main__":
  sys.exit(main())
