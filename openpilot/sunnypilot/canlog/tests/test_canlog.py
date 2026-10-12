import json
import os

import pytest

from openpilot.sunnypilot.canlog import analyze, decode as dec
from openpilot.sunnypilot.canlog.recorder import Recorder

S = 1_000_000_000


def test_setpoint_and_heating():
  cases = {0: "LO", 1: "16.0C", 12: "21.5C", 28: "29.5C", 29: "HI"}
  for raw, text in cases.items():
    d = bytes([0, (raw & 3) << 6, raw >> 2, 0])
    out = dec.decode(0x16A954FB, d)
    assert out["setpoint_raw"] == raw and out["setpoint"] == text
  assert dec.decode(0x16A954FB, bytes([0, 0, 0x7F]))["setpoint"] == "?(60)"
  assert dec.decode(0x16A95493, b"\x01")["heating_active"] is True
  assert dec.decode(0x16A95493, b"\x00")["heating_active"] is False
  assert dec.decode(0x16A954FB, b"") == {"raw": ""}
  assert dec.decode(0x123, b"\x00") == {}


def test_addr_helpers():
  assert dec.fmt_addr(0x16A954FB) == "0x16A954FB"
  assert dec.parse_addr("0x16A954FB") == dec.parse_addr("16A954FB") == 0x16A954FB
  assert dec.parse_addr("1000") == 1000


SAMPLE = bytes([0x11, 0, 0x4A, 0x05, 0, 0, 0, 0x80])


def test_nmh_fallback():
  out = dec.decode_signals(SAMPLE, dec.nmh_signals_fallback())
  assert out["NM_Gateway_SNI"] == 0x11
  assert out["NM_Gateway_NM_State"] == 0x0A
  assert out["NM_Gateway_Car_Wakeup"] == 1
  assert out["NM_Gateway_Wakeup"] == 5
  assert out["NM_Gateway_UDS_CC"] == 1
  assert out["NM_Gateway_NM_aktiv_KL15"] == 0


def test_nmh_dbc_matches_fallback():
  sigs = dec.nmh_signals_dbc()
  if sigs is None:
    pytest.skip("opendbc not importable")
  assert dec.decode_signals(SAMPLE, sigs) == dec.decode_signals(SAMPLE, dec.nmh_signals_fallback())


def test_recorder_roundtrip(tmp_path):
  rec = Recorder(str(tmp_path))
  flag = tmp_path / ".keep_can_awake"
  assert not flag.exists()
  with pytest.raises(RuntimeError):
    rec.add_marker("x")
  rec._handle_event(1 * S, [(0x16A954FB, bytes([0, 0, 3, 0]), 0)])
  name = rec.start_session()
  assert rec.start_session() == name and flag.exists() and rec.recording
  rec._handle_event(2 * S, [(0x16A954FB, bytes([0, 0, 3, 0]), 0), (0x16A95493, b"\x01", 2), (0x300, b"\xAB", 1), (0x300, b"\xFF", 130)])
  m = rec.add_marker("pressed\nbutton")
  assert m["text"] == "pressed button" and m["t"] == 2 * S and m["rel_s"] == 1.0
  rec._handle_event(3 * S, [(0x1B000010, SAMPLE, 0)])
  st = rec.status()
  assert st["frames"] == 4 and st["bus_counts"] == {"0": 2, "1": 1, "2": 1} and st["can_alive"]
  lat = rec.latest()
  assert lat["0x16A954FB"]["0"]["decoded"]["setpoint"] == "21.5C"
  assert lat["0x16A95493"]["2"]["decoded"]["heating_active"] is True
  assert lat["0x1B000010"]["0"]["decoded"]["NM_Gateway_Wakeup"] == 5
  assert rec.stop_session() == name and not flag.exists() and rec.stop_session() is None

  header, frames, markers = analyze.read_log(rec.session_path(name))
  assert header["mono_ns"] == 1 * S
  assert frames == [(2 * S, 0, 0x16A954FB, bytes([0, 0, 3, 0])), (2 * S, 2, 0x16A95493, b"\x01"),
                    (2 * S, 1, 0x300, b"\xAB"), (3 * S, 0, 0x1B000010, SAMPLE)]
  assert markers == [{"t": 2 * S, "text": "pressed button"}]
  ss = rec.list_sessions()
  assert len(ss) == 1 and ss[0]["name"] == name and ss[0]["markers"] == 1
  assert rec.session_path("../x") is None and rec.session_path("nope") is None


def test_autostop(tmp_path, monkeypatch):
  rec = Recorder(str(tmp_path))
  name = rec.start_session()
  monkeypatch.setattr("openpilot.sunnypilot.canlog.config.MAX_FILE_BYTES", 10)
  rec._last_flush = 0.0  # force the 1 Hz check to run now
  rec._tick()
  assert not rec.recording and not (tmp_path / ".keep_can_awake").exists()
  _, _, markers = analyze.read_log(rec.session_path(name))
  assert markers[0]["text"].startswith("AUTO-STOP")


def _write_log(path):
  lines = [f"# canlog v1 started=2026-01-01T00:00:00 mono_ns={0} device=t"]
  mt = 20 * S
  for i in range(0, 241):
    t = 10 * S + i * S // 10
    a_b2 = 0x30 if t < 21 * S else 0x31
    lines.append(f"F {t} 0 16A954FB 0000{a_b2:02X}00")
    lines.append(f"F {t} 0 00000100 {i & 0xF:02X}11223344")
    if t >= 21 * S:
      lines.append(f"F {t} 0 00000200 0102030405060708")
  lines.insert(1, "M 0 early")
  lines.append(f"M {mt} test press")
  lines.sort(key=lambda s: int(s.split(" ")[1]) if s[0] in "FM" else -1)
  path.write_text("\n".join(lines) + "\nF 99 0 1")  # truncated last line
  return path


def test_diff(tmp_path):
  p = _write_log(tmp_path / "x.canlog")
  header, frames, markers = analyze.read_log(str(p))
  assert len(markers) == 2 and frames[-1][0] != 99
  res = analyze.diff_around_markers(frames, [m for m in markers if m["text"] == "test press"])
  ch = res[0]["changes"]
  assert [c["addr"] for c in ch] == [0x16A954FB, 0x200, 0x100]
  a = ch[0]
  assert a["score"] == 60 and a["name"] and [b["i"] for b in a["bytes"]] == [2]
  assert a["bytes"][0]["last_before"] == "30" and a["bytes"][0]["after_vals"] == ["30", "31"] and not a["bytes"][0]["noisy"]
  assert ch[1]["new_id"] and not ch[1]["gone_id"]
  assert ch[2]["bytes"][0]["noisy"] and ch[2]["score"] == 0
  assert res[0]["summary"] and "16A954FB" in analyze.format_diff_text(res)
  rows = analyze.list_frames(frames, {0x16A954FB}, header)
  assert rows[0]["rel_s"] == 10.0 and rows[0]["decoded"]["setpoint"] == "LO"
  assert "LO" in analyze.format_frames_text(rows)


def test_cli(tmp_path, capsys, monkeypatch):
  p = str(_write_log(tmp_path / "x.canlog"))
  assert analyze.main([p]) == 0
  assert "bus 0" in capsys.readouterr().out
  assert analyze.main([p, "--list", "0x16A954FB,100", "--json"]) == 0
  assert len(json.loads(capsys.readouterr().out)["frames"]) > 0
  assert analyze.main([p, "--diff", "--json", "--pre", "2", "--post", "2"]) == 0
  assert len(json.loads(capsys.readouterr().out)["diff"]) == 2
  assert analyze.main([p, "--diff"]) == 0
  monkeypatch.setenv("CANLOG_ROOT", str(tmp_path))
  assert analyze.resolve("latest") == os.path.join(str(tmp_path), "x.canlog")


def test_diff_file_windowed(tmp_path):
  p = _write_log(tmp_path / "w.canlog")
  _, markers, res, frames = analyze.diff_file(str(p), pre_s=3.0, post_s=3.0)
  assert len(markers) == 2 and len(res) == 2
  # only frames near markers are loaded: the log spans 10..34 s, windows cover at most 0..23 s
  assert frames and max(f[0] for f in frames) <= 23 * S + S
  hit = [c for c in res[1]["changes"] if c["addr"] == 0x16A954FB]
  assert hit and hit[0]["bytes"][0]["last_before"] == "30" and hit[0]["bytes"][0]["first_after"] == "31"


VIN = [bytes([0, 0, 0, 0, 0, 0x57, 0x56, 0x47]), bytes([1, 0x52, 0x4D, 0x50, 0x45, 0x32, 0x38, 0x4D]),
       bytes([2, 0x50, 0x30, 0x33, 0x35, 0x32, 0x38, 0x30])]  # fake VIN, mux in byte 0
BAP = [bytes([0x3D, 0x82 + k, 0x03, k, 0, 0, 0, 0]) for k in range(11)] + [bytes([0x80, 0x09, 0x3D, 0x90, 0, 0, 0, 0]), bytes([0xC0, 0, 0, 0, 0, 0])]
CLIMATE = [("Climate ON", 10), ("Climate OFF", 30), ("Climate ON", 40), ("Climate OFF", 50)]
STEPS = [("Temp up", 56), ("Temp up", 57.5), ("Temp down", 59), ("Temp down", 60.5)]
LAG = 4.0  # remote command latency: the car reacts seconds after the marker


def _real_log(path, end_s=64):
  """Synthetic MEB-like log: VIN mux, 13-payload BAP cycle at 1 Hz, slow counter, a lagging climate state byte
  (0x300 b2) and a setpoint (0x16A954FB) that steps with Temp up/down."""
  lines = ["# canlog v1 started=2026-01-01T00:00:00 mono_ns=0 device=t"]
  lines += [f"M {int(t * S)} {txt}" for txt, t in CLIMATE + STEPS]
  sp, sp_t = 12, sorted((t + 0.5, 1 if "up" in txt else -1) for txt, t in STEPS)
  for k in range(end_s * 10):
    t = k / 10
    ts = int(t * S)
    lines.append(f"F {ts} 0 000006B4 {VIN[k % 3].hex()}")
    if k % 10 == 0:
      lines.append(f"F {ts} 0 17333610 {BAP[(k // 10) % len(BAP)].hex()}")
    if k % 20 == 0:
      lines.append(f"F {ts} 0 16A954C4 00{(k // 20 * 0x19) & 0xFF:02X}0000")
    on = any(a + LAG <= t < b + LAG for (_, a), (_, b) in zip(CLIMATE[::2], CLIMATE[1::2], strict=True))
    lines.append(f"F {ts} 0 00000300 1122{5 if on else 0:02X}33")
    while sp_t and sp_t[0][0] <= t:
      sp += sp_t.pop(0)[1]
    lines.append(f"F {ts} 0 16A954FB 00{(sp & 3) << 6:02X}{sp >> 2:02X}00")
  lines.sort(key=lambda s: int(s.split(" ")[1]) if s[0] in "FM" else -1)
  path.write_text("\n".join(lines) + "\n")
  return path


def test_profile_detects_mux_cycle_counter(tmp_path):
  p = _real_log(tmp_path / "r.canlog")
  _, frames, markers = analyze.read_log(str(p))
  prof = analyze.Profile.from_frames(frames, markers)
  vin, bap, ctr, st = (prof.get(0, a) for a in (0x6B4, 0x17333610, 0x16A954C4, 0x300))
  assert vin.mux and vin.cyclic and vin.bad == {0: "mux"}
  assert bap.cyclic and not bap.mux and bap.period == len(BAP)
  assert ctr.bad == {1: "counter"} and not ctr.cyclic
  assert not st.cyclic and not st.bad
  # BAP cycle unbroken everywhere, even before one full cycle has been seen
  assert analyze.Profile.cycle_unbroken(bap, 0, 64 * S)


def test_diff_filters_mux_cycle_counter(tmp_path):
  p = _real_log(tmp_path / "r.canlog")
  _, frames, markers = analyze.read_log(str(p))
  prof = analyze.Profile.from_frames(frames, markers)
  on = [m for m in markers if m["text"] == "Climate ON"]
  res = analyze.diff_around_markers(frames, on, 3, 6, profile=prof)
  for r in res:
    top = r["changes"][0]
    assert top["addr"] == 0x300 and [b["i"] for b in top["bytes"] if not b["noisy"]] == [2]
    for c in r["changes"]:
      if c["addr"] in (0x6B4, 0x17333610, 0x16A954C4):
        assert c["score"] == 0 and all(b["noisy"] for b in c["bytes"]), c
    whys = {c["addr"]: {b["why"] for b in c["bytes"]} for c in r["changes"]}
    assert whys.get(0x16A954C4, {"counter"}) == {"counter"}
  # without the profile the old rule lets the VIN mux and BAP cycle through
  raw = analyze.diff_around_markers(frames, on[:1], 3, 6)
  assert any(c["addr"] == 0x6B4 and c["score"] > 0 for c in raw[0]["changes"])


def test_state_and_step_candidates(tmp_path):
  p = _real_log(tmp_path / "r.canlog")
  _, frames, markers = analyze.read_log(str(p))
  states = analyze.state_candidates(frames, markers)
  assert states and (states[0]["addr"], states[0]["i"]) == (0x300, 2)
  assert states[0]["on_vals"] == ["05"] and states[0]["off_vals"] == ["00"] and states[0]["on_periods"] == 2
  assert not any(c["addr"] in (0x6B4, 0x17333610, 0x16A954C4) for c in states)
  # a 2 s settle alone would mix in the lagging OFF values; the half-period rule keeps the sets clean
  assert analyze.state_periods(markers)[0][0] == 20 * S
  steps = analyze.step_candidates(frames, markers)
  assert steps[0]["addr"] == 0x16A954FB and steps[0]["matched"] == 4 and steps[0]["both_dirs"]
  assert not any(c["addr"] in (0x6B4, 0x17333610, 0x16A954C4, 0x300) for c in steps)
  assert "0x00000300" in analyze.format_states_text(states, steps)


def test_analyze_file_and_cli_states(tmp_path, capsys):
  p = _real_log(tmp_path / "r.canlog")
  r = analyze.analyze_file(str(p), post_s=6)
  assert r["diff"][0]["changes"][0]["addr"] == 0x300
  assert (r["states"][0]["addr"], r["steps"][0]["addr"]) == (0x300, 0x16A954FB)
  assert r["profile"].summary()["counter_bytes"] >= 1 and r["profile"].get(0, 0x16A954C4).bad == {1: "counter"}
  assert max(f[0] for f in r["frames"]) <= 61 * S + 6 * S  # still windowed
  assert analyze.main([str(p), "--states", "--json"]) == 0
  out = json.loads(capsys.readouterr().out)
  assert out["states"][0]["addr"] == 0x300 and out["steps"] and out["profile"]["mux"] == 1
  assert analyze.main([str(p), "--states", "--diff"]) == 0
  assert "State candidates" in capsys.readouterr().out
