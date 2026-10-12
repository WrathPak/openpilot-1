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
