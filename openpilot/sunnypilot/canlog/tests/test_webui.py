import gzip
import http.cookiejar
import json
import os
import urllib.error
import urllib.request

import pytest

from openpilot.sunnypilot.canlog import webui
from openpilot.sunnypilot.canlog.tools.dev_webui import FakeRecorder


@pytest.fixture
def srv(tmp_path, monkeypatch):
  monkeypatch.setenv("CANLOG_BIND_ANY", "1")
  monkeypatch.setenv("CANLOG_ROOT", str(tmp_path))
  rec = FakeRecorder(str(tmp_path))
  s = webui.serve(rec, port=0)
  yield s, f"http://127.0.0.1:{s.ports[0]}", rec
  s.shutdown()


def client():
  return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def call(op, base, path, body=None, method=None):
  data = json.dumps(body).encode() if body is not None else None
  req = urllib.request.Request(base + path, data=data, method=method, headers={"Content-Type": "application/json"})
  try:
    with op.open(req) as r:
      return r.status, r.read(), r.headers
  except urllib.error.HTTPError as e:
    return e.code, e.read(), e.headers


def js(x):
  return json.loads(x[1])


def test_flow(srv):
  s, base, rec = srv
  op = client()
  st, body, _ = call(op, base, "/")
  assert st == 200 and b"Set a PIN" in body and b'rel="apple-touch-icon"' in body
  assert call(op, base, "/api/status")[0] == 401
  assert call(op, base, "/logs/x.canlog")[0] == 401
  assert call(op, base, "/api/setpin", {"pin": "12", "pin2": "12"})[0] == 400
  r = call(op, base, "/api/setpin", {"pin": "1234", "pin2": "1234"})
  assert r[0] == 200 and "HttpOnly" in r[2]["Set-Cookie"] and "SameSite=Lax" in r[2]["Set-Cookie"]
  assert os.path.isfile(os.path.join(os.environ["CANLOG_ROOT"], "pin.json"))
  assert call(op, base, "/api/status")[0] == 200
  assert call(op, base, "/api/marker", {"text": "x"})[0] == 409
  assert call(op, base, "/api/marker", {"text": ""})[0] == 400
  assert call(op, base, "/api/marker", {"text": "x" * 201})[0] == 400
  name = js(call(op, base, "/api/start", {}))["session"]
  assert "rel_s" in js(call(op, base, "/api/marker", {"text": "Climate ON"}))
  live = js(call(op, base, "/api/live"))
  assert {"0x16A954FB", "0x16A95493", "0x1B000010"} <= set(live)
  assert call(op, base, f"/api/sessions/{name}", method="DELETE")[0] == 409
  call(op, base, "/api/stop", {})
  st, body, h = call(op, base, f"/logs/{name}.canlog")
  with open(rec.session_path(name), "rb") as f:
    assert st == 200 and body == f.read()
  assert "attachment" in h["Content-Disposition"]
  assert gzip.decompress(call(op, base, f"/logs/{name}.canlog?gz=1")[1]) == body
  assert call(op, base, "/logs/..%2Fpin.json")[0] == 404
  assert call(op, base, "/logs/..%2Fpin.canlog")[0] == 404
  assert len(js(call(op, base, "/api/sessions"))) == 1
  assert call(op, base, f"/api/sessions/{name}", method="DELETE")[0] == 200
  assert call(op, base, "/api/logout", {})[0] == 200
  assert call(op, base, "/api/status")[0] == 401
  assert call(op, base, "/api/login", {"pin": "0000"})[0] == 401
  assert call(op, base, "/api/login", {"pin": "1234"})[0] == 200
  assert call(op, base, "/api/status")[0] == 200


def test_lockout(srv, monkeypatch):
  s, base, _ = srv
  call(client(), base, "/api/setpin", {"pin": "1234", "pin2": "1234"})
  op = client()
  codes = [call(op, base, "/api/login", {"pin": "9999"})[0] for _ in range(5)]
  assert codes[:4] == [401] * 4 and codes[-1] == 429
  assert call(op, base, "/api/login", {"pin": "1234"})[0] == 429
  s.ctx.auth.fails.clear()
  assert call(op, base, "/api/login", {"pin": "1234"})[0] == 200


def test_static(srv):
  _, base, _ = srv
  op = client()
  st, body, h = call(op, base, "/manifest.webmanifest")
  assert st == 200 and "manifest+json" in h["Content-Type"] and json.loads(body)["short_name"] == "CAN Log"
  for n in (180, 192, 512):
    st, body, h = call(op, base, f"/icon-{n}.png")
    assert st == 200 and h["Content-Type"] == "image/png" and body[:8] == b"\x89PNG\r\n\x1a\n"
  assert call(op, base, "/nope")[0] == 404


def test_no_wlan_on_pc():
  assert webui.iface_ipv4_addrs("definitely-not-an-iface0") in (set(), {"127.0.0.1"})


def test_diff_states(srv, tmp_path):
  from openpilot.sunnypilot.canlog.tests.test_canlog import _real_log
  _, base, _ = srv
  _real_log(tmp_path / "r.canlog")
  op = client()
  call(op, base, "/api/setpin", {"pin": "1234", "pin2": "1234"})
  d = js(call(op, base, "/api/diff?session=r&pre=3&post=6&settle=2"))
  assert d["results"][0]["changes"][0]["addr"] == 0x300
  assert d["states"][0]["addr"] == 0x300 and d["states"][0]["on_vals"] == ["05"]
  assert d["steps"][0]["addr"] == 0x16A954FB and d["profile"]["mux"] == 1
  assert call(op, base, "/api/diff?session=r&settle=x")[0] == 400
  assert b"stateCards" in call(op, base, "/")[1]


def test_verdict_api(srv, tmp_path):
  from openpilot.sunnypilot.canlog.tests.test_canlog import _guided_log
  _, base, _ = srv
  _guided_log(tmp_path / "g.canlog")
  op = client()
  assert call(op, base, "/api/verdict?session=g")[0] == 401
  call(op, base, "/api/setpin", {"pin": "1234", "pin2": "1234"})
  v = js(call(op, base, "/api/verdict?session=g"))
  assert v["session"] == "g" and v["candidates"][0]["level"] == "green" and v["markers"] == 8
  assert js(call(op, base, "/api/verdict"))["session"] == "g"  # latest
  assert call(op, base, "/api/verdict?session=nope")[0] == 404
  page = call(op, base, "/")[1]
  assert b"data-t=\"test\"" in page and b"showVerdict" in page and b"wakeLock" in page and b"Manual mode" in page


def test_live_has_climate_candidate(srv):
  _, base, _ = srv
  op = client()
  call(op, base, "/api/setpin", {"pin": "1234", "pin2": "1234"})
  live = js(call(op, base, "/api/live"))
  assert "climate_on_candidate" in live["0x000003B5"]["1"]["decoded"]
  assert live["names"]["0x000003B5"].startswith("Climate status")
