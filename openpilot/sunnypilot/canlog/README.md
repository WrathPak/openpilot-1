# canlog: read-only offroad CAN logger + phone UI

Phase-1 tooling for reverse engineering VW MEB remote climate control. Records all
three CAN buses while the car is offroad, lets you drop text markers from your phone,
and diffs what changed around each marker.

**Strictly read-only.** The logger never opens the panda itself and never publishes
`sendcan`. It subscribes to the `can` msgq socket that `pandad` already publishes at
100 Hz while offroad, with the panda in `NO_OUTPUT` safety mode (receive-only).

## Files

| File | Purpose |
|------|---------|
| `canlogd.py` | Managed process (`only_offroad`). Starts the recorder thread and the web UI. |
| `recorder.py` | Subscribes to `can`, writes `/data/canlogs/<timestamp>.canlog`, tracks latest frames for the watch list. |
| `decode.py` | Watch list and decoders (climate setpoint, heating active, `NMH_Gateway` from the opendbc MQB-evo DBC). |
| `analyze.py` | Search/diff CLI: list frames for IDs, diff bytes around markers (mux/cycle/counter aware), ON/OFF state and Temp step candidates. |
| `webui.py` | Stdlib HTTP server on port 8080, Wi-Fi/hotspot (`wlan0`) only, PIN protected, iOS home-screen web app. |
| `tools/dev_webui.py` | Run the UI on a PC with fake data. |

## Changes outside this directory

* `system/manager/process_config.py`: one line registering `canlogd` as an offroad-only process.
* `selfdrive/pandad/pandad.cc`: one line. While `/data/canlogs/.keep_can_awake` exists
  (created by the recorder only during an active session) pandad does not put the panda
  into power-save, so buses 1 and 2 stay powered while parked. Power-save is ignition-off
  only, so nothing changes while driving. This is a C++ change, so the first boot after
  installing rebuilds (a few minutes with a black screen; normal for git installs).

A session auto-stops when free space drops below 3 GiB, the file passes 2 GiB, or it has run
for 6 hours (so a forgotten session cannot drain the 12 V battery overnight).

## Log format

```
# canlog v1 started=<ISO wall time> mono_ns=<logMonoTime> device=<host>
F <mono_ns> <bus> <ADDR hex> <DATA hex>
M <mono_ns> <marker text>
```

## CLI

```bash
cd /data/openpilot
python -m openpilot.sunnypilot.canlog.analyze latest                 # summary
python -m openpilot.sunnypilot.canlog.analyze latest --list 0x16A954FB,0x1B000010
python -m openpilot.sunnypilot.canlog.analyze latest --diff --pre 3 --post 3
python -m openpilot.sunnypilot.canlog.analyze /data/canlogs/2026-10-12_17-00-00.canlog --diff --json
python -m openpilot.sunnypilot.canlog.analyze latest --states --post 30 --settle 10   # ON/OFF + Temp up/down candidates
```

The diff makes one pass over the whole log to filter real-car noise:

- **mux / cyclic IDs** (VIN `0x6B4`, BAP `0x1733xx10` cycles): byte0 used as a mux/channel selector, or a
  payload sequence that repeats with a fixed period. A change only counts if the value was never seen before
  the marker for that mux value, or if it breaks the payload cycle. These IDs must change at >= 0.2 Hz, so a
  real state toggled ON/OFF/ON/OFF is not mistaken for a cycle.
- **counter bytes** (>= 8 changes, >= 90 % in one direction) and **noise bytes** (CRC-like) are marked noisy (`~`).
- **IDs that pause** in the post window and come back later are not counted as changes.

`--states` lists bytes whose value set during **Climate ON** periods never overlaps **Climate OFF** periods, and
bytes that step one way on every **Temp up** and the other way on every **Temp down**. Remote (app) commands
can take a while to reach the car, so each ON/OFF period ignores its first half plus `--settle` seconds. For app
tests, hold each state for a minute or more, repeat ON/OFF a few times, and use a long `--post` (or the
"after" box in the web UI).

## Web UI

`http://<device wifi ip>:8080` on the same Wi-Fi, or `http://192.168.43.1:8080` on the
device hotspot. First visit sets the PIN. Forgot it: `rm /data/canlogs/pin.json` over SSH.
Port 8080 is also used by the optional copyparty file server; keep **Enable Copyparty** off.

Dev on PC:

```bash
CANLOG_BIND_ANY=1 CANLOG_ROOT=/tmp/canlogs python -m openpilot.sunnypilot.canlog.tools.dev_webui
```

## Tests

```bash
python -m pytest openpilot/sunnypilot/canlog/tests -q
```
