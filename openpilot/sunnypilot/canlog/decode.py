import os
import sys
from typing import Any

from openpilot.sunnypilot.canlog import config

WATCH: dict[int, str] = {
  0x16A954FB: "Climate setpoint / heating state",
  0x16A95493: "Heating active",
  0x1B000010: "NMH_Gateway (gateway network management)",
  0x3B5: "Climate status? (candidate)",
  0x668: "Climate status 2? (candidate)",
}

NMH_ADDR = 0x1B000010

# (name, start_bit, size) all little-endian unsigned, factor 1, offset 0
NMH_FALLBACK: list[tuple[str, int, int]] = [
  ("NM_Gateway_SNI", 0, 8), ("NM_Gateway_NM_State", 16, 6), ("NM_Gateway_Car_Wakeup", 22, 1),
  ("NM_Gateway_Wakeup", 24, 8), ("NM_Gateway_NM_aktiv_KL15", 32, 1), ("NM_Gateway_NM_aktiv_Diagnose", 33, 1),
  ("NM_Gateway_NM_aktiv_Tmin", 34, 1), ("NM_Gateway_ACAN_Aktivitaet", 35, 1), ("NM_Gateway_FCAN_Aktivitaet", 36, 1),
  ("NM_Gateway_KCAN_Aktivitaet", 37, 1), ("NM_Gateway_ICAN_Aktivitaet", 38, 1), ("NM_Gateway_DiagCAN_Aktivitaet", 39, 1),
  ("NM_Gateway_ECAN_Aktivitaet", 40, 1), ("NM_Gateway_Energie_LIN_Aktivi000", 41, 1),
  ("NM_Gateway_Bedien_LIN_Aktivitaet", 42, 1), ("NM_Gateway_EM_Aktivitaet", 43, 1), ("NM_Gateway_NL_EM", 48, 1),
  ("NM_Gateway_NL_Shutdown", 49, 1), ("NM_Gateway_NL_Spg_Messung", 50, 1), ("NM_Gateway_NL_Wakeup_Monitor", 51, 1),
  ("NM_Gateway_UDS_CC", 63, 1),
]

# (name, start, size, is_signed, factor, offset)
SigTable = list[tuple[str, int, int, bool, float, float]]

_dbc_cache: SigTable | None = None
_dbc_tried = False


def nmh_signals_fallback() -> SigTable:
  return [(n, s, z, False, 1, 0) for n, s, z in NMH_FALLBACK]


def nmh_signals_dbc(path: str | None = None) -> SigTable | None:
  try:
    try:
      from opendbc.can.dbc import DBC
    except Exception:
      sys.path.insert(0, os.path.join(config.basedir(), "opendbc_repo"))
      from opendbc.can.dbc import DBC
    dbc = DBC(path or config.dbc_path())
    for key, msg in dbc.addr_to_msg.items():
      if (key & 0x1FFFFFFF) == NMH_ADDR:
        sigs = [(s.name, s.start_bit, s.size, s.is_signed, s.factor, s.offset) for s in msg.sigs.values()]
        sigs.sort(key=lambda x: x[1])
        return sigs or None
  except Exception:
    return None
  return None


def _nmh_table() -> SigTable:
  global _dbc_cache, _dbc_tried
  if not _dbc_tried:
    _dbc_tried = True
    _dbc_cache = nmh_signals_dbc()
  return _dbc_cache or nmh_signals_fallback()


def decode_signals(data: bytes, sigs: SigTable) -> dict[str, object]:
  v = int.from_bytes(data, "little")
  nbits = len(data) * 8
  out: dict[str, object] = {}
  for name, start, size, signed, factor, offset in sigs:
    if start + size > nbits:
      continue
    x = (v >> start) & ((1 << size) - 1)
    if signed and x >> (size - 1):
      x -= 1 << size
    if factor != 1 or offset != 0:
      out[name] = x * factor + offset
    else:
      out[name] = x
  return out


def fmt_addr(addr: int) -> str:
  return f"0x{addr:08X}"


def parse_addr(s: str | int) -> int:
  if isinstance(s, int):
    return s
  t = s.strip().lower()
  if t.startswith("0x"):
    return int(t, 16)
  if t.isdigit():
    return int(t, 10)
  return int(t, 16)


def _setpoint(raw: int) -> str:
  if raw == 0:
    return "LO"
  if 1 <= raw <= 28:
    return f"{16.0 + 0.5 * (raw - 1):.1f}C"
  if raw == 29:
    return "HI"
  return f"?({raw})"


def decode(addr: int, data: bytes) -> dict[str, object]:
  try:
    data = bytes(data)
    out: dict[str, Any] = {}
    if addr == 0x16A954FB:
      if len(data) >= 3:
        raw = ((data[2] & 0xF) << 2) | ((data[1] & 0xC0) >> 6)
        out["setpoint_raw"] = raw
        out["setpoint"] = _setpoint(raw)
      out["raw"] = data.hex().upper()
    elif addr == 0x16A95493:
      if len(data) >= 1:
        out["heating_active"] = data[0] == 0x01
      out["raw"] = data.hex().upper()
    elif addr == 0x3B5:
      if len(data) >= 1:
        out["climate_on_candidate"] = bool(data[0] & 0x80)
      out["raw"] = data.hex().upper()
    elif addr == 0x668:
      if len(data) >= 8:
        out["climate_on_candidate"] = bool(data[7] & 0x10)
      if len(data) >= 4:
        out["b3"] = data[3]
      out["raw"] = data.hex().upper()
    elif addr == NMH_ADDR:
      out.update(decode_signals(data, _nmh_table()))
      out["raw"] = data.hex().upper()
    return out
  except Exception:
    return {}
