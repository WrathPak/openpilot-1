import logging
import os

DEFAULT_LOG_ROOT = "/data/canlogs"
KEEP_AWAKE_NAME = ".keep_can_awake"
MIN_FREE_BYTES = 3 * 1024 ** 3
MAX_FILE_BYTES = 2 * 1024 ** 3
MAX_SESSION_S = 6 * 3600  # a forgotten session keeps the panda's CAN transceivers awake and drains the 12 V battery
EXT = ".canlog"
DBC_REL = os.path.join("opendbc_repo", "opendbc", "dbc", "generator", "volkswagen", "_vw_mqbevo_common.dbc")


def log_root() -> str:
  return os.environ.get("CANLOG_ROOT") or DEFAULT_LOG_ROOT


def keep_awake_path(root: str | None = None) -> str:
  return os.path.join(root or log_root(), KEEP_AWAKE_NAME)


def basedir() -> str:
  try:
    from openpilot.common.basedir import BASEDIR
    return str(BASEDIR)
  except Exception:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def dbc_path() -> str:
  return os.path.join(basedir(), DBC_REL)


class _Log:
  def __init__(self) -> None:
    self._l = None
    try:
      from openpilot.common.swaglog import cloudlog
      self._l = cloudlog
    except Exception:
      self._l = logging.getLogger("canlog")

  def info(self, msg: str, *a) -> None:
    self._l.info(msg, *a)

  def warning(self, msg: str, *a) -> None:
    self._l.warning(msg, *a)

  def exception(self, msg: str, *a) -> None:
    self._l.exception(msg, *a)


_log: _Log | None = None


def get_log() -> _Log:
  global _log
  if _log is None:
    _log = _Log()
  return _log
