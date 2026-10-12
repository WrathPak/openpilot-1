import signal
import threading

from openpilot.sunnypilot.canlog.recorder import Recorder


def main() -> None:
  rec = Recorder()
  threading.Thread(target=rec.run, daemon=True).start()
  srv = None
  try:
    from openpilot.sunnypilot.canlog.webui import serve
    srv = serve(rec)
    done = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: done.set())
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    while not done.wait(0.5):
      pass
  finally:
    if srv is not None:
      srv.shutdown()
    rec.shutdown()


if __name__ == "__main__":
  main()
