"""Live session lifecycle and atomic, read-only-dashboard snapshots."""

from contextlib import ExitStack
import json
from pathlib import Path
import time

from .config import Settings
from .errors import NetSentinelError
from .live import capture_live
from .pipeline import AnalysisSession
from .storage import capture_lock, write_report


def monitor_live(interface: str, *, output: str | Path, settings: Settings | None = None,
                 detect: bool = True, alert_log_path: str | Path | None = None,
                 packet_limit: int | None = None, sample_limit: int = 10,
                 duration: float | None = None, stop_event=None) -> dict:
    output = Path(output)
    session = AnalysisSession(f"live://{interface}", settings=settings, detect=detect,
                              alert_log_path=alert_log_path, packet_limit=packet_limit,
                              sample_limit=sample_limit)
    if detect and (output.resolve() == session.log_path.resolve() or (
            output.exists() and session.log_path.exists() and output.samefile(session.log_path))):
        raise NetSentinelError("Live summary and alert log must be different files.")
    started = time.time()

    def publish(status="running", reason=None, error=None):
        report = session.report()
        report["monitor"] = {"mode": "live", "status": status, "interface": interface,
                             "started_at": started, "updated_at": time.time(),
                             "stop_reason": reason, "error": error}
        write_report(output, json.dumps(report, indent=2, allow_nan=False))
        return report

    # Output ownership also prevents another process from clobbering its status.
    with ExitStack() as owners:
        owners.enter_context(capture_lock(output))
        if detect:
            owners.enter_context(capture_lock(session.log_path))
        try:
            with session:
                publish("starting")
                result = capture_live(interface, session.consume, on_tick=publish,
                                      stop_event=stop_event, packet_limit=packet_limit, duration=duration)
                return publish("stopped" if result.reason == "stopped" else "completed", result.reason)
        except KeyboardInterrupt:
            publish("stopped", "keyboard_interrupt")
            raise
        except Exception as exc:
            try:
                publish("failed", error=str(exc))
            except OSError:
                pass  # Preserve the original cause if failure publication also fails.
            raise
