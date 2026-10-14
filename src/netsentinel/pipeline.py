"""Offline packet analysis with optional Part 2 threat detection and logging."""

from collections import deque
from contextlib import ExitStack, closing
from pathlib import Path

from .analyzer import analyze_packet
from .alerts import AlertLog, AlertManager
from .capture import read_capture
from .config import Settings
from .detection.engine import DetectionEngine
from .errors import NetSentinelError
from .statistics import TrafficStatistics

MAX_SAMPLE_PACKETS = 1000
MAX_RECENT_ALERTS = 100


def analyze_capture(path: str | Path, *, settings: Settings | None = None,
                    packet_limit: int | None = None, sample_limit: int = 10,
                    detect: bool = False, alert_log_path: str | Path | None = None) -> dict:
    """Produce a JSON-ready summary, retaining only a bounded packet sample."""
    if type(sample_limit) is not int or not 0 <= sample_limit <= MAX_SAMPLE_PACKETS:
        raise ValueError(f"sample_limit must be an integer from 0 through {MAX_SAMPLE_PACKETS}")
    if type(detect) is not bool:
        raise ValueError("detect must be boolean")
    if alert_log_path is not None and not detect:
        raise ValueError("alert_log_path requires detection")
    settings = settings or Settings()
    log_path = Path(alert_log_path if alert_log_path is not None else settings.alert_log_path)
    if detect and (log_path.resolve() == Path(path).resolve() or (
            log_path.exists() and Path(path).exists() and log_path.samefile(path))):
        raise NetSentinelError("Alert log must not overwrite the capture.")
    statistics = TrafficStatistics()
    sample = []
    engine = DetectionEngine(settings) if detect else None
    manager = AlertManager(settings) if detect else None
    recent_alerts = deque(maxlen=MAX_RECENT_ALERTS)
    with ExitStack() as stack:
        log = stack.enter_context(AlertLog(log_path)) if detect else None
        frames = stack.enter_context(closing(read_capture(path, limit=packet_limit)))
        for frame in frames:
            result = analyze_packet(frame)
            statistics.observe(frame, result)
            if result.record is not None and len(sample) < sample_limit:
                sample.append(result.record.to_dict())
            if result.record is not None and engine is not None:
                findings = engine.process(result.record)
                manager.advance(engine.watermark)
                if findings is not None:
                    alert = manager.create(findings, log)
                    if alert is not None:
                        recent_alerts.append(alert)
    report = {
        "schema_version": 2 if detect else 1,
        "stage": "threat_analysis" if detect else "packet_analysis",
        "source": str(Path(path).resolve()),
        "packet_limit": packet_limit,
        "settings": settings.to_dict(),
        "statistics": statistics.to_dict(),
        "sample_packets": sample,
    }
    if detect:
        report["detection"] = {**engine.snapshot(), **manager.snapshot(),
                               "alert_log_path": str(log_path.resolve()),
                               "recent_alert_limit": MAX_RECENT_ALERTS}
        report["recent_alerts"] = list(recent_alerts)
    return report
