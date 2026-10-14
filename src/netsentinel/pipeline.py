"""Shared analysis session for offline and live capture; payloads are never retained."""

from collections import deque
from contextlib import closing
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


class AnalysisSession:
    def __init__(self, source: str, *, settings: Settings | None = None,
                 detect: bool = False, sample_limit: int = 10,
                 packet_limit: int | None = None, alert_log_path: str | Path | None = None):
        if type(sample_limit) is not int or not 0 <= sample_limit <= MAX_SAMPLE_PACKETS:
            raise ValueError(f"sample_limit must be an integer from 0 through {MAX_SAMPLE_PACKETS}")
        if type(detect) is not bool:
            raise ValueError("detect must be boolean")
        if alert_log_path is not None and not detect:
            raise ValueError("alert_log_path requires detection")
        self.source = source
        self.settings = settings or Settings()
        self.detect = detect
        self.sample_limit = sample_limit
        self.packet_limit = packet_limit
        self.log_path = Path(alert_log_path if alert_log_path is not None else self.settings.alert_log_path)
        self.statistics = TrafficStatistics()
        self.sample = []
        self.engine = DetectionEngine(self.settings) if detect else None
        self.manager = AlertManager(self.settings) if detect else None
        self.recent_alerts = deque(maxlen=MAX_RECENT_ALERTS)
        self.log = None

    def __enter__(self):
        if self.detect:
            self.log = AlertLog(self.log_path)
            self.log.__enter__()
        return self

    def __exit__(self, *args):
        if self.log is not None:
            self.log.close()

    def consume(self, frame) -> None:
        result = analyze_packet(frame)
        self.statistics.observe(frame, result)
        if result.record is not None and len(self.sample) < self.sample_limit:
            self.sample.append(result.record.to_dict())
        if result.record is not None and self.engine is not None:
            findings = self.engine.process(result.record)
            self.manager.advance(self.engine.watermark)
            if findings is not None:
                alert = self.manager.create(findings, self.log)
                if alert is not None:
                    self.recent_alerts.append(alert)

    def report(self) -> dict:
        report = {
            "schema_version": 2 if self.detect else 1,
            "stage": "threat_analysis" if self.detect else "packet_analysis",
            "source": self.source,
            "packet_limit": self.packet_limit,
            "settings": self.settings.to_dict(),
            "statistics": self.statistics.to_dict(),
            "sample_packets": list(self.sample),
        }
        if self.detect:
            report["detection"] = {**self.engine.snapshot(), **self.manager.snapshot(),
                                   "alert_log_path": str(self.log_path.resolve()),
                                   "recent_alert_limit": MAX_RECENT_ALERTS}
            report["recent_alerts"] = list(self.recent_alerts)
        return report


def analyze_capture(path: str | Path, *, settings: Settings | None = None,
                    packet_limit: int | None = None, sample_limit: int = 10,
                    detect: bool = False, alert_log_path: str | Path | None = None) -> dict:
    session = AnalysisSession(str(Path(path).resolve()), settings=settings, detect=detect,
                              sample_limit=sample_limit, packet_limit=packet_limit,
                              alert_log_path=alert_log_path)
    if detect and (session.log_path.resolve() == Path(path).resolve() or (
            session.log_path.exists() and Path(path).exists() and session.log_path.samefile(path))):
        raise NetSentinelError("Alert log must not overwrite the capture.")
    with session, closing(read_capture(path, limit=packet_limit)) as frames:
        for frame in frames:
            session.consume(frame)
    return session.report()
