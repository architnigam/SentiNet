"""Evidence-rich alerts, signature cooldowns, and durable local JSON Lines logs."""

from collections import Counter, OrderedDict
import json
import math
import os
from pathlib import Path
from uuid import uuid4

from .config import Settings, settings_from_dict
from .detection.engine import Findings
from .errors import AlertLogError, DetectionError
from .risk import score_rules

MAX_COOLDOWNS = 16_384
MAX_ALERT_BYTES = 1_048_576


def _reject_constant(value: str):
    raise ValueError(f"Invalid JSON constant: {value}")


class AlertLog:
    """Single-writer append log; validate its last record before appending.

    Each write is flushed and synced. A failed partial append is rolled back
    to its original byte position where possible. Concurrent writers are not
    supported. Earlier complete records are left untouched.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._handle = None

    def __enter__(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = self.path.open("a+b")
            self._handle.seek(0, 2)
            size = self._handle.tell()
            if size:
                # Limit validation memory; an oversized last record is rejected.
                start = max(0, size - MAX_ALERT_BYTES)
                previous = b"\n"
                if start:
                    self._handle.seek(start - 1)
                    previous = self._handle.read(1)
                self._handle.seek(start)
                tail = self._handle.read()
                if not tail.endswith(b"\n"):
                    raise AlertLogError("Alert log has an incomplete final line; repair it or use a new log.")
                if start and b"\n" not in tail[:-1] and previous != b"\n":
                    raise AlertLogError("Alert log final record exceeds the 1 MiB limit.")
                lines = tail.splitlines()
                last = lines[-1] if lines else b""
                value = json.loads(last, parse_constant=_reject_constant)
                if (not isinstance(value, dict) or type(value.get("schema_version")) is not int
                        or value["schema_version"] != 1 or not isinstance(value.get("alert_id"), str)
                        or not value["alert_id"]):
                    raise AlertLogError("Alert log final line is not a NetSentinel alert.")
            return self
        except (OSError, ValueError) as exc:
            self.close()
            raise AlertLogError(f"Cannot open alert log '{self.path}': {exc}") from exc
        except AlertLogError:
            self.close()
            raise

    def append(self, alert: dict) -> None:
        if self._handle is None:
            raise AlertLogError("Alert log is not open.")
        try:
            encoded = (json.dumps(alert, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise AlertLogError(f"Alert is not valid JSON: {exc}") from exc
        if len(encoded) > MAX_ALERT_BYTES:
            raise AlertLogError("Alert exceeds the 1 MiB record limit.")
        position = None
        try:
            self._handle.seek(0, 2)
            position = self._handle.tell()
            written = self._handle.write(encoded)
            if written != len(encoded):
                raise OSError("Incomplete alert write")
            self._handle.flush()
            os.fsync(self._handle.fileno())
        except OSError as exc:
            try:
                if position is not None:
                    self._handle.seek(position)
                    self._handle.truncate()
                    self._handle.flush()
            except OSError:
                pass  # Original write error is retained; next run checks the tail.
            raise AlertLogError(f"Cannot persist alert to '{self.path}': {exc}") from exc

    def close(self) -> None:
        if self._handle is not None:
            handle, self._handle = self._handle, None
            handle.close()

    def __exit__(self, *args):
        self.close()


class AlertManager:
    def __init__(self, settings: Settings, *, max_cooldowns: int = MAX_COOLDOWNS):
        if type(max_cooldowns) is not int or max_cooldowns < 1:
            raise ValueError("max_cooldowns must be a positive integer")
        self.settings = settings_from_dict(settings.to_dict())
        self.max_cooldowns = max_cooldowns
        self.run_id = uuid4().hex
        self.emitted = 0
        self.suppressed = 0
        self.rule_counts = Counter()
        self.severity_counts = Counter()
        self._cooldowns = OrderedDict()
        self.watermark = None

    def advance(self, now: float) -> None:
        try:
            valid_time = type(now) in (int, float) and math.isfinite(now) and now >= 0
        except OverflowError:
            valid_time = False
        if not valid_time:
            raise ValueError("Alert time must be finite and nonnegative")
        if self.watermark is not None and now < self.watermark:
            raise ValueError("Alert time must not move backwards")
        self.watermark = now
        while self._cooldowns and now - next(iter(self._cooldowns.values())) >= self.settings.alert_cooldown_seconds:
            self._cooldowns.popitem(last=False)

    def create(self, findings: Findings, log: AlertLog) -> dict | None:
        risk = score_rules(findings.evidence, self.settings)
        if risk.score == 0:
            return None
        now = findings.timestamp
        self.advance(now)
        signature = (findings.source_ip, findings.destination_ip, risk.rules)
        if signature in self._cooldowns:
            self.suppressed += 1
            return None
        if self.settings.alert_cooldown_seconds and len(self._cooldowns) >= self.max_cooldowns:
            raise DetectionError("Alert cooldown limit reached; detection stopped without evicting cooldowns.")
        alert = {
            "schema_version": 1,
            "alert_id": uuid4().hex,
            "run_id": self.run_id,
            "timestamp": now,
            "source_ip": findings.source_ip,
            "destination_ip": findings.destination_ip,
            "window_seconds": self.settings.window_seconds,
            "window_start": max(0, now - self.settings.window_seconds),
            "rules": list(risk.rules),
            "score": risk.score,
            "severity": risk.severity,
            "evidence": findings.evidence,
        }
        log.append(alert)
        # Update cooldowns/counters only after the alert has been persisted.
        if self.settings.alert_cooldown_seconds:
            self._cooldowns[signature] = now
        self.emitted += 1
        self.rule_counts.update(risk.rules)
        self.severity_counts[risk.severity] += 1
        return alert

    def snapshot(self) -> dict:
        return {"run_id": self.run_id, "alerts_emitted": self.emitted,
                "alerts_suppressed": self.suppressed, "rule_alert_counts": dict(self.rule_counts),
                "severity_alert_counts": dict(self.severity_counts),
                "active_cooldowns": len(self._cooldowns), "cooldown_limit": self.max_cooldowns}
