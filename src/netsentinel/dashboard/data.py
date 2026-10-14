"""Bounded, defensive readers; dashboard refresh never imports capture code."""

from collections import deque
from datetime import datetime, timezone
import json
import math
from pathlib import Path

MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_LOG_BYTES = 2 * 1024 * 1024
SEVERITIES = ("Low", "Medium", "High", "Critical")
RULES = {"port_scan", "syn_flood", "traffic_anomaly"}


class DashboardDataError(ValueError):
    pass


def _constant(value):
    raise DashboardDataError(f"Invalid JSON constant: {value}")


def _count(value):
    return type(value) is int and 0 <= value <= 2**63 - 1


def _time(value):
    try:
        return type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def valid_alert(value) -> bool:
    if not isinstance(value, dict):
        return False
    rules = value.get("rules")
    return (
        type(value.get("schema_version")) is int and value["schema_version"] == 1
        and isinstance(value.get("alert_id"), str) and bool(value["alert_id"])
        and isinstance(value.get("run_id"), str) and bool(value["run_id"])
        and _time(value.get("timestamp"))
        and isinstance(value.get("source_ip"), str) and bool(value["source_ip"])
        and (value.get("destination_ip") is None or (isinstance(value["destination_ip"], str) and bool(value["destination_ip"])))
        and _count(value.get("score")) and 1 <= value["score"] <= 100
        and value.get("severity") in SEVERITIES
        and isinstance(rules, list) and bool(rules)
        and all(isinstance(rule, str) and rule in RULES for rule in rules)
        and len(set(rules)) == len(rules)
        and isinstance(value.get("evidence"), dict)
    )


def read_snapshot(path: str | Path) -> dict:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(MAX_REPORT_BYTES + 1)
        if len(data) > MAX_REPORT_BYTES:
            raise DashboardDataError("Snapshot exceeds the 8 MiB dashboard limit.")
        value = json.loads(data, parse_constant=_constant)
    except (OSError, ValueError, UnicodeError) as exc:
        raise DashboardDataError(f"Cannot load snapshot '{path}': {exc}") from exc
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] not in (1, 2):
        raise DashboardDataError("Unsupported snapshot schema.")
    if value.get("stage") not in ("packet_analysis", "threat_analysis"):
        raise DashboardDataError("Unknown analysis stage.")
    stats = value.get("statistics")
    if not isinstance(stats, dict):
        raise DashboardDataError("Snapshot has no packet statistics.")
    for name in ("total_packets", "analyzed_packets", "skipped_packets"):
        if not _count(stats.get(name)):
            raise DashboardDataError(f"Invalid packet count: {name}.")
    if stats["analyzed_packets"] + stats["skipped_packets"] != stats["total_packets"]:
        raise DashboardDataError("Packet totals are inconsistent.")
    protocols = stats.get("protocol_counts")
    if (not isinstance(protocols, dict) or set(protocols) != {"TCP", "UDP"}
            or not all(_count(count) for count in protocols.values())
            or sum(protocols.values()) != stats["analyzed_packets"]):
        raise DashboardDataError("Protocol counts are inconsistent.")
    sources = stats.get("source_counts", {})
    if (not isinstance(sources, dict) or len(sources) > 4096
            or not all(isinstance(ip, str) and _count(count) for ip, count in sources.items())
            or sum(sources.values()) > stats["analyzed_packets"]):
        raise DashboardDataError("Invalid source counts.")
    samples = value.get("sample_packets", [])
    if not isinstance(samples, list) or len(samples) > 1000 or not all(isinstance(row, dict) for row in samples):
        raise DashboardDataError("Invalid packet samples.")
    detection = value.get("detection", {})
    if not isinstance(detection, dict) or not _count(detection.get("alerts_emitted", 0)):
        raise DashboardDataError("Invalid detection counters.")
    if detection.get("run_id") is not None and not isinstance(detection["run_id"], str):
        raise DashboardDataError("Invalid detection run ID.")
    alerts = value.get("recent_alerts", [])
    if not isinstance(alerts, list) or len(alerts) > 100 or not all(valid_alert(alert) for alert in alerts):
        raise DashboardDataError("Invalid recent alerts.")
    monitor = value.get("monitor")
    if monitor is not None and (not isinstance(monitor, dict)
            or monitor.get("status") not in {"starting", "running", "completed", "stopped", "failed"}
            or not _time(monitor.get("updated_at"))
            or not isinstance(monitor.get("interface"), str)
            or (monitor.get("error") is not None and not isinstance(monitor["error"], str))):
        raise DashboardDataError("Invalid live-monitor status.")
    return value


def read_recent_alerts(path: str | Path, *, run_id: str | None = None,
                       limit: int = 100) -> tuple[list[dict], list[str]]:
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("limit must be from 1 through 100")
    try:
        with Path(path).open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            start = max(0, size - MAX_LOG_BYTES)
            previous = b"\n"
            if start:
                handle.seek(start - 1)
                previous = handle.read(1)
            handle.seek(start)
            data = handle.read(MAX_LOG_BYTES)
    except OSError as exc:
        return [], [f"Alert log is unavailable: {exc}"]
    messages = []
    if start:
        messages.append("Showing only the latest 2 MiB of the alert log.")
        if previous != b"\n":
            data = data.partition(b"\n")[2]
    if data and not data.endswith(b"\n"):
        messages.append("An incomplete final alert line was ignored; it may still be being written.")
        data = data.rpartition(b"\n")[0]
    alerts = deque(maxlen=limit)
    malformed = 0
    for line in data.splitlines():
        try:
            value = json.loads(line, parse_constant=_constant)
            if not valid_alert(value):
                raise DashboardDataError("Invalid alert record")
            if run_id is None or value["run_id"] == run_id:
                alerts.append(value)
        except (ValueError, UnicodeError):
            malformed += 1
    if malformed:
        messages.append(f"Ignored {malformed} invalid alert line(s).")
    return list(alerts), messages


def alert_rows(alerts: list[dict], severities, source_filter="") -> list[dict]:
    selected = set(severities)
    query = source_filter.casefold().strip()
    rows = []
    for alert in reversed(alerts):
        target = alert.get("destination_ip") or "All destinations"
        if alert["severity"] not in selected or (query and query not in (alert["source_ip"] + " " + target).casefold()):
            continue
        try:
            timestamp = datetime.fromtimestamp(alert["timestamp"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (ValueError, OverflowError, OSError):
            timestamp = str(alert["timestamp"])
        rows.append({"Time": timestamp, "Severity": alert["severity"], "Score": alert["score"],
                     "Source": alert["source_ip"], "Destination": target,
                     "Rules": ", ".join(rule.replace("_", " ") for rule in alert["rules"])})
    return rows
