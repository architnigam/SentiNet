"""Strict configuration loading; no capture or file-writing side effects."""

from dataclasses import dataclass, field
import json
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from .errors import ConfigurationError


@dataclass(frozen=True)
class Settings:
    window_seconds: int = 10
    port_scan_unique_ports_threshold: int = 20
    syn_packets_threshold: int = 100
    traffic_packets_per_second_threshold: int = 200
    alert_cooldown_seconds: int = 30
    risk_weights: Mapping[str, int] = field(default_factory=lambda: MappingProxyType(
        {"port_scan": 30, "syn_flood": 40, "traffic_anomaly": 30}
    ))
    severity_min_scores: Mapping[str, int] = field(default_factory=lambda: MappingProxyType(
        {"low": 1, "medium": 25, "high": 50, "critical": 75}
    ))
    alert_log_path: str = "logs/alerts.jsonl"

    def to_dict(self) -> dict:
        return {
            "window_seconds": self.window_seconds,
            "port_scan_unique_ports_threshold": self.port_scan_unique_ports_threshold,
            "syn_packets_threshold": self.syn_packets_threshold,
            "traffic_packets_per_second_threshold": self.traffic_packets_per_second_threshold,
            "alert_cooldown_seconds": self.alert_cooldown_seconds,
            "risk_weights": dict(self.risk_weights),
            "severity_min_scores": dict(self.severity_min_scores),
            "alert_log_path": self.alert_log_path,
        }


def _unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError(f"Duplicate configuration key: {key}")
        result[key] = value
    return result


def _integer(value: object, name: str, minimum: int = 1, maximum: int | None = None) -> None:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        bound = f" through {maximum}" if maximum is not None else " or greater"
        raise ConfigurationError(f"{name} must be an integer {minimum}{bound}.")


def load_settings(path: str | Path | None = None) -> Settings:
    """Merge a partial JSON configuration with defaults, rejecting unknown keys.

    Numeric strings, floats, booleans, duplicate keys, and nonstandard JSON
    constants are rejected rather than silently converted.
    """
    if path is None:
        return Settings()
    try:
        with Path(path).open(encoding="utf-8-sig") as handle:
            supplied = json.load(handle, object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ConfigurationError(f"Cannot read configuration '{path}': {exc}") from exc
    return settings_from_dict(supplied)


def settings_from_dict(supplied: dict) -> Settings:
    """Validate programmatic settings with the same policy used for JSON files."""
    values = Settings().to_dict()
    if not isinstance(supplied, dict):
        raise ConfigurationError("Configuration must be a JSON object.")
    unknown = supplied.keys() - values.keys()
    if unknown:
        raise ConfigurationError(f"Unknown configuration keys: {', '.join(sorted(unknown))}")
    for name, value in supplied.items():
        if name in ("risk_weights", "severity_min_scores"):
            if not isinstance(value, dict):
                raise ConfigurationError(f"{name} must be an object.")
            if value.keys() - values[name].keys():
                raise ConfigurationError(f"Unknown keys in {name}.")
            values[name].update(value)
        else:
            values[name] = value
    for name in ("window_seconds", "port_scan_unique_ports_threshold", "syn_packets_threshold",
                 "traffic_packets_per_second_threshold", "alert_cooldown_seconds"):
        maximum = 86_400 if name == "window_seconds" else (
            604_800 if name == "alert_cooldown_seconds" else 1_000_000_000)
        _integer(values[name], name, minimum=0 if name == "alert_cooldown_seconds" else 1, maximum=maximum)
    for name, value in values["risk_weights"].items():
        _integer(value, f"risk_weights.{name}", maximum=100)
    if sum(values["risk_weights"].values()) > 100:
        raise ConfigurationError("Risk weights must sum to at most 100.")
    severities = values["severity_min_scores"]
    for name, value in severities.items():
        _integer(value, f"severity_min_scores.{name}", maximum=100)
    ordered = [severities[name] for name in ("low", "medium", "high", "critical")]
    if ordered[0] != 1 or any(a >= b for a, b in zip(ordered, ordered[1:])):
        raise ConfigurationError("Severity thresholds must start at 1 and strictly increase.")
    log_path = values["alert_log_path"]
    if not isinstance(log_path, str) or not log_path.strip() or "\0" in log_path:
        raise ConfigurationError("alert_log_path must be a nonempty path without null characters.")
    values["risk_weights"] = MappingProxyType(values["risk_weights"])
    values["severity_min_scores"] = MappingProxyType(values["severity_min_scores"])
    return Settings(**values)
