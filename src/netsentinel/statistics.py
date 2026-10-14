"""Bounded aggregate traffic counters, without storing packet payloads."""

from collections import Counter
from dataclasses import dataclass, field
import math

from .models import AnalysisResult, CapturedPacket

MAX_TRACKED_SOURCES = 4096


@dataclass
class TrafficStatistics:
    source_limit: int = MAX_TRACKED_SOURCES
    total_packets: int = 0
    analyzed_packets: int = 0
    captured_bytes: int = 0
    wire_bytes: int = 0
    truncated_packets: int = 0
    out_of_order_timestamps: int = 0
    untracked_source_packets: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    _previous_timestamp: float | None = None
    protocol_counts: Counter = field(default_factory=lambda: Counter({"TCP": 0, "UDP": 0}))
    skip_reasons: Counter = field(default_factory=Counter)
    source_counts: Counter = field(default_factory=Counter)

    def __post_init__(self) -> None:
        if type(self.source_limit) is not int or self.source_limit < 1:
            raise ValueError("source_limit must be a positive integer")

    def observe(self, frame: CapturedPacket, result: AnalysisResult) -> None:
        self.total_packets += 1
        self.captured_bytes += len(frame.data)
        self.wire_bytes += frame.wire_length
        self.truncated_packets += len(frame.data) < frame.wire_length
        timestamp = frame.timestamp
        try:
            valid_time = type(timestamp) in (float, int) and math.isfinite(timestamp) and timestamp >= 0
        except OverflowError:
            valid_time = False
        if valid_time:
            if self._previous_timestamp is not None and timestamp < self._previous_timestamp:
                self.out_of_order_timestamps += 1
            self._previous_timestamp = timestamp
            self.first_timestamp = timestamp if self.first_timestamp is None else min(self.first_timestamp, timestamp)
            self.last_timestamp = timestamp if self.last_timestamp is None else max(self.last_timestamp, timestamp)
        if result.record is None:
            self.skip_reasons[result.skip_reason or "unknown"] += 1
            return
        self.analyzed_packets += 1
        record = result.record
        self.protocol_counts[record.protocol] += 1
        if record.source_ip in self.source_counts or len(self.source_counts) < self.source_limit:
            self.source_counts[record.source_ip] += 1
        else:
            self.untracked_source_packets += 1

    def to_dict(self) -> dict:
        duration = 0.0 if self.first_timestamp is None else self.last_timestamp - self.first_timestamp
        return {
            "total_packets": self.total_packets,
            "analyzed_packets": self.analyzed_packets,
            "skipped_packets": self.total_packets - self.analyzed_packets,
            "captured_bytes": self.captured_bytes,
            "wire_bytes": self.wire_bytes,
            "truncated_packets": self.truncated_packets,
            "protocol_counts": dict(self.protocol_counts),
            "skip_reasons": dict(self.skip_reasons),
            "source_counts": dict(self.source_counts),
            "source_tracking_limit": self.source_limit,
            "untracked_source_packets": self.untracked_source_packets,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "duration_seconds": duration,
            "out_of_order_timestamps": self.out_of_order_timestamps,
        }
