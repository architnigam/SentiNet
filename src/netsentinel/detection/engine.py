"""Incremental, bounded rolling windows and observational TCP handshake tracking."""

from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
import math

from ..config import Settings, settings_from_dict
from ..errors import DetectionError
from ..models import PacketRecord
from . import port_scan, syn_flood, traffic_anomaly

MAX_EVENTS = 100_000
MAX_CONNECTIONS = 16_384


@dataclass
class PendingConnection:
    timestamp: float
    syn_ack_seen: bool = False


@dataclass(frozen=True)
class Findings:
    source_ip: str
    destination_ip: str | None
    timestamp: float
    evidence: dict


class DetectionEngine:
    """Observe accepted records in order; late records never alter rule state.

    Windows are (now - window, now]. SYN retransmissions count as packets but
    occupy one pending flow. SYN-ACK followed by an originating ACK completes
    a flow; resets in either direction clear it. TCP sequence numbers are not
    validated: this is observed progress, not full TCP stream reassembly.
    """

    def __init__(self, settings: Settings, *, max_events: int = MAX_EVENTS,
                 max_connections: int = MAX_CONNECTIONS):
        for name, value in (("max_events", max_events), ("max_connections", max_connections)):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.settings = settings_from_dict(settings.to_dict())
        self.max_events = max_events
        self.max_connections = max_connections
        self.watermark: float | None = None
        self.processed_packets = 0
        self.late_packets = 0
        self.completed_handshakes = 0
        self.reset_connections = 0
        self._events = deque()
        self._ports: dict[tuple[str, str], Counter] = {}
        self._syns = Counter()
        self._rates = Counter()
        self._pending: OrderedDict[tuple, PendingConnection] = OrderedDict()
        self._pending_counts = Counter()

    @staticmethod
    def _decrement(counter: Counter, key) -> None:
        counter[key] -= 1
        if counter[key] == 0:
            del counter[key]

    def _remove_connection(self, flow: tuple) -> None:
        del self._pending[flow]
        self._decrement(self._pending_counts, flow[:2])

    def _expire(self, now: float) -> None:
        # Subtract event time, not window length: at very large float timestamps
        # now-window can round back to now and incorrectly expire equal times.
        while self._events and now - self._events[0].timestamp >= self.settings.window_seconds:
            old = self._events.popleft()
            pair = (old.source_ip, old.destination_ip)
            ports = self._ports[pair]
            self._decrement(ports, (old.protocol, old.destination_port))
            if not ports:
                del self._ports[pair]
            self._decrement(self._rates, old.source_ip)
            if old.syn_without_ack:
                self._decrement(self._syns, pair)
        while self._pending:
            flow, pending = next(iter(self._pending.items()))
            if now - pending.timestamp < self.settings.window_seconds:
                break
            self._remove_connection(flow)

    def _track_connection(self, record: PacketRecord) -> None:
        if record.protocol != "TCP":
            return
        flow = (record.source_ip, record.destination_ip, record.source_port, record.destination_port)
        reverse = (record.destination_ip, record.source_ip, record.destination_port, record.source_port)
        flags = record.tcp_flags
        if flags & 0x04:  # RST takes precedence over all handshake flags.
            for candidate in (flow, reverse):
                if candidate in self._pending:
                    self._remove_connection(candidate)
                    self.reset_connections += 1
        elif record.syn_without_ack and not flags & 0x01:
            if flow not in self._pending:
                if len(self._pending) >= self.max_connections:
                    raise DetectionError("Pending connection limit reached; detection stopped without discarding state.")
                self._pending[flow] = PendingConnection(record.timestamp)
                self._pending_counts[flow[:2]] += 1
            else:
                self._pending[flow].timestamp = record.timestamp
                self._pending.move_to_end(flow)
        elif flags & 0x12 == 0x12 and reverse in self._pending:
            self._pending[reverse].syn_ack_seen = True
        elif flags & 0x10 and not flags & 0x03 and flow in self._pending:
            if self._pending[flow].syn_ack_seen:
                self._remove_connection(flow)
                self.completed_handshakes += 1

    def process(self, record: PacketRecord) -> Findings | None:
        """Return active findings for this source/target, or a source-wide rate finding."""
        try:
            valid_time = type(record.timestamp) in (int, float) and math.isfinite(record.timestamp) and record.timestamp >= 0
        except OverflowError:
            valid_time = False
        if not valid_time or record.protocol not in ("TCP", "UDP"):
            raise ValueError("Detection requires a finite nonnegative timestamp and TCP/UDP record")
        if self.watermark is not None and record.timestamp < self.watermark:
            self.late_packets += 1
            return None
        self.watermark = record.timestamp
        self._expire(record.timestamp)
        if len(self._events) >= self.max_events:
            raise DetectionError("Detection event limit reached; reduce traffic/window or raise the library limit.")
        self._track_connection(record)
        self._events.append(record)
        self.processed_packets += 1
        pair = (record.source_ip, record.destination_ip)
        ports = self._ports.setdefault(pair, Counter())
        ports[(record.protocol, record.destination_port)] += 1
        self._rates[record.source_ip] += 1
        if record.syn_without_ack:
            self._syns[pair] += 1
        evidence = {}
        scan = port_scan.detect(ports, self.settings.port_scan_unique_ports_threshold)
        syn = syn_flood.detect(self._syns[pair], self._pending_counts[pair], self.settings.syn_packets_threshold)
        traffic = traffic_anomaly.detect(self._rates[record.source_ip], self.settings.window_seconds,
                                         self.settings.traffic_packets_per_second_threshold)
        if scan is not None:
            evidence["port_scan"] = scan
        if syn is not None:
            evidence["syn_flood"] = syn
        target = record.destination_ip if evidence else None
        if traffic is not None:
            evidence["traffic_anomaly"] = traffic
        if not evidence:
            return None
        return Findings(record.source_ip, target, record.timestamp, evidence)

    def snapshot(self) -> dict:
        return {
            "processed_packets": self.processed_packets,
            "late_packets_skipped": self.late_packets,
            "active_events": len(self._events),
            "active_ip_pairs": len(self._ports),
            "active_sources": len(self._rates),
            "pending_connections": len(self._pending),
            "completed_handshakes": self.completed_handshakes,
            "reset_connections": self.reset_connections,
            "event_limit": self.max_events,
            "connection_limit": self.max_connections,
            "watermark": self.watermark,
        }
