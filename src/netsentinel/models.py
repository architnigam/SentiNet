"""Immutable packet data shared by capture, analysis, and later detection."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class CapturedPacket:
    data: bytes
    timestamp: float | None
    wire_length: int
    link_type: int


@dataclass(frozen=True)
class PacketRecord:
    timestamp: float
    source_ip: str
    destination_ip: str
    ip_version: int
    protocol: str
    source_port: int
    destination_port: int
    tcp_flags: int
    captured_length: int
    wire_length: int
    truncated: bool

    @property
    def syn_without_ack(self) -> bool:
        return self.protocol == "TCP" and bool(self.tcp_flags & 0x02) and not bool(self.tcp_flags & 0x10)

    def to_dict(self) -> dict:
        result = asdict(self)
        result["syn_without_ack"] = self.syn_without_ack
        return result


@dataclass(frozen=True)
class AnalysisResult:
    record: PacketRecord | None
    skip_reason: str | None = None
