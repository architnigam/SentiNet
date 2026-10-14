"""Part 1 offline packet-analysis pipeline (detection follows in Part 2)."""

from contextlib import closing
from pathlib import Path

from .analyzer import analyze_packet
from .capture import read_capture
from .config import Settings
from .statistics import TrafficStatistics

MAX_SAMPLE_PACKETS = 1000


def analyze_capture(path: str | Path, *, settings: Settings | None = None,
                    packet_limit: int | None = None, sample_limit: int = 10) -> dict:
    """Produce a JSON-ready summary, retaining only a bounded packet sample."""
    if type(sample_limit) is not int or not 0 <= sample_limit <= MAX_SAMPLE_PACKETS:
        raise ValueError(f"sample_limit must be an integer from 0 through {MAX_SAMPLE_PACKETS}")
    statistics = TrafficStatistics()
    sample = []
    with closing(read_capture(path, limit=packet_limit)) as frames:
        for frame in frames:
            result = analyze_packet(frame)
            statistics.observe(frame, result)
            if result.record is not None and len(sample) < sample_limit:
                sample.append(result.record.to_dict())
    return {
        "schema_version": 1,
        "stage": "packet_analysis",
        "source": str(Path(path).resolve()),
        "packet_limit": packet_limit,
        "settings": (settings or Settings()).to_dict(),
        "statistics": statistics.to_dict(),
        "sample_packets": sample,
    }
