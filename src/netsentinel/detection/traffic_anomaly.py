"""Source-wide rate indicator using a fixed, full-window denominator."""


def detect(packet_count: int, window_seconds: int, threshold: int) -> dict | None:
    if packet_count < window_seconds * threshold:
        return None
    return {
        "packet_count": packet_count,
        "packets_per_second": packet_count / window_seconds,
        "threshold_packets_per_second": threshold,
        "scope": "source_all_destinations",
    }
