"""High SYN-without-ACK activity, with observational handshake evidence."""


def detect(syn_packets: int, pending_connections: int, threshold: int) -> dict | None:
    if syn_packets < threshold:
        return None
    return {
        "syn_packets": syn_packets,
        "threshold": threshold,
        "incomplete_connections": pending_connections,
        "scope": "source_destination",
        "interpretation": "High SYN activity; missing handshakes alone do not prove flooding.",
    }
