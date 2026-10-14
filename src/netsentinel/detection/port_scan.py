"""Port-scan indicator: unique (protocol, destination port) pairs per IP pair."""

from itertools import islice
from typing import Mapping


def detect(ports: Mapping[tuple[str, int], int], threshold: int) -> dict | None:
    if len(ports) < threshold:
        return None
    return {
        "unique_destination_ports": len(ports),
        "threshold": threshold,
        "sample_ports": [{"protocol": protocol, "port": port}
                         for protocol, port in islice(ports, 20)],
        "scope": "source_destination",
    }
