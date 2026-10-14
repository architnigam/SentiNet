"""Write a synthetic scan/SYN/burst PCAP; no packets are transmitted."""

import argparse
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import PcapWriter


def create_demo(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with PcapWriter(str(path), linktype=1, sync=True) as writer:
        for index in range(2000):
            packet = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
                      IP(src="198.51.100.10", dst="198.51.100.20") /
                      TCP(sport=40000 + index, dport=1000 + index % 20, flags="S"))
            packet.time = 1_700_000_000 + index / 1000
            writer.write(packet)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("data/pcaps/threat_demo.pcap"))
    create_demo(parser.parse_args().output)
