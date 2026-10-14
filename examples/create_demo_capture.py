"""Create synthetic packets in a file; never transmit network traffic."""

import argparse
from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap


def create_demo(path: Path) -> None:
    ethernet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    ipv4 = IP(src="192.0.2.10", dst="192.0.2.20")
    packets = [
        ethernet / ipv4 / TCP(sport=50000, dport=443, flags="S"),
        ethernet / IP(src="192.0.2.20", dst="192.0.2.10") / TCP(sport=443, dport=50000, flags="SA"),
        ethernet / ipv4 / TCP(sport=50000, dport=443, flags="A"),
        ethernet / ipv4 / UDP(sport=50001, dport=53) / Raw(b"synthetic DNS payload"),
        ethernet / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=50002, dport=5353),
        ethernet / ARP(psrc="192.0.2.10", pdst="192.0.2.20",
                       hwsrc="02:00:00:00:00:01", hwdst="00:00:00:00:00:00"),
        ethernet / ipv4 / ICMP(),
        ethernet / IP(src="192.0.2.10", dst="192.0.2.20", flags="MF") / UDP(sport=50003, dport=53),
    ]
    for index, packet in enumerate(packets):
        packet.time = 1_700_000_000 + index * 0.25
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), packets)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("data/pcaps/demo.pcap"))
    create_demo(parser.parse_args().output)
