"""Synchronous live capture: one socket, bounded polling, no background sniffer."""

from dataclasses import dataclass
import math
import sys
import time
from threading import Event

from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.error import Scapy_Exception
from scapy.sendrecv import sniff
from scapy.layers.l2 import Ether  # noqa: F401 - register link decoders

from .capture import MAX_PACKET_BYTES
from .errors import CaptureError
from .models import CapturedPacket


def interface_catalog() -> dict:
    try:
        interfaces = []
        for interface in conf.ifaces.values():
            if interface.dummy:
                continue
            interfaces.append({"id": interface.network_name, "name": interface.name,
                               "description": interface.description,
                               "addresses": [ip for group in interface.ips.values() for ip in group]})
        return {"provider_available": bool(conf.use_pcap) if WINDOWS else True,
                "platform": "Windows" if WINDOWS else "Unix", "interfaces": interfaces}
    except (OSError, Scapy_Exception) as exc:
        raise CaptureError(f"Cannot enumerate interfaces: {exc}") from exc


def resolve_interface(selector: str) -> str:
    if not isinstance(selector, str) or not selector.strip():
        raise CaptureError("Select an interface from --list-interfaces.")
    catalog = interface_catalog()
    if not catalog["provider_available"]:
        raise CaptureError("Npcap/libpcap is unavailable. Install Npcap on Windows, then restart the terminal; offline PCAP analysis still works.")
    exact = [item["id"] for item in catalog["interfaces"] if selector == item["id"]]
    matches = exact or [item["id"] for item in catalog["interfaces"]
                        if selector in (item["name"], item["description"])]
    unique = list(dict.fromkeys(matches))
    if len(unique) != 1:
        raise CaptureError("Interface is unavailable or ambiguous; use its exact ID from --list-interfaces.")
    return unique[0]


def packet_to_frame(packet) -> CapturedPacket:
    data = bytes(packet)
    original_length = len(data)
    if len(data) > MAX_PACKET_BYTES:
        data = data[:MAX_PACKET_BYTES]
    wire = getattr(packet, "wirelen", None)
    try:
        wire = original_length if wire is None else int(wire)
        timestamp = None if packet.time is None else float(packet.time)
    except (ValueError, TypeError, OverflowError) as exc:
        raise CaptureError(f"Invalid live packet metadata: {exc}") from exc
    if wire < original_length:
        raise CaptureError("Live packet wire length is shorter than its captured data.")
    link = conf.l2types.layer2num.get(type(packet), -1)
    return CapturedPacket(data, timestamp, wire, link)


@dataclass(frozen=True)
class LiveResult:
    packets: int
    reason: str


def capture_live(interface: str, on_packet, *, on_tick=lambda: None,
                 stop_event: Event | None = None, packet_limit: int | None = None,
                 duration: float | None = None, poll_interval: float = 1.0) -> LiveResult:
    """Deliver packets on the calling thread, releasing the socket on all exits.

    Idle stop latency is at most the polling interval plus processing time.
    Scapy never retains packets (store=False). No packets are transmitted.
    """
    if packet_limit is not None and (type(packet_limit) is not int or packet_limit < 1):
        raise ValueError("packet_limit must be positive")
    for name, value in (("duration", duration), ("poll_interval", poll_interval)):
        try:
            valid = value is None or (type(value) in (int, float) and math.isfinite(value) and value > 0)
        except OverflowError:
            valid = False
        if not valid:
            raise ValueError(f"{name} must be finite and positive")
    if poll_interval is None or poll_interval > 5:
        raise ValueError("poll_interval must be at most 5 seconds")
    stop_event = stop_event or Event()
    if stop_event.is_set():
        return LiveResult(0, "stopped")
    resolved = resolve_interface(interface)
    count = 0
    started = time.monotonic()
    socket = None
    failures = []

    def deliver(packet):
        nonlocal count
        if failures or stop_event.is_set() or (packet_limit is not None and count >= packet_limit):
            return
        try:
            on_packet(packet_to_frame(packet))
            count += 1
        except Exception as exc:
            # Scapy may swallow callback exceptions; return normally and rethrow
            # after sniff stops so detector/log failures cannot disappear.
            failures.append(exc)

    try:
        socket = conf.L2listen(iface=resolved)
        while not stop_event.is_set():
            remaining = None if duration is None else duration - (time.monotonic() - started)
            if remaining is not None and remaining <= 0:
                return LiveResult(count, "duration")
            timeout = poll_interval if remaining is None else min(poll_interval, remaining)
            sniff(opened_socket=socket, store=False, prn=deliver, timeout=timeout,
                  count=0 if packet_limit is None else packet_limit - count,
                  stop_filter=lambda packet: stop_event.is_set() or bool(failures), chainCC=True)
            if failures:
                raise failures[0]
            if getattr(socket, "closed", False):
                raise CaptureError("Capture socket closed unexpectedly; monitoring stopped.")
            on_tick()
            if packet_limit is not None and count >= packet_limit:
                return LiveResult(count, "packet_limit")
        return LiveResult(count, "stopped")
    except (OSError, Scapy_Exception, RuntimeError) as exc:
        raise CaptureError(f"Live capture failed on '{interface}': {exc}. Check the capture provider and permissions.") from exc
    finally:
        if socket is not None:
            active_error = sys.exc_info()[0] is not None
            try:
                socket.close()
            except (OSError, Scapy_Exception) as exc:
                if not active_error:
                    raise CaptureError(f"Capture socket cleanup failed: {exc}") from exc
