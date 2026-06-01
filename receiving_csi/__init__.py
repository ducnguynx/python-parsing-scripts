"""Live NexmonCSI capture helpers."""

from .models import CsiSample, PacketInfo

__all__ = [
    "CsiSample",
    "PacketInfo",
    "NexmonCsiParser",
    "parse_nexmon_payload",
    "listen_udp",
    "read_pcap_stream",
]


def __getattr__(name):
    if name in {"NexmonCsiParser", "parse_nexmon_payload"}:
        from .nexmon import NexmonCsiParser, parse_nexmon_payload

        return {
            "NexmonCsiParser": NexmonCsiParser,
            "parse_nexmon_payload": parse_nexmon_payload,
        }[name]
    if name in {"listen_udp", "read_pcap_stream"}:
        from .receivers import listen_udp, read_pcap_stream

        return {"listen_udp": listen_udp, "read_pcap_stream": read_pcap_stream}[name]
    raise AttributeError(name)
