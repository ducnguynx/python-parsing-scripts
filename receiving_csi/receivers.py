from __future__ import annotations

import socket
from collections.abc import Callable
from typing import BinaryIO

from .models import CsiSample, PacketInfo
from .nexmon import NexmonCsiError, NexmonCsiParser
from .pcap import PcapStreamReader, iter_udp_payloads

ErrorCallback = Callable[[Exception], None]
SampleCallback = Callable[[CsiSample], None]


def read_pcap_stream(
    stream: BinaryIO,
    callback: SampleCallback,
    *,
    port: int = 5500,
    error_callback: ErrorCallback | None = None,
    parser: NexmonCsiParser | None = None,
) -> None:
    parser = parser or NexmonCsiParser()
    reader = PcapStreamReader(stream)
    packets = iter(reader)
    try:
        first_packet = next(packets)
    except StopIteration:
        return
    except Exception as exc:
        _report_error(exc, error_callback)
        return

    if reader.linktype is None:
        return

    def packet_iter():
        yield first_packet
        yield from packets

    for payload, packet_info in iter_udp_payloads(packet_iter(), reader.linktype, dst_port=port):
        try:
            callback(parser.parse(payload, packet_info))
        except NexmonCsiError as exc:
            _report_error(exc, error_callback)


def listen_udp(
    host: str,
    port: int,
    callback: SampleCallback,
    *,
    error_callback: ErrorCallback | None = None,
    parser: NexmonCsiParser | None = None,
    buffer_size: int = 4096,
) -> None:
    parser = parser or NexmonCsiParser()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        while True:
            data, address = sock.recvfrom(buffer_size)
            packet = PacketInfo(src_ip=address[0], src_port=address[1], dst_port=port)
            try:
                callback(parser.parse(data, packet))
            except NexmonCsiError as exc:
                _report_error(exc, error_callback)


def _report_error(exc: Exception, error_callback: ErrorCallback | None) -> None:
    if error_callback is not None:
        error_callback(exc)
