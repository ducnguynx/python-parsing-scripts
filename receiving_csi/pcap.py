from __future__ import annotations

import io
import ipaddress
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

from .models import PacketInfo


class PcapError(ValueError):
    """Raised for unsupported or malformed pcap streams."""


@dataclass(frozen=True)
class PcapPacket:
    ts_sec: int
    ts_subsec: int
    captured_len: int
    wire_len: int
    data: bytes
    timestamp_resolution: str


class PcapStreamReader:
    """Incremental reader for classic libpcap streams."""

    _MAGICS = {
        b"\xd4\xc3\xb2\xa1": ("<", "us"),
        b"\xa1\xb2\xc3\xd4": (">", "us"),
        b"\x4d\x3c\xb2\xa1": ("<", "ns"),
        b"\xa1\xb2\x3c\x4d": (">", "ns"),
    }

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        self.endian: str | None = None
        self.timestamp_resolution = "us"
        self.linktype: int | None = None

    def __iter__(self) -> Iterator[PcapPacket]:
        self._read_global_header()
        assert self.endian is not None
        packet_header = struct.Struct(f"{self.endian}IIII")
        while True:
            header = self._read_exact(packet_header.size)
            if not header:
                return
            if len(header) < packet_header.size:
                raise PcapError("truncated pcap packet header")

            ts_sec, ts_subsec, caplen, wirelen = packet_header.unpack(header)
            data = self._read_exact(caplen)
            if len(data) < caplen:
                raise PcapError("truncated pcap packet data")
            yield PcapPacket(
                ts_sec=ts_sec,
                ts_subsec=ts_subsec,
                captured_len=caplen,
                wire_len=wirelen,
                data=data,
                timestamp_resolution=self.timestamp_resolution,
            )

    def _read_global_header(self) -> None:
        header = self._read_exact(24)
        if len(header) < 24:
            if _looks_like_tcpdump_text(header):
                raise PcapError("tcpdump text stream detected; use tcpdump -U -s 0 -w -")
            raise PcapError("truncated pcap global header")

        magic = header[:4]
        if magic not in self._MAGICS:
            if _looks_like_tcpdump_text(header):
                raise PcapError("tcpdump text stream detected; use tcpdump -U -s 0 -w -")
            raise PcapError(f"unsupported pcap magic: {magic.hex()}")

        self.endian, self.timestamp_resolution = self._MAGICS[magic]
        fields = struct.unpack(f"{self.endian}HHIIII", header[4:])
        self.linktype = fields[-1]

    def _read_exact(self, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            chunk = self.stream.read(size - len(chunks))
            if not chunk:
                break
            chunks.extend(chunk)
        return bytes(chunks)


def iter_udp_payloads(
    packets: Iterator[PcapPacket],
    linktype: int,
    *,
    dst_port: int = 5500,
    source_id: str | None = None,
) -> Iterator[tuple[bytes, PacketInfo]]:
    for packet in packets:
        try:
            ip_packet = _extract_ipv4(packet.data, linktype)
            payload, src_ip, dst_ip, src_port, found_dst_port = _extract_udp(ip_packet)
        except PcapError:
            continue
        if found_dst_port != dst_port:
            continue
        yield (
            payload,
            PacketInfo(
                timestamp_sec=packet.ts_sec,
                timestamp_subsec=packet.ts_subsec,
                timestamp_resolution=packet.timestamp_resolution,
                source_id=source_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=found_dst_port,
            ),
        )


def _extract_ipv4(frame: bytes, linktype: int) -> bytes:
    if linktype == 1:
        return _extract_ethernet_ipv4(frame)
    if linktype == 101:
        return _require_ipv4(frame)
    if linktype == 113:
        return _extract_linux_sll_ipv4(frame)
    if linktype == 276:
        return _extract_linux_sll2_ipv4(frame)
    if linktype == 0:
        return _extract_null_loopback_ipv4(frame)
    raise PcapError(f"unsupported pcap linktype: {linktype}")


def _extract_ethernet_ipv4(frame: bytes) -> bytes:
    if len(frame) < 14:
        raise PcapError("short ethernet frame")
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    while ethertype == 0x8100:
        if len(frame) < offset + 4:
            raise PcapError("short vlan frame")
        ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    if ethertype != 0x0800:
        raise PcapError("not IPv4")
    return _require_ipv4(frame[offset:])


def _extract_linux_sll_ipv4(frame: bytes) -> bytes:
    if len(frame) < 16:
        raise PcapError("short linux cooked frame")
    protocol = struct.unpack_from("!H", frame, 14)[0]
    if protocol != 0x0800:
        raise PcapError("not IPv4")
    return _require_ipv4(frame[16:])


def _extract_linux_sll2_ipv4(frame: bytes) -> bytes:
    if len(frame) < 20:
        raise PcapError("short linux cooked v2 frame")
    protocol = struct.unpack_from("!H", frame, 0)[0]
    if protocol != 0x0800:
        raise PcapError("not IPv4")
    return _require_ipv4(frame[20:])


def _extract_null_loopback_ipv4(frame: bytes) -> bytes:
    if len(frame) < 4:
        raise PcapError("short null loopback frame")
    family = struct.unpack_from("<I", frame, 0)[0]
    if family not in {2, 24, 28, 30}:
        raise PcapError("not IPv4")
    return _require_ipv4(frame[4:])


def _require_ipv4(packet: bytes) -> bytes:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        raise PcapError("not an IPv4 packet")
    return packet


def _extract_udp(ip_packet: bytes) -> tuple[bytes, str, str, int, int]:
    if len(ip_packet) < 20:
        raise PcapError("short IPv4 packet")
    ihl = (ip_packet[0] & 0x0F) * 4
    if ihl < 20 or len(ip_packet) < ihl + 8:
        raise PcapError("invalid IPv4 header length")
    protocol = ip_packet[9]
    if protocol != 17:
        raise PcapError("not UDP")

    total_len = struct.unpack_from("!H", ip_packet, 2)[0]
    if total_len == 0 or total_len > len(ip_packet):
        total_len = len(ip_packet)
    udp = ip_packet[ihl:total_len]
    if len(udp) < 8:
        raise PcapError("short UDP datagram")

    src_port, dst_port, udp_len, _checksum = struct.unpack_from("!HHHH", udp)
    if udp_len < 8 or udp_len > len(udp):
        raise PcapError("invalid UDP length")

    src_ip = str(ipaddress.IPv4Address(ip_packet[12:16]))
    dst_ip = str(ipaddress.IPv4Address(ip_packet[16:20]))
    return udp[8:udp_len], src_ip, dst_ip, src_port, dst_port


def _looks_like_tcpdump_text(data: bytes) -> bool:
    if not data:
        return False
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return False
    return "IP " in text or "listening on" in text or "tcpdump:" in text


def read_all_udp_payloads(data: bytes, *, dst_port: int = 5500) -> list[tuple[bytes, PacketInfo]]:
    stream = io.BytesIO(data)
    reader = PcapStreamReader(stream)
    iterator = iter(reader)
    packets = list(iterator)
    if reader.linktype is None:
        return []
    return list(iter_udp_payloads(iter(packets), reader.linktype, dst_port=dst_port))
