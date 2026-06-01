from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PacketInfo:
    """Network and capture metadata around a UDP payload."""

    timestamp_sec: int | None = None
    timestamp_subsec: int | None = None
    timestamp_resolution: str = "us"
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None


@dataclass(frozen=True)
class CsiSample:
    """One parsed NexmonCSI UDP payload."""

    mac: str
    seq: int
    core: int
    spatial_stream: int
    chanspec: int
    chip_version: int
    bandwidth_mhz: int
    csi: Any
    packet: PacketInfo = PacketInfo()
    magic: int = 0x1111
    rssi: int | None = None
    frame_control: int | None = None
    header_layout: str = "compact"
