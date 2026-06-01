from __future__ import annotations

import struct
from dataclasses import replace

import numpy as np

from .models import CsiSample, PacketInfo


class NexmonCsiError(ValueError):
    """Raised when a UDP payload is not a supported NexmonCSI sample."""


_TONES_BY_CSI_BYTES = {
    64 * 4: (20, 64),
    128 * 4: (40, 128),
    256 * 4: (80, 256),
}


class NexmonCsiParser:
    """Pure Python/NumPy parser for NexmonCSI UDP payloads.

    The first supported chip target is bcm4366c0, used by the Asus RT-AC86U.
    That chip stores each complex CSI value in Nexmon's packed float-like
    representation. The unpacking logic follows Nexmon's `unpack_float.c`
    format 1 configuration: nbits=10, nman=12, nexp=6.
    """

    def __init__(self, chip: str = "4366c0") -> None:
        if chip not in {"4366c0", "rt-ac86u", "rtac86u"}:
            raise ValueError(f"unsupported Nexmon chip for pure parser: {chip}")
        self.chip = chip

    def parse(self, payload: bytes, packet: PacketInfo | None = None) -> CsiSample:
        if len(payload) < 16:
            raise NexmonCsiError("payload too short for NexmonCSI header")

        offsets = _detect_magic_offsets(payload)
        if not offsets:
            raise NexmonCsiError("missing NexmonCSI magic 0x1111")

        packet_info = packet or PacketInfo()
        for offset in offsets:
            try:
                return self._parse_header(payload, offset, packet_info)
            except NexmonCsiError:
                continue
        raise NexmonCsiError("payload length does not match known NexmonCSI layouts")

    def _parse_header(
        self,
        payload: bytes,
        offset: int,
        packet: PacketInfo,
    ) -> CsiSample:
        candidates = []
        for layout in (_parse_extended_header, _parse_compact_header):
            try:
                candidates.append(layout(payload, offset, packet))
            except NexmonCsiError:
                continue

        if not candidates:
            raise NexmonCsiError("payload length does not match 20/40/80 MHz CSI")

        sample, raw_csi = candidates[0]
        return replace(sample, csi=unpack_bcm4366c0(raw_csi, sample.bandwidth_mhz))


def parse_nexmon_payload(
    payload: bytes,
    packet: PacketInfo | None = None,
    chip: str = "4366c0",
) -> CsiSample:
    return NexmonCsiParser(chip=chip).parse(payload, packet)


def unpack_bcm4366c0(raw_csi: bytes, bandwidth_mhz: int) -> np.ndarray:
    expected_bytes = {20: 64 * 4, 40: 128 * 4, 80: 256 * 4}.get(bandwidth_mhz)
    if expected_bytes is None:
        raise NexmonCsiError(f"unsupported bandwidth: {bandwidth_mhz}")
    if len(raw_csi) != expected_bytes:
        raise NexmonCsiError(
            f"expected {expected_bytes} CSI bytes for {bandwidth_mhz} MHz, "
            f"got {len(raw_csi)}"
        )

    packed = np.frombuffer(raw_csi, dtype="<u4")
    iq = _unpack_float_acphy(packed, nbits=10, nman=12, nexp=6)
    return (iq[:, 0].astype(np.float32) + 1j * iq[:, 1].astype(np.float32)).astype(
        np.complex64
    )


def _unpack_float_acphy(
    packed: np.ndarray,
    *,
    nbits: int,
    nman: int,
    nexp: int,
) -> np.ndarray:
    iq_mask = (1 << (nman - 1)) - 1
    e_mask = (1 << nexp) - 1
    e_p = 1 << (nexp - 1)
    e_zero = -nman
    shft = nbits

    out = np.empty((packed.size, 2), dtype=np.int32)
    for index, word in enumerate(packed.astype(np.uint32, copy=False)):
        value = int(word)
        real = (value >> (nexp + nman)) & iq_mask
        imag = (value >> nexp) & iq_mask
        exponent = value & e_mask
        if exponent >= e_p:
            exponent -= e_p << 1

        real_sign = -1 if value & (1 << 31) else 1
        imag_sign = -1 if value & (1 << (nexp + nman - 1)) else 1
        out[index, 0] = real_sign * _shift_mantissa(real, exponent + shft, e_zero)
        out[index, 1] = imag_sign * _shift_mantissa(imag, exponent + shft, e_zero)
    return out


def _shift_mantissa(value: int, exponent: int, e_zero: int) -> int:
    if exponent < e_zero:
        return 0
    if exponent < 0:
        return value >> -exponent
    return value << exponent


def _detect_magic_offsets(payload: bytes) -> tuple[int, ...]:
    if payload[:4] == b"\x11\x11\x11\x11":
        return (2, 0)
    if payload[:2] == b"\x11\x11":
        return (0,)
    return ()


def _parse_extended_header(
    payload: bytes,
    offset: int,
    packet: PacketInfo,
) -> tuple[CsiSample, bytes]:
    header_len = offset + 18
    if len(payload) < header_len:
        raise NexmonCsiError("payload too short for extended NexmonCSI header")
    csi_bytes = payload[header_len:]
    bandwidth, _tones = _bandwidth_from_length(csi_bytes)

    rssi = struct.unpack_from("<b", payload, offset + 2)[0]
    frame_control = payload[offset + 3]
    mac = _format_mac(payload[offset + 4 : offset + 10])
    seq, css, chanspec, chip_version = struct.unpack_from("<HHHH", payload, offset + 10)

    return (
        CsiSample(
            mac=mac,
            seq=seq,
            core=css & 0x7,
            spatial_stream=(css >> 3) & 0x7,
            chanspec=chanspec,
            chip_version=chip_version,
            bandwidth_mhz=bandwidth,
            csi=np.empty(0, dtype=np.complex64),
            packet=packet,
            rssi=rssi,
            frame_control=frame_control,
            header_layout="extended",
        ),
        csi_bytes,
    )


def _parse_compact_header(
    payload: bytes,
    offset: int,
    packet: PacketInfo,
) -> tuple[CsiSample, bytes]:
    header_len = offset + 16
    if len(payload) < header_len:
        raise NexmonCsiError("payload too short for compact NexmonCSI header")
    csi_bytes = payload[header_len:]
    bandwidth, _tones = _bandwidth_from_length(csi_bytes)

    mac = _format_mac(payload[offset + 2 : offset + 8])
    seq, css, chanspec, chip_version = struct.unpack_from("<HHHH", payload, offset + 8)

    return (
        CsiSample(
            mac=mac,
            seq=seq,
            core=css & 0x7,
            spatial_stream=(css >> 3) & 0x7,
            chanspec=chanspec,
            chip_version=chip_version,
            bandwidth_mhz=bandwidth,
            csi=np.empty(0, dtype=np.complex64),
            packet=packet,
            header_layout="compact",
        ),
        csi_bytes,
    )


def _bandwidth_from_length(csi_bytes: bytes) -> tuple[int, int]:
    try:
        return _TONES_BY_CSI_BYTES[len(csi_bytes)]
    except KeyError as exc:
        raise NexmonCsiError(f"unsupported CSI byte length: {len(csi_bytes)}") from exc


def _format_mac(raw: bytes) -> str:
    if len(raw) != 6:
        raise NexmonCsiError("invalid MAC length")
    return ":".join(f"{byte:02x}" for byte in raw)
