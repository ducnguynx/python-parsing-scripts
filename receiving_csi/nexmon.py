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
        packet_info = packet or PacketInfo()
        try:
            return self._parse_header(payload, packet_info)
        except NexmonCsiError:
            return _zero_sample(packet_info)

    def _parse_header(
        self,
        payload: bytes,
        packet: PacketInfo,
    ) -> CsiSample:
        sample, raw_csi = _parse_header(payload, packet)
        return replace(sample, csi=unpack_bcm4366c0(raw_csi, sample.bandwidth_mhz))


def parse_nexmon_payload(
    payload: bytes,
    packet: PacketInfo | None = None,
    chip: str = "4366c0",
) -> CsiSample:
    return NexmonCsiParser(chip=chip).parse(payload, packet)


def unpack_bcm4366c0(
    raw_csi: bytes,
    bandwidth_mhz: int,
    *,
    autoscale: bool = True,
) -> np.ndarray:
    expected_bytes = {20: 64 * 4, 40: 128 * 4, 80: 256 * 4}.get(bandwidth_mhz)
    if expected_bytes is None:
        raise NexmonCsiError(f"unsupported bandwidth: {bandwidth_mhz}")
    if len(raw_csi) != expected_bytes:
        raise NexmonCsiError(
            f"expected {expected_bytes} CSI bytes for {bandwidth_mhz} MHz, "
            f"got {len(raw_csi)}"
        )

    packed = np.frombuffer(raw_csi, dtype="<u4")
    iq = _unpack_float_acphy(packed, nbits=10, nman=12, nexp=6, autoscale=autoscale)
    return (iq[:, 0].astype(np.float32) + 1j * iq[:, 1].astype(np.float32)).astype(
        np.complex64
    )


def _unpack_float_acphy(
    packed: np.ndarray,
    *,
    nbits: int,
    nman: int,
    nexp: int,
    autoscale: bool,
) -> np.ndarray:
    iq_mask = (1 << (nman - 1)) - 1
    e_mask = (1 << nexp) - 1
    e_p = 1 << (nexp - 1)
    real_sign_mask = 1 << (nexp + 2 * nman - 1)
    imag_sign_mask = real_sign_mask >> nman
    e_zero = -nman

    mantissas = np.empty((packed.size, 2), dtype=np.int64)
    exponents = np.empty(packed.size, dtype=np.int16)
    maxbit = -e_p
    signs = np.ones((packed.size, 2), dtype=np.int8)

    for index, word in enumerate(packed.astype(np.uint32, copy=False)):
        value = int(word)
        real = (value >> (nexp + nman)) & iq_mask
        imag = (value >> nexp) & iq_mask
        exponent = value & e_mask
        if exponent >= e_p:
            exponent -= e_p << 1

        mantissas[index, 0] = real
        mantissas[index, 1] = imag
        exponents[index] = exponent
        if value & real_sign_mask:
            signs[index, 0] = -1
        if value & imag_sign_mask:
            signs[index, 1] = -1

        mantissa_bits = (real | imag).bit_length() - 1
        if autoscale and mantissa_bits >= 0:
            maxbit = max(maxbit, exponent + mantissa_bits)

    shft = nbits - maxbit if autoscale else nbits
    out = np.empty((packed.size, 2), dtype=np.int64)
    for index, exponent in enumerate(exponents):
        scaled_exponent = int(exponent) + shft
        out[index, 0] = int(signs[index, 0]) * _shift_mantissa(
            int(mantissas[index, 0]),
            scaled_exponent,
            e_zero,
        )
        out[index, 1] = int(signs[index, 1]) * _shift_mantissa(
            int(mantissas[index, 1]),
            scaled_exponent,
            e_zero,
        )
    return out


def _shift_mantissa(value: int, exponent: int, e_zero: int) -> int:
    if exponent < e_zero:
        return 0
    if exponent < 0:
        return value >> -exponent
    return value << exponent


def _parse_header(
    payload: bytes,
    packet: PacketInfo,
) -> tuple[CsiSample, bytes]:
    offset = 0
    header_len = 18
    if len(payload) < header_len:
        raise NexmonCsiError("payload too short for NexmonCSI header")
    if payload[:2] != b"\x11\x11":
        raise NexmonCsiError("missing NexmonCSI magic 0x1111")
    csi_bytes = payload[header_len:]
    bandwidth, _tones = _bandwidth_from_length(csi_bytes)

    rssi = struct.unpack_from("<b", payload, offset + 2)[0]
    frame_control = payload[offset + 3]
    mac = _format_mac(payload[offset + 4 : offset + 10])
    sequence_control, css, chanspec, chip_version = struct.unpack_from(
        "<HHHH",
        payload,
        offset + 10,
    )

    return (
        CsiSample(
            mac=mac,
            seq=_sequence_number(sequence_control),
            core=_core_index(css),
            spatial_stream=_spatial_stream_index(css),
            chanspec=chanspec,
            chip_version=chip_version,
            bandwidth_mhz=bandwidth,
            csi=np.empty(0, dtype=np.complex64),
            css=css,
            packet=packet,
            rssi=rssi,
            frame_control=frame_control,
            header_layout="extended",
        ),
        csi_bytes,
    )


def _zero_sample(packet: PacketInfo) -> CsiSample:
    return CsiSample(
        mac="00:00:00:00:00:00",
        seq=0,
        core=0,
        spatial_stream=0,
        chanspec=0,
        chip_version=0,
        bandwidth_mhz=0,
        csi=np.zeros(0, dtype=np.complex64),
        css=0,
        packet=packet,
        magic=0,
        rssi=0,
        frame_control=0,
        header_layout="invalid",
    )


def _sequence_number(sequence_control: int) -> int:
    return sequence_control >> 4


def _core_index(css: int) -> int:
    return (css >> 8) & 0x7


def _spatial_stream_index(css: int) -> int:
    return css & 0x7



def _bandwidth_from_length(csi_bytes: bytes) -> tuple[int, int]:
    try:
        return _TONES_BY_CSI_BYTES[len(csi_bytes)]
    except KeyError as exc:
        raise NexmonCsiError(f"unsupported CSI byte length: {len(csi_bytes)}") from exc


def _format_mac(raw: bytes) -> str:
    if len(raw) != 6:
        raise NexmonCsiError("invalid MAC length")
    return ":".join(f"{byte:02x}" for byte in raw)
