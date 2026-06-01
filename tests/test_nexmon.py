import struct
import unittest

try:
    import numpy as np
except ModuleNotFoundError:  # pragma: no cover
    raise unittest.SkipTest("NumPy is not installed")

from receiving_csi.nexmon import NexmonCsiParser, NexmonCsiError, unpack_bcm4366c0


class NexmonParserTests(unittest.TestCase):
    def test_parse_extended_header_and_unpack(self):
        payload = _payload(header="extended", tones=64)
        sample = NexmonCsiParser().parse(payload)

        self.assertEqual(sample.header_layout, "extended")
        self.assertEqual(sample.rssi, -42)
        self.assertEqual(sample.frame_control, 0x88)
        self.assertEqual(sample.mac, "00:11:22:33:44:55")
        self.assertEqual(sample.seq, 123)
        self.assertEqual(sample.core, 1)
        self.assertEqual(sample.spatial_stream, 3)
        self.assertEqual(sample.bandwidth_mhz, 20)
        self.assertEqual(sample.csi.shape, (64,))
        self.assertEqual(sample.csi.dtype, np.complex64)

    def test_parse_compact_header(self):
        payload = _payload(header="compact", tones=128)
        sample = NexmonCsiParser().parse(payload)

        self.assertEqual(sample.header_layout, "compact")
        self.assertIsNone(sample.rssi)
        self.assertEqual(sample.bandwidth_mhz, 40)
        self.assertEqual(sample.csi.shape, (128,))

    def test_parse_legacy_four_byte_magic(self):
        payload = b"\x11\x11" + _payload(header="compact", tones=256)
        sample = NexmonCsiParser().parse(payload)

        self.assertEqual(sample.header_layout, "compact")
        self.assertEqual(sample.bandwidth_mhz, 80)
        self.assertEqual(sample.csi.shape, (256,))

    def test_rejects_bad_magic(self):
        with self.assertRaises(NexmonCsiError):
            NexmonCsiParser().parse(b"not csi")

    def test_unpack_autoscales_large_exponents(self):
        raw_word = (1 << 6) | 31
        raw_csi = struct.pack("<I", raw_word) + (b"\x00\x00\x00\x00" * 63)

        csi = unpack_bcm4366c0(raw_csi, 20)

        self.assertEqual(csi.dtype, np.complex64)
        self.assertEqual(csi[0].real, 0)
        self.assertEqual(csi[0].imag, 1024)

    def test_unpack_can_preserve_unscaled_magnitude(self):
        raw_word = (1 << 6) | 31
        raw_csi = struct.pack("<I", raw_word) + (b"\x00\x00\x00\x00" * 63)

        csi = unpack_bcm4366c0(raw_csi, 20, autoscale=False)

        self.assertGreater(abs(csi[0].imag), np.iinfo(np.int32).max)

    def test_unpack_uses_format_one_real_sign_bit(self):
        real_sign_mask = 1 << 29
        real_mantissa = 1 << (6 + 12)
        raw_word = real_sign_mask | real_mantissa
        raw_csi = struct.pack("<I", raw_word) + (b"\x00\x00\x00\x00" * 63)

        csi = unpack_bcm4366c0(raw_csi, 20)

        self.assertEqual(csi[0].real, -1024)
        self.assertEqual(csi[0].imag, 0)


def _payload(header, tones):
    raw_csi = b"\x00\x00\x00\x00" * tones
    if header == "extended":
        return (
            b"\x11\x11"
            + struct.pack("<bB", -42, 0x88)
            + bytes.fromhex("001122334455")
            + struct.pack("<HHHH", 123, 0x19, 0x1234, 0x4366)
            + raw_csi
        )
    return (
        b"\x11\x11"
        + bytes.fromhex("001122334455")
        + struct.pack("<HHHH", 123, 0x19, 0x1234, 0x4366)
        + raw_csi
    )
