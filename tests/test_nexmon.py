import struct
import unittest

try:
    import numpy as np
except ModuleNotFoundError:  # pragma: no cover
    raise unittest.SkipTest("NumPy is not installed")

from receiving_csi.nexmon import NexmonCsiParser, unpack_bcm4366c0


class NexmonParserTests(unittest.TestCase):
    def test_parse_extended_header_and_unpack(self):
        payload = _payload(tones=64, sequence=123, fragment=2)
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

    def test_parse_sequence_control_uses_upper_12_bits(self):
        payload = _payload(tones=128, sequence=0x0FB7, fragment=0x2)
        sample = NexmonCsiParser().parse(payload)

        self.assertEqual(sample.seq, 0x0FB7)
        self.assertEqual(payload[10:12], bytes.fromhex("72fb"))

    def test_zeroes_compact_header_without_rssi_and_frame_control(self):
        raw_csi = b"\x00\x00\x00\x00" * 64
        compact_payload = (
            b"\x11\x11"
            + bytes.fromhex("001122334455")
            + struct.pack("<HHHH", 123 << 4, _css(core=1, spatial=3), 0x1234, 0x4366)
            + raw_csi
        )

        sample = NexmonCsiParser().parse(compact_payload)

        assert_zero_sample(self, sample)

    def test_parse_40mhz_header(self):
        payload = _payload(tones=128)
        sample = NexmonCsiParser().parse(payload)

        self.assertEqual(sample.header_layout, "extended")
        self.assertEqual(sample.rssi, -42)
        self.assertEqual(sample.bandwidth_mhz, 40)
        self.assertEqual(sample.csi.shape, (128,))

    def test_parse_80mhz_header(self):
        payload = _payload(tones=256)
        sample = NexmonCsiParser().parse(payload)

        self.assertEqual(sample.header_layout, "extended")
        self.assertEqual(sample.bandwidth_mhz, 80)
        self.assertEqual(sample.csi.shape, (256,))

    def test_zeroes_bad_magic(self):
        sample = NexmonCsiParser().parse(b"not csi")

        assert_zero_sample(self, sample)

    def test_zeroes_legacy_four_byte_magic_prefix(self):
        payload = b"\x11\x11" + _payload(tones=64)
        sample = NexmonCsiParser().parse(payload)

        assert_zero_sample(self, sample)

    def test_zeroes_unsupported_csi_length(self):
        payload = _payload(tones=63)
        sample = NexmonCsiParser().parse(payload)

        assert_zero_sample(self, sample)

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


def _payload(tones, sequence=123, fragment=0):
    raw_csi = b"\x00\x00\x00\x00" * tones
    sequence_control = (sequence << 4) | fragment
    return (
        b"\x11\x11"
        + struct.pack("<bB", -42, 0x88)
        + bytes.fromhex("001122334455")
        + struct.pack("<HHHH", sequence_control, _css(core=1, spatial=3), 0x1234, 0x4366)
        + raw_csi
    )


def _css(core, spatial):
    return (core << 8) | spatial


def assert_zero_sample(testcase, sample):
    testcase.assertEqual(sample.header_layout, "invalid")
    testcase.assertEqual(sample.magic, 0)
    testcase.assertEqual(sample.mac, "00:00:00:00:00:00")
    testcase.assertEqual(sample.seq, 0)
    testcase.assertEqual(sample.core, 0)
    testcase.assertEqual(sample.spatial_stream, 0)
    testcase.assertEqual(sample.chanspec, 0)
    testcase.assertEqual(sample.chip_version, 0)
    testcase.assertEqual(sample.bandwidth_mhz, 0)
    testcase.assertEqual(sample.css, 0)
    testcase.assertEqual(sample.rssi, 0)
    testcase.assertEqual(sample.frame_control, 0)
    testcase.assertEqual(sample.csi.shape, (0,))
    testcase.assertEqual(sample.csi.dtype, np.complex64)
