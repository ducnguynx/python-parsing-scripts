import io
import struct
import unittest

from receiving_csi.pcap import PcapError, PcapStreamReader, iter_udp_payloads

try:
    import numpy as np
except ModuleNotFoundError:  # pragma: no cover
    np = None


class PcapTests(unittest.TestCase):
    def test_extract_udp_payload_from_chunky_stream(self):
        payload = b"csi-payload"
        pcap = _pcap(_ethernet_ipv4_udp(payload))
        reader = PcapStreamReader(_ChunkyBytesIO(pcap, chunk_size=3))
        packets = iter(reader)
        first = next(packets)

        extracted = list(iter_udp_payloads(iter([first]), reader.linktype, dst_port=5500))

        self.assertEqual(len(extracted), 1)
        udp_payload, info = extracted[0]
        self.assertEqual(udp_payload, payload)
        self.assertEqual(info.src_ip, "10.10.10.10")
        self.assertEqual(info.dst_ip, "255.255.255.255")
        self.assertEqual(info.dst_port, 5500)

    def test_text_tcpdump_stream_is_rejected(self):
        stream = io.BytesIO(b"listening on wlan0, link-type EN10MB\n")
        with self.assertRaises(PcapError):
            list(PcapStreamReader(stream))

    @unittest.skipIf(np is None, "NumPy is not installed")
    def test_pcap_stream_receiver_calls_callback_with_sample(self):
        from receiving_csi.receivers import read_pcap_stream

        csi_payload = (
            b"\x11\x11"
            + bytes.fromhex("001122334455")
            + struct.pack("<HHHH", 7, 0x09, 0x1234, 0x4366)
            + (b"\x00\x00\x00\x00" * 64)
        )
        samples = []

        read_pcap_stream(io.BytesIO(_pcap(_ethernet_ipv4_udp(csi_payload))), samples.append)

        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].seq, 7)
        self.assertEqual(samples[0].core, 1)
        self.assertEqual(samples[0].spatial_stream, 1)


class _ChunkyBytesIO(io.BytesIO):
    def __init__(self, data, chunk_size):
        super().__init__(data)
        self.chunk_size = chunk_size

    def read(self, size=-1):
        if size < 0:
            size = self.chunk_size
        return super().read(min(size, self.chunk_size))


def _pcap(frame):
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packet_header = struct.pack("<IIII", 1, 2, len(frame), len(frame))
    return global_header + packet_header + frame


def _ethernet_ipv4_udp(payload):
    ethernet = b"\xff" * 6 + b"\x00\x11\x22\x33\x44\x55" + struct.pack("!H", 0x0800)
    udp_len = 8 + len(payload)
    total_len = 20 + udp_len
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0,
        0,
        64,
        17,
        0,
        bytes([10, 10, 10, 10]),
        bytes([255, 255, 255, 255]),
    )
    udp = struct.pack("!HHHH", 5500, 5500, udp_len, 0)
    return ethernet + ipv4 + udp + payload
