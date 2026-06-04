import io
import json
import os
import struct
import tempfile
import threading
import unittest
from pathlib import Path

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

        csi_payload = _csi_payload(sequence=7, core=1, spatial=1)
        samples = []

        read_pcap_stream(io.BytesIO(_pcap(_ethernet_ipv4_udp(csi_payload))), samples.append)

        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].seq, 7)
        self.assertEqual(samples[0].core, 1)
        self.assertEqual(samples[0].spatial_stream, 1)

    @unittest.skipIf(np is None, "NumPy is not installed")
    def test_pcap_streams_receiver_keeps_sources_separate(self):
        from receiving_csi.receivers import read_pcap_streams

        streams = {
            "router-a": io.BytesIO(_pcap(_ethernet_ipv4_udp(_csi_payload(sequence=1, core=0)))),
            "router-b": io.BytesIO(_pcap(_ethernet_ipv4_udp(_csi_payload(sequence=2, core=1)))),
        }
        samples = []

        read_pcap_streams(streams, samples.append)

        by_source = {sample.packet.source_id: sample for sample in samples}
        self.assertEqual(set(by_source), {"router-a", "router-b"})
        self.assertEqual(by_source["router-a"].seq, 1)
        self.assertEqual(by_source["router-a"].core, 0)
        self.assertEqual(by_source["router-b"].seq, 2)
        self.assertEqual(by_source["router-b"].core, 1)

    @unittest.skipIf(np is None, "NumPy is not installed")
    def test_read_pcap_stream_singular_supports_parallel_threads(self):
        from receiving_csi.receivers import read_pcap_stream

        streams = [
            io.BytesIO(_pcap(_ethernet_ipv4_udp(_csi_payload(sequence=21, core=0)))),
            io.BytesIO(_pcap(_ethernet_ipv4_udp(_csi_payload(sequence=22, core=1)))),
        ]
        samples = []
        errors = []
        lock = threading.Lock()

        def callback(sample):
            with lock:
                samples.append(sample)

        def error_callback(exc):
            with lock:
                errors.append(exc)

        threads = [
            threading.Thread(
                target=read_pcap_stream,
                kwargs={
                    "stream": stream,
                    "callback": callback,
                    "error_callback": error_callback,
                    "source_id": f"router-{index}",
                },
            )
            for index, stream in enumerate(streams)
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=1)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        by_source = {sample.packet.source_id: sample for sample in samples}
        self.assertEqual(set(by_source), {"router-0", "router-1"})
        self.assertEqual(by_source["router-0"].seq, 21)
        self.assertEqual(by_source["router-0"].core, 0)
        self.assertEqual(by_source["router-1"].seq, 22)
        self.assertEqual(by_source["router-1"].core, 1)

    @unittest.skipIf(np is None, "NumPy is not installed")
    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are not supported")
    def test_read_pcap_stream_singular_supports_parallel_named_pipes(self):
        from receiving_csi.receivers import read_pcap_stream

        with tempfile.TemporaryDirectory() as directory:
            fifo_a = os.path.join(directory, "router-a.pcap")
            fifo_b = os.path.join(directory, "router-b.pcap")
            os.mkfifo(fifo_a)
            os.mkfifo(fifo_b)

            writers = [
                _write_fifo_later(
                    fifo_a,
                    _pcap(_ethernet_ipv4_udp(_csi_payload(sequence=31, core=0))),
                ),
                _write_fifo_later(
                    fifo_b,
                    _pcap(_ethernet_ipv4_udp(_csi_payload(sequence=32, core=1))),
                ),
            ]

            with open(fifo_a, "rb") as stream_a, open(fifo_b, "rb") as stream_b:
                samples = []
                errors = []
                lock = threading.Lock()

                def callback(sample):
                    with lock:
                        samples.append(sample)

                def error_callback(exc):
                    with lock:
                        errors.append(exc)

                threads = [
                    threading.Thread(
                        target=read_pcap_stream,
                        kwargs={
                            "stream": stream_a,
                            "callback": callback,
                            "error_callback": error_callback,
                            "source_id": "router-a",
                        },
                    ),
                    threading.Thread(
                        target=read_pcap_stream,
                        kwargs={
                            "stream": stream_b,
                            "callback": callback,
                            "error_callback": error_callback,
                            "source_id": "router-b",
                        },
                    ),
                ]

                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=1)

            for writer in writers:
                writer.join(timeout=1)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        by_source = {sample.packet.source_id: sample for sample in samples}
        self.assertEqual(set(by_source), {"router-a", "router-b"})
        self.assertEqual(by_source["router-a"].seq, 31)
        self.assertEqual(by_source["router-a"].core, 0)
        self.assertEqual(by_source["router-b"].seq, 32)
        self.assertEqual(by_source["router-b"].core, 1)

    @unittest.skipIf(np is None, "NumPy is not installed")
    def test_json_writer_callback_is_safe_for_parallel_sources(self):
        import importlib.util

        module_path = os.path.join(os.path.dirname(__file__), "..", "test-json.py")
        spec = importlib.util.spec_from_file_location("test_json_script", module_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as directory:
            writer = module.MultiCoreJsonSampleWriter(
                output_dir=Path(directory) / "json",
                limit=2,
                expected_cores=2,
            )
            samples = [
                _sample(source="router-a", sequence=1, core=0),
                _sample(source="router-b", sequence=1, core=0),
                _sample(source="router-a", sequence=1, core=1),
                _sample(source="router-b", sequence=1, core=1),
            ]

            def write(sample):
                try:
                    writer(sample)
                except module.StopCapture:
                    pass

            threads = [threading.Thread(target=write, args=(sample,)) for sample in samples]

            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=1)

            output_dir = os.path.join(directory, "json")
            rows = []
            for name in sorted(os.listdir(output_dir)):
                with open(os.path.join(output_dir, name), encoding="utf-8") as stream:
                    rows.append(json.loads(stream.read()))

        self.assertEqual(writer.count, 2)
        self.assertEqual({row["source_id"] for row in rows}, {"router-a", "router-b"})
        for row in rows:
            self.assertTrue(row["csi"]["c0"])
            self.assertTrue(row["csi"]["c1"])

    @unittest.skipIf(np is None, "NumPy is not installed")
    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are not supported")
    def test_pcap_streams_receiver_reads_multiple_named_pipes(self):
        from receiving_csi.receivers import read_pcap_streams

        with tempfile.TemporaryDirectory() as directory:
            fifo_a = os.path.join(directory, "router-a.pcap")
            fifo_b = os.path.join(directory, "router-b.pcap")
            os.mkfifo(fifo_a)
            os.mkfifo(fifo_b)

            writers = [
                _write_fifo_later(
                    fifo_a,
                    _pcap(_ethernet_ipv4_udp(_csi_payload(sequence=11, core=0))),
                ),
                _write_fifo_later(
                    fifo_b,
                    _pcap(_ethernet_ipv4_udp(_csi_payload(sequence=12, core=1))),
                ),
            ]

            with open(fifo_a, "rb") as stream_a, open(fifo_b, "rb") as stream_b:
                samples = []
                read_pcap_streams(
                    {"router-a": stream_a, "router-b": stream_b},
                    samples.append,
                )

            for writer in writers:
                writer.join(timeout=1)

        by_source = {sample.packet.source_id: sample for sample in samples}
        self.assertEqual(set(by_source), {"router-a", "router-b"})
        self.assertEqual(by_source["router-a"].seq, 11)
        self.assertEqual(by_source["router-a"].core, 0)
        self.assertEqual(by_source["router-b"].seq, 12)
        self.assertEqual(by_source["router-b"].core, 1)


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


def _csi_payload(sequence, core=0, spatial=0):
    return (
        b"\x11\x11"
        + struct.pack("<bB", -42, 0x88)
        + bytes.fromhex("001122334455")
        + struct.pack("<HHHH", sequence << 4, (core << 8) | spatial, 0x1234, 0x4366)
        + (b"\x00\x00\x00\x00" * 64)
    )


def _write_fifo_later(path, data):
    def write():
        with open(path, "wb") as stream:
            stream.write(data)

    thread = threading.Thread(target=write, daemon=True)
    thread.start()
    return thread


def _sample(source, sequence, core):
    from receiving_csi.nexmon import NexmonCsiParser
    from receiving_csi.models import PacketInfo

    payload = _csi_payload(sequence=sequence, core=core)
    packet = PacketInfo(source_id=source, timestamp_sec=1, timestamp_subsec=2)
    return NexmonCsiParser().parse(payload, packet)


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
