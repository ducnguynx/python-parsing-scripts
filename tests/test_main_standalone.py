import io
import json
import socket
import struct
import tempfile
import time
import unittest
from pathlib import Path

import main


class StandaloneMainTests(unittest.TestCase):
    def test_read_capture_stream_emits_final_json_with_bit_string_csi(self):
        raw_words = [1, 0xFFFFFFFF] + [0] * 62
        payload = _csi_payload(sequence=7, core=0, chanspec=157, raw_words=raw_words)
        pcap = _pcap(_ethernet_ipv4_udp(payload))
        collector = _Collector()
        sink = main.CompositeSink([collector])
        aggregator = main.SampleAggregator(expected_cores=1)

        main.read_capture_stream(io.BytesIO(pcap), "02:1a:2b:3c:4d:5e", 5500, aggregator, sink)

        self.assertEqual(len(collector.rows), 1)
        row = collector.rows[0]
        self.assertEqual(row["device_id"], "02:1a:2b:3c:4d:5e")
        self.assertEqual(row["seq"], 7)
        self.assertEqual(row["timestamp"], 1_000_002)
        self.assertEqual(row["bw"], 20)
        self.assertEqual(row["ch"], 157)
        self.assertEqual(row["rssi"], [-42, 0, 0, 0])
        self.assertEqual(row["csi"]["c0"][0], "00000000000000000000000000000001")
        self.assertEqual(row["csi"]["c0"][1], "11111111111111111111111111111111")
        self.assertEqual(row["csi"]["c1"], [])

    def test_aggregator_groups_expected_cores(self):
        packet = main.PacketInfo(timestamp_sec=1, timestamp_subsec=2)
        aggregator = main.SampleAggregator(expected_cores=4)
        rows = []

        for core in range(4):
            sample = main.CsiPacket(
                device_id="aa:bb:cc:dd:ee:ff",
                seq=10,
                core=core,
                bandwidth_mhz=20,
                channel=6,
                rssi=core + 1,
                csi_words=[f"{core:032b}"],
                packet=packet,
                mac="00:11:22:33:44:55",
                spatial_stream=0,
                css=core << 8,
                chanspec=6,
            )
            row = aggregator.add(sample)
            if row is not None:
                rows.append(row)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["rssi"], [1, 2, 3, 4])
        self.assertEqual(rows[0]["csi"]["c3"], ["00000000000000000000000000000011"])

    def test_file_sink_writes_numbered_json(self):
        with tempfile.TemporaryDirectory() as directory:
            sink = main.FileSink(Path(directory))
            sink.write({"seq": 1})

            output = Path(directory) / "sample_0001.json"
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), {"seq": 1})

    def test_tee_reader_copies_bytes_read_by_parser(self):
        raw_words = [0] * 64
        payload = _csi_payload(sequence=1, core=0, chanspec=6, raw_words=raw_words)
        pcap = _pcap(_ethernet_ipv4_udp(payload))
        source = io.BytesIO(pcap)
        copied = io.BytesIO()
        collector = _Collector()
        sink = main.CompositeSink([collector])
        aggregator = main.SampleAggregator(expected_cores=1)

        main.read_capture_stream(main.TeeReader(source, copied), "aa:bb:cc:dd:ee:ff", 5500, aggregator, sink)

        self.assertEqual(copied.getvalue(), pcap)
        self.assertEqual(len(collector.rows), 1)

    def test_tcp_server_sink_streams_jsonl_to_client(self):
        try:
            sink = main.TcpServerSink("127.0.0.1", 0)
        except PermissionError as exc:
            self.skipTest(f"local sockets are not permitted: {exc}")
        port = sink.server.getsockname()[1]
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
                client.settimeout(1)
                for _ in range(20):
                    with sink.clients_lock:
                        if sink.clients:
                            break
                    time.sleep(0.01)
                sink.write({"seq": 123})
                self.assertEqual(client.recv(1024), b'{"seq":123}\n')
        finally:
            sink.close()


class _Collector:
    def __init__(self):
        self.rows = []

    def write(self, row):
        self.rows.append(row)


def _pcap(frame):
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packet_header = struct.pack("<IIII", 1, 2, len(frame), len(frame))
    return global_header + packet_header + frame


def _csi_payload(sequence, core, chanspec, raw_words):
    return (
        b"\x11\x11"
        + struct.pack("<bB", -42, 0x88)
        + bytes.fromhex("001122334455")
        + struct.pack("<HHHH", sequence << 4, core << 8, chanspec, 0x4366)
        + b"".join(struct.pack("<I", word) for word in raw_words)
    )


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
