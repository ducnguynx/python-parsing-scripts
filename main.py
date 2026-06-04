from __future__ import annotations

import argparse
import json
import socket
import struct
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator


PCAP_LINKTYPE_ETHERNET = 1
PCAP_LINKTYPE_RAW_IPV4 = 101
NEXMON_MAGIC = b"\x11\x11"


class CaptureError(ValueError):
    pass


class SkipPacket(ValueError):
    pass


@dataclass(frozen=True)
class PacketInfo:
    timestamp_sec: int | None = None
    timestamp_subsec: int | None = None
    timestamp_resolution: str = "us"
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None


@dataclass(frozen=True)
class PcapPacket:
    ts_sec: int
    ts_subsec: int
    captured_len: int
    wire_len: int
    data: bytes
    timestamp_resolution: str


@dataclass(frozen=True)
class CsiPacket:
    device_id: str
    seq: int
    core: int
    bandwidth_mhz: int
    channel: int
    rssi: int
    csi_words: list[str]
    packet: PacketInfo
    mac: str
    spatial_stream: int
    css: int
    chanspec: int


class PcapStreamReader:
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
            if len(header) != packet_header.size:
                raise CaptureError("truncated pcap packet header")
            ts_sec, ts_subsec, captured_len, wire_len = packet_header.unpack(header)
            data = self._read_exact(captured_len)
            if len(data) != captured_len:
                raise CaptureError("truncated pcap packet data")
            yield PcapPacket(
                ts_sec=ts_sec,
                ts_subsec=ts_subsec,
                captured_len=captured_len,
                wire_len=wire_len,
                data=data,
                timestamp_resolution=self.timestamp_resolution,
            )

    def _read_global_header(self) -> None:
        header = self._read_exact(24)
        if len(header) != 24:
            if looks_like_tcpdump_text(header):
                raise CaptureError("tcpdump text stream detected; use tcpdump -U -s 0 -w -")
            raise CaptureError("truncated pcap global header")

        magic = header[:4]
        if magic not in self._MAGICS:
            if looks_like_tcpdump_text(header):
                raise CaptureError("tcpdump text stream detected; use tcpdump -U -s 0 -w -")
            raise CaptureError(f"unsupported pcap magic: {magic.hex()}")

        self.endian, self.timestamp_resolution = self._MAGICS[magic]
        _major, _minor, _zone, _sigfigs, _snaplen, self.linktype = struct.unpack(
            f"{self.endian}HHIIII",
            header[4:],
        )

    def _read_exact(self, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            chunk = self.stream.read(size - len(chunks))
            if not chunk:
                break
            chunks.extend(chunk)
        return bytes(chunks)


class TeeReader:
    def __init__(self, stream: BinaryIO, copy_to: BinaryIO) -> None:
        self.stream = stream
        self.copy_to = copy_to

    def read(self, size: int = -1) -> bytes:
        data = self.stream.read(size)
        if data:
            self.copy_to.write(data)
            self.copy_to.flush()
        return data


class SampleAggregator:
    def __init__(self, expected_cores: int) -> None:
        if expected_cores < 1 or expected_cores > 4:
            raise ValueError("--expected-cores must be between 1 and 4")
        self.expected_cores = expected_cores
        self.pending: dict[tuple[str, int, int, int], dict[int, CsiPacket]] = {}
        self.lock = threading.Lock()

    def add(self, sample: CsiPacket) -> dict[str, object] | None:
        if not 0 <= sample.core < 4:
            raise CaptureError(f"unsupported core index: {sample.core}")
        key = (sample.device_id, sample.seq, sample.bandwidth_mhz, sample.channel)
        with self.lock:
            samples = self.pending.setdefault(key, {})
            samples[sample.core] = sample
            if len(samples) < self.expected_cores:
                return None
            row = samples_to_json(samples)
            del self.pending[key]
            return row


class FileSink:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.count = 0
        self.lock = threading.Lock()

    def write(self, row: dict[str, object]) -> None:
        with self.lock:
            self.count += 1
            path = self.output_dir / f"sample_{self.count:04d}.json"
            path.write_text(json.dumps(row, indent=2) + "\n", encoding="utf-8")


class TcpServerSink:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.clients: list[socket.socket] = []
        self.clients_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen()
        self.thread = threading.Thread(target=self._accept_clients, name="tcp-json-server", daemon=True)
        self.thread.start()

    def write(self, row: dict[str, object]) -> None:
        line = (json.dumps(row, separators=(",", ":")) + "\n").encode("utf-8")
        with self.clients_lock:
            live_clients = []
            for client in self.clients:
                try:
                    client.sendall(line)
                    live_clients.append(client)
                except OSError:
                    close_quietly(client)
            self.clients = live_clients

    def close(self) -> None:
        self.stop_event.set()
        close_quietly(self.server)
        with self.clients_lock:
            for client in self.clients:
                close_quietly(client)
            self.clients = []

    def _accept_clients(self) -> None:
        while not self.stop_event.is_set():
            try:
                client, _address = self.server.accept()
            except OSError:
                return
            with self.clients_lock:
                self.clients.append(client)


class CompositeSink:
    def __init__(self, sinks: list[object], *, limit: int | None = None) -> None:
        self.sinks = sinks
        self.limit = limit
        self.count = 0
        self.lock = threading.Lock()
        self.stop_event = threading.Event()

    def write(self, row: dict[str, object]) -> None:
        with self.lock:
            if self.stop_event.is_set():
                return
            for sink in self.sinks:
                sink.write(row)
            self.count += 1
            if self.limit is not None and self.count >= self.limit:
                self.stop_event.set()

    def close(self) -> None:
        for sink in self.sinks:
            close = getattr(sink, "close", None)
            if close is not None:
                close()


def parse_router(value: str) -> tuple[str, str]:
    if "=" in value:
        source_id, target = value.split("=", 1)
        if not source_id or not target:
            raise argparse.ArgumentTypeError("router must be TARGET or ID=TARGET")
        return source_id, target
    return value, value


def parse_host_port(value: str) -> tuple[str, int]:
    if ":" not in value:
        raise argparse.ArgumentTypeError("expected HOST:PORT")
    host, raw_port = value.rsplit(":", 1)
    if not host:
        raise argparse.ArgumentTypeError("host is required")
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    return host, port


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture Nexmon CSI over multiple SSH pcap streams.")
    parser.add_argument(
        "--router",
        action="append",
        type=parse_router,
        required=True,
        metavar="TARGET|ID=TARGET",
        help="SSH target. Repeat for multiple routers.",
    )
    parser.add_argument("--interface", default="wlan0", help="router interface for MAC query and tcpdump")
    parser.add_argument("--port", type=int, default=5500, help="UDP destination port carrying CSI")
    parser.add_argument("--expected-cores", type=int, default=4)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--tcp-listen", type=parse_host_port, metavar="HOST:PORT")
    parser.add_argument(
        "--save-pcap-dir",
        type=Path,
        help="optional directory for saving raw tcpdump pcap streams, one file per router",
    )
    parser.add_argument("--count", type=int, help="stop after this many grouped JSON records")
    args = parser.parse_args(argv)

    sinks = []
    if args.output_dir is not None:
        sinks.append(FileSink(args.output_dir))
    if args.tcp_listen is not None:
        host, tcp_port = args.tcp_listen
        sinks.append(TcpServerSink(host, tcp_port))
    if not sinks:
        parser.error("at least one output is required: --output-dir or --tcp-listen")

    aggregator = SampleAggregator(args.expected_cores)
    sink = CompositeSink(sinks, limit=args.count)
    threads = [
        threading.Thread(
            target=capture_router,
            kwargs={
                "source_name": source_name,
                "ssh_target": ssh_target,
                "interface": args.interface,
                "port": args.port,
                "save_pcap_dir": args.save_pcap_dir,
                "aggregator": aggregator,
                "sink": sink,
            },
            name=f"capture-{source_name}",
        )
        for source_name, ssh_target in args.router
    ]

    try:
        for thread in threads:
            thread.start()
        while any(thread.is_alive() for thread in threads) and not sink.stop_event.is_set():
            for thread in threads:
                thread.join(timeout=0.2)
    except KeyboardInterrupt:
        sink.stop_event.set()
    finally:
        sink.close()
    return 0


def capture_router(
    *,
    source_name: str,
    ssh_target: str,
    interface: str,
    port: int,
    save_pcap_dir: Path | None,
    aggregator: SampleAggregator,
    sink: CompositeSink,
) -> None:
    try:
        device_id = query_router_mac(ssh_target, interface)
    except Exception as exc:
        print(f"warning: {source_name}: failed to query router MAC: {exc}", file=sys.stderr, flush=True)
        return

    command = f"tcpdump -i {shell_quote(interface)} -U -s 0 -w - udp dst port {port}"
    process = subprocess.Popen(
        ["ssh", ssh_target, command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    pcap_output = None
    capture_stream: BinaryIO = process.stdout
    try:
        if save_pcap_dir is not None:
            save_pcap_dir.mkdir(parents=True, exist_ok=True)
            pcap_path = save_pcap_dir / f"{safe_filename(source_name)}_{safe_filename(device_id)}.pcap"
            pcap_output = pcap_path.open("wb")
            capture_stream = TeeReader(process.stdout, pcap_output)
        read_capture_stream(capture_stream, device_id, port, aggregator, sink)
    except Exception as exc:
        print(f"warning: {source_name}: {exc}", file=sys.stderr, flush=True)
    finally:
        if pcap_output is not None:
            pcap_output.close()
        if sink.stop_event.is_set() and process.poll() is None:
            process.terminate()
        try:
            _stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            _stdout, stderr = process.communicate(timeout=2)
        if stderr:
            sys.stderr.buffer.write(stderr)
            sys.stderr.flush()


def query_router_mac(ssh_target: str, interface: str) -> str:
    command = f"cat /sys/class/net/{shell_quote(interface)}/address"
    output = subprocess.check_output(["ssh", ssh_target, command], text=True, stderr=subprocess.PIPE)
    mac = output.strip().lower()
    if not is_mac_address(mac):
        raise CaptureError(f"invalid MAC address from router: {mac!r}")
    return mac


def read_capture_stream(
    stream: BinaryIO,
    device_id: str,
    port: int,
    aggregator: SampleAggregator,
    sink: CompositeSink,
) -> None:
    reader = PcapStreamReader(stream)
    for packet in reader:
        if sink.stop_event.is_set():
            return
        if reader.linktype is None:
            continue
        try:
            payload, packet_info = extract_udp_payload(packet, reader.linktype, port)
            csi_packet = parse_nexmon_packet(payload, packet_info, device_id)
            row = aggregator.add(csi_packet)
        except SkipPacket:
            continue
        except CaptureError as exc:
            print(f"warning: {exc}", file=sys.stderr, flush=True)
            continue
        if row is not None:
            sink.write(row)


def extract_udp_payload(
    packet: PcapPacket,
    linktype: int,
    dst_port: int,
) -> tuple[bytes, PacketInfo]:
    ip_packet = extract_ipv4(packet.data, linktype)
    payload, src_ip, dst_ip, src_port, found_dst_port = extract_udp(ip_packet)
    if found_dst_port != dst_port:
        raise SkipPacket
    return (
        payload,
        PacketInfo(
            timestamp_sec=packet.ts_sec,
            timestamp_subsec=packet.ts_subsec,
            timestamp_resolution=packet.timestamp_resolution,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=found_dst_port,
        ),
    )


def extract_ipv4(frame: bytes, linktype: int) -> bytes:
    if linktype == PCAP_LINKTYPE_ETHERNET:
        if len(frame) < 14:
            raise CaptureError("short ethernet frame")
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        offset = 14
        while ethertype == 0x8100:
            if len(frame) < offset + 4:
                raise CaptureError("short vlan frame")
            ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
            offset += 4
        if ethertype != 0x0800:
            raise SkipPacket
        return require_ipv4(frame[offset:])
    if linktype == PCAP_LINKTYPE_RAW_IPV4:
        return require_ipv4(frame)
    if linktype == 113:
        if len(frame) < 16:
            raise CaptureError("short linux cooked frame")
        protocol = struct.unpack_from("!H", frame, 14)[0]
        if protocol != 0x0800:
            raise SkipPacket
        return require_ipv4(frame[16:])
    if linktype == 276:
        if len(frame) < 20:
            raise CaptureError("short linux cooked v2 frame")
        protocol = struct.unpack_from("!H", frame, 0)[0]
        if protocol != 0x0800:
            raise SkipPacket
        return require_ipv4(frame[20:])
    if linktype == 0:
        if len(frame) < 4:
            raise CaptureError("short null loopback frame")
        family = struct.unpack_from("<I", frame, 0)[0]
        if family not in {2, 24, 28, 30}:
            raise SkipPacket
        return require_ipv4(frame[4:])
    raise CaptureError(f"unsupported pcap linktype: {linktype}")


def require_ipv4(packet: bytes) -> bytes:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        raise SkipPacket
    return packet


def extract_udp(ip_packet: bytes) -> tuple[bytes, str, str, int, int]:
    ihl = (ip_packet[0] & 0x0F) * 4
    if ihl < 20 or len(ip_packet) < ihl + 8:
        raise CaptureError("invalid IPv4 header length")
    if ip_packet[9] != 17:
        raise SkipPacket

    total_len = struct.unpack_from("!H", ip_packet, 2)[0]
    if total_len == 0 or total_len > len(ip_packet):
        total_len = len(ip_packet)
    udp = ip_packet[ihl:total_len]
    if len(udp) < 8:
        raise CaptureError("short UDP datagram")

    src_port, dst_port, udp_len, _checksum = struct.unpack_from("!HHHH", udp)
    if udp_len < 8 or udp_len > len(udp):
        raise CaptureError("invalid UDP length")

    src_ip = ".".join(str(byte) for byte in ip_packet[12:16])
    dst_ip = ".".join(str(byte) for byte in ip_packet[16:20])
    return udp[8:udp_len], src_ip, dst_ip, src_port, dst_port


def parse_nexmon_packet(payload: bytes, packet: PacketInfo, device_id: str) -> CsiPacket:
    if len(payload) < 18:
        raise CaptureError("payload too short for Nexmon CSI header")
    if payload[:2] != NEXMON_MAGIC:
        raise CaptureError("missing Nexmon CSI magic 0x1111")

    rssi = struct.unpack_from("<b", payload, 2)[0]
    mac = format_mac(payload[4:10])
    sequence_control, css, chanspec, _chip_version = struct.unpack_from("<HHHH", payload, 10)
    raw_csi = payload[18:]
    bandwidth_mhz = bandwidth_from_csi_length(len(raw_csi))

    return CsiPacket(
        device_id=device_id,
        seq=sequence_control >> 4,
        core=(css >> 8) & 0x7,
        bandwidth_mhz=bandwidth_mhz,
        channel=decode_broadcom_channel(chanspec, bandwidth_mhz),
        rssi=rssi,
        csi_words=csi_words_to_bit_strings(raw_csi),
        packet=packet,
        mac=mac,
        spatial_stream=css & 0x7,
        css=css,
        chanspec=chanspec,
    )


def bandwidth_from_csi_length(csi_len: int) -> int:
    if csi_len == 64 * 4:
        return 20
    if csi_len == 128 * 4:
        return 40
    if csi_len == 256 * 4:
        return 80
    raise CaptureError(f"unsupported CSI byte length: {csi_len}")


def decode_broadcom_channel(chanspec: int, bandwidth_mhz: int) -> int:
    channel = chanspec & 0x00FF
    if bandwidth_mhz == 20:
        return channel

    sideband = (chanspec >> 8) & 0x0F
    if bandwidth_mhz == 40:
        if sideband == 1:
            return channel - 2
        if sideband == 2:
            return channel + 2
        return channel

    if bandwidth_mhz == 80:
        offsets = {
            1: -6,
            2: -2,
            3: 2,
            4: 6,
        }
        return channel + offsets.get(sideband, 0)

    return channel


def csi_words_to_bit_strings(raw_csi: bytes) -> list[str]:
    if len(raw_csi) % 4 != 0:
        raise CaptureError("CSI payload length is not aligned to 32-bit words")
    words = []
    for offset in range(0, len(raw_csi), 4):
        value = int.from_bytes(raw_csi[offset : offset + 4], "little", signed=False)
        words.append(f"{value:032b}")
    return words


def samples_to_json(samples_by_core: dict[int, CsiPacket]) -> dict[str, object]:
    first = samples_by_core[min(samples_by_core)]
    rssi = [0, 0, 0, 0]
    csi = {f"c{core}": [] for core in range(4)}
    for core, sample in sorted(samples_by_core.items()):
        rssi[core] = sample.rssi
        csi[f"c{core}"] = sample.csi_words
    return {
        "device_id": first.device_id,
        "seq": first.seq,
        "timestamp": packet_timestamp_us(first.packet),
        "bw": first.bandwidth_mhz,
        "ch": first.channel,
        "agc": [0, 0, 0, 0],
        "rssi": rssi,
        "csi": csi,
    }


def packet_timestamp_us(packet: PacketInfo) -> int | None:
    if packet.timestamp_sec is None or packet.timestamp_subsec is None:
        return None
    if packet.timestamp_resolution == "ns":
        return packet.timestamp_sec * 1_000_000 + packet.timestamp_subsec // 1_000
    return packet.timestamp_sec * 1_000_000 + packet.timestamp_subsec


def format_mac(raw: bytes) -> str:
    if len(raw) != 6:
        raise CaptureError("invalid MAC length")
    return ":".join(f"{byte:02x}" for byte in raw)


def is_mac_address(value: str) -> bool:
    parts = value.split(":")
    return len(parts) == 6 and all(len(part) == 2 and is_hex(part) for part in parts)


def is_hex(value: str) -> bool:
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def looks_like_tcpdump_text(data: bytes) -> bool:
    if not data:
        return False
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return False
    return "IP " in text or "listening on" in text or "tcpdump:" in text


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def safe_filename(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in value)


def close_quietly(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass


if __name__ == "__main__":
    raise SystemExit(main())
