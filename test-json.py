from __future__ import annotations

import argparse
import json
import sys
import threading
from pathlib import Path

from receiving_csi import CsiSample, read_pcap_stream


class StopCapture(Exception):
    pass


class MultiCoreJsonSampleWriter:
    def __init__(self, output_dir: Path, limit: int, expected_cores: int) -> None:
        self.output_dir = output_dir
        self.limit = limit
        self.expected_cores = expected_cores
        self.count = 0
        self.pending: dict[tuple[str | None, str, int, int, int, int], dict[int, CsiSample]] = {}
        self.lock = threading.Lock()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def __call__(self, sample: CsiSample) -> None:
        with self.lock:
            print(
                "packet source={source} seq={seq} css=0x{css:04x} core={core} "
                "spatial={spatial} bw={bw}MHz ch={channel} chanspec=0x{chanspec:04x} "
                "mac={mac}".format(
                    source=sample.packet.source_id,
                    seq=sample.seq,
                    css=sample.css if sample.css is not None else 0,
                    core=sample.core,
                    spatial=sample.spatial_stream,
                    bw=sample.bandwidth_mhz,
                    channel=decode_broadcom_channel(sample.chanspec, sample.bandwidth_mhz),
                    chanspec=sample.chanspec,
                    mac=sample.mac,
                ),
                file=sys.stderr,
                flush=True,
            )

            if self.count >= self.limit:
                raise StopCapture

            if not 0 <= sample.core < self.expected_cores:
                print(f"warning: skipping unexpected core {sample.core}", file=sys.stderr, flush=True)
                return

            key = (
                sample.packet.source_id,
                sample.mac,
                sample.seq,
                sample.spatial_stream,
                sample.bandwidth_mhz,
                sample.chanspec,
            )
            samples_by_core = self.pending.setdefault(key, {})
            if sample.core in samples_by_core:
                print(
                    "warning: duplicate core {core} for source={source} seq={seq}; "
                    "still waiting for cores {missing}".format(
                        core=sample.core,
                        source=sample.packet.source_id,
                        seq=sample.seq,
                        missing=missing_cores(samples_by_core, self.expected_cores),
                    ),
                    file=sys.stderr,
                    flush=True,
                )
            samples_by_core[sample.core] = sample

            if len(samples_by_core) < self.expected_cores:
                return

            self.count += 1
            row = samples_to_json(samples_by_core)
            output_path = self.output_dir / f"sample_{self.count:04d}.json"
            output_path.write_text(json.dumps(row, indent=2) + "\n", encoding="utf-8")
            del self.pending[key]
            print(
                f"wrote {output_path} with cores {sorted(samples_by_core)}",
                file=sys.stderr,
                flush=True,
            )

            if self.count >= self.limit:
                raise StopCapture


def samples_to_json(samples_by_core: dict[int, CsiSample]) -> dict[str, object]:
    first = samples_by_core[min(samples_by_core)]
    rssi = [0, 0, 0, 0]
    csi = {f"c{core}": [] for core in range(4)}

    for core, sample in sorted(samples_by_core.items()):
        if 0 <= core < len(rssi) and sample.rssi is not None:
            rssi[core] = sample.rssi
        if 0 <= core < 4:
            csi[f"c{core}"] = [[int(value.imag), int(value.real)] for value in sample.csi]

    return {
        "device_id": first.mac,
        "source_id": first.packet.source_id,
        "seq": first.seq,
        "timestamp": packet_timestamp_us(first),
        "bw": first.bandwidth_mhz,
        "ch": decode_broadcom_channel(first.chanspec, first.bandwidth_mhz),
        "css": {f"c{core}": sample.css for core, sample in sorted(samples_by_core.items())},
        "agc": [0, 0, 0, 0],
        "rssi": rssi,
        "csi": csi,
    }


def missing_cores(samples_by_core: dict[int, CsiSample], expected_cores: int) -> list[int]:
    return [core for core in range(expected_cores) if core not in samples_by_core]


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


def packet_timestamp_us(sample: CsiSample) -> int | None:
    packet = sample.packet
    if packet.timestamp_sec is None or packet.timestamp_subsec is None:
        return None
    if packet.timestamp_resolution == "ns":
        return packet.timestamp_sec * 1_000_000 + packet.timestamp_subsec // 1_000
    return packet.timestamp_sec * 1_000_000 + packet.timestamp_subsec


def print_error(exc: Exception) -> None:
    print(f"warning: {exc}", file=sys.stderr, flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Capture a small NexmonCSI JSON sample set from stdin pcap."
    )
    parser.add_argument("--port", type=int, default=5500)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--output-dir", type=Path, default=Path("json-samples"))
    parser.add_argument("--expected-cores", type=int, default=4)
    args = parser.parse_args(argv)

    writer = MultiCoreJsonSampleWriter(args.output_dir, args.count, args.expected_cores)
    try:
        read_pcap_stream(
            sys.stdin.buffer,
            writer,
            port=args.port,
            error_callback=print_error,
        )
    except StopCapture:
        pass

    print(f"captured {writer.count} samples", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
