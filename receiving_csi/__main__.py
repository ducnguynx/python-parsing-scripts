from __future__ import annotations

import argparse
import json
import sys

import numpy as np

from .models import CsiSample
from .receivers import listen_udp, read_pcap_stream


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Receive and parse NexmonCSI samples")
    subparsers = parser.add_subparsers(dest="command", required=True)

    pcap_parser = subparsers.add_parser("pcap-stdin", help="read binary pcap from stdin")
    pcap_parser.add_argument("--port", type=int, default=5500)
    pcap_parser.add_argument("--dump-jsonl", action="store_true")

    udp_parser = subparsers.add_parser("udp", help="listen for raw NexmonCSI UDP packets")
    udp_parser.add_argument("--host", default="0.0.0.0")
    udp_parser.add_argument("--port", type=int, default=5500)
    udp_parser.add_argument("--dump-jsonl", action="store_true")

    args = parser.parse_args(argv)

    def callback(sample: CsiSample) -> None:
        if args.dump_jsonl:
            print(json.dumps(_summary(sample)), flush=True)
        else:
            print(
                "seq={seq} core={core} spatial={spatial} bw={bw}MHz "
                "mac={mac} csi_shape={shape}".format(
                    seq=sample.seq,
                    core=sample.core,
                    spatial=sample.spatial_stream,
                    bw=sample.bandwidth_mhz,
                    mac=sample.mac,
                    shape=sample.csi.shape,
                ),
                flush=True,
            )

    def error_callback(exc: Exception) -> None:
        print(f"warning: {exc}", file=sys.stderr, flush=True)

    if args.command == "pcap-stdin":
        read_pcap_stream(sys.stdin.buffer, callback, port=args.port, error_callback=error_callback)
    elif args.command == "udp":
        listen_udp(args.host, args.port, callback, error_callback=error_callback)
    return 0


def _summary(sample: CsiSample) -> dict[str, object]:
    amplitude = np.abs(sample.csi)
    return {
        "seq": sample.seq,
        "core": sample.core,
        "spatial_stream": sample.spatial_stream,
        "bandwidth_mhz": sample.bandwidth_mhz,
        "mac": sample.mac,
        "chanspec": sample.chanspec,
        "chip_version": sample.chip_version,
        "rssi": sample.rssi,
        "frame_control": sample.frame_control,
        "header_layout": sample.header_layout,
        "src_ip": sample.packet.src_ip,
        "dst_ip": sample.packet.dst_ip,
        "src_port": sample.packet.src_port,
        "dst_port": sample.packet.dst_port,
        "timestamp_sec": sample.packet.timestamp_sec,
        "timestamp_subsec": sample.packet.timestamp_subsec,
        "timestamp_resolution": sample.packet.timestamp_resolution,
        "csi_shape": list(sample.csi.shape),
        "amplitude_mean": float(amplitude.mean()) if amplitude.size else None,
        "amplitude_max": float(amplitude.max()) if amplitude.size else None,
    }


if __name__ == "__main__":
    raise SystemExit(main())
