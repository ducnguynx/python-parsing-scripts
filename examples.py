from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable

import numpy as np

from receiving_csi import CsiSample, read_pcap_stream


def print_summary(sample: CsiSample) -> None:
    """Small callback for checking that live capture is working."""
    amplitude = np.abs(sample.csi)
    print(
        "seq={seq} rssi={rssi} core={core} spatial={spatial} "
        "bw={bw}MHz mac={mac} amp_mean={amp_mean:.2f} amp_max={amp_max:.2f}".format(
            seq=sample.seq,
            rssi=sample.rssi,
            core=sample.core,
            spatial=sample.spatial_stream,
            bw=sample.bandwidth_mhz,
            mac=sample.mac,
            amp_mean=float(amplitude.mean()) if amplitude.size else 0.0,
            amp_max=float(amplitude.max()) if amplitude.size else 0.0,
        ),
        flush=True,
    )


def jsonl_callback(*, include_csi: bool = False) -> Callable[[CsiSample], None]:
    """Return a callback that prints one JSON object per CSI sample."""

    def handle_sample(sample: CsiSample) -> None:
        print(json.dumps(sample_to_dict(sample, include_csi=include_csi)), flush=True)

    return handle_sample


def sample_to_dict(sample: CsiSample, *, include_csi: bool = False) -> dict[str, object]:
    amplitude = np.abs(sample.csi)
    row: dict[str, object] = {
        "seq": sample.seq,
        "rssi": sample.rssi,
        "frame_control": sample.frame_control,
        "core": sample.core,
        "spatial_stream": sample.spatial_stream,
        "bandwidth_mhz": sample.bandwidth_mhz,
        "mac": sample.mac,
        "chanspec": sample.chanspec,
        "chip_version": sample.chip_version,
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
    if include_csi:
        row["csi_real"] = sample.csi.real.astype(float).tolist()
        row["csi_imag"] = sample.csi.imag.astype(float).tolist()
        row["amplitude"] = amplitude.astype(float).tolist()
    return row


def custom_callback(sample: CsiSample) -> None:
    """Replace this with your own pipeline code."""
    row = sample_to_dict(sample)

    # Examples of custom logic:
    # - write row to a JSONL file
    # - push row into Kafka/MQTT/Redis
    # - convert sample.csi into a tensor for ML inference
    # - filter by MAC, RSSI, core, spatial stream, or channel
    if row["rssi"] is not None and row["rssi"] < -80:
        return

    print(json.dumps(row), flush=True)


def print_error(exc: Exception) -> None:
    print(f"warning: {exc}", file=sys.stderr, flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Examples for reading live NexmonCSI pcap streams from stdin."
    )
    parser.add_argument("--port", type=int, default=5500)
    parser.add_argument(
        "--mode",
        choices=("summary", "jsonl", "custom"),
        default="summary",
    )
    parser.add_argument(
        "--include-csi",
        action="store_true",
        help="include full CSI real/imag/amplitude arrays in jsonl mode",
    )
    args = parser.parse_args(argv)

    if args.mode == "summary":
        callback = print_summary
    elif args.mode == "jsonl":
        callback = jsonl_callback(include_csi=args.include_csi)
    else:
        callback = custom_callback

    read_pcap_stream(
        sys.stdin.buffer,
        callback,
        port=args.port,
        error_callback=print_error,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
