# receiving-csi

`receiving-csi` is a small Python package for receiving and parsing live
NexmonCSI data, with the Asus RT-AC86U / Broadcom `bcm4366c0` target as the
first supported device.

The project has two jobs:

1. Receive CSI samples from a stream.
2. Convert each NexmonCSI UDP payload into a Python `CsiSample` whose CSI values
   are a NumPy `complex64` array.

It intentionally does not decide how your machine-learning or sensing pipeline
stores, filters, normalizes, labels, or trains on CSI. The parser hands clean
Python objects to your callback so downstream code can write JSONL, tensors,
databases, files, plots, or model inputs.

## Documentation Map

Start here:

- [Project Guide](docs/PROJECT_GUIDE.md): complete walkthrough of what the
  project does, how data flows through it, and how to use it.
- [API Reference](docs/API_REFERENCE.md): detailed public and internal function
  reference with examples.
- [Packet Formats](docs/PACKET_FORMATS.md): pcap, UDP, NexmonCSI header, and CSI
  unpacking details.
- [Development Guide](docs/DEVELOPMENT.md): setup, tests, repository layout, and
  extension notes.

## Quick Start

Install the package in editable mode from the repository root:

```bash
python -m pip install -e .
```

Capture a binary pcap stream from a router over SSH and parse it locally:

```bash
ssh admin@ROUTER 'tcpdump -i wlan0 -U -s 0 -w - udp dst port 5500' \
  | python -m receiving_csi pcap-stdin
```

The `tcpdump` options matter:

- `-i wlan0` captures from the router interface.
- `-U` packet-buffers the output so data arrives continuously.
- `-s 0` avoids snap-length truncation.
- `-w -` writes binary pcap to stdout.
- `udp dst port 5500` keeps only the expected NexmonCSI UDP traffic.

For a raw UDP relay where NexmonCSI packets are sent directly to this computer:

```bash
python -m receiving_csi udp --host 0.0.0.0 --port 5500
```

To print one JSON object per parsed sample:

```bash
python -m receiving_csi pcap-stdin --dump-jsonl < capture.pcap
```

## Python Usage

Read a saved pcap file and handle every parsed CSI sample:

```python
from receiving_csi import read_pcap_stream


def handle_sample(sample):
    print(sample.seq, sample.core, sample.spatial_stream, sample.csi.shape)


with open("capture.pcap", "rb") as stream:
    read_pcap_stream(stream, handle_sample)
```

Parse one raw NexmonCSI UDP payload:

```python
from receiving_csi import parse_nexmon_payload

payload = b"..."  # bytes from a NexmonCSI UDP datagram
sample = parse_nexmon_payload(payload)

print(sample.mac)
print(sample.bandwidth_mhz)
print(sample.csi.dtype)
print(sample.csi.shape)
```

Listen forever on UDP port `5500`:

```python
from receiving_csi import listen_udp


def handle_sample(sample):
    amplitude = abs(sample.csi)
    print(sample.seq, amplitude.mean())


listen_udp("0.0.0.0", 5500, handle_sample)
```

## What A Parsed Sample Contains

The parser returns a frozen dataclass:

```python
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CsiSample:
    mac: str
    seq: int
    core: int
    spatial_stream: int
    chanspec: int
    chip_version: int
    bandwidth_mhz: int
    csi: Any
    packet: PacketInfo = PacketInfo()
    magic: int = 0x1111
    rssi: int | None = None
    frame_control: int | None = None
    header_layout: str = "compact"
```

Important fields:

- `mac`: transmitter MAC address from the NexmonCSI header.
- `seq`: NexmonCSI sequence number.
- `core`: radio core extracted from the CSS bit field.
- `spatial_stream`: spatial stream extracted from the CSS bit field.
- `bandwidth_mhz`: one of `20`, `40`, or `80`, inferred from CSI byte length.
- `csi`: NumPy `complex64` array with one value per subcarrier tone.
- `packet`: capture metadata such as timestamp and IP/UDP addresses when the
  sample came from a pcap stream.
- `rssi`, `frame_control`: available for the extended header layout only.

## Supported Input

The project currently supports:

- Classic libpcap streams, not pcapng.
- Ethernet, raw IPv4, Linux cooked v1, Linux cooked v2, and BSD null loopback
  link types.
- IPv4 UDP packets.
- Destination UDP port `5500` by default.
- NexmonCSI compact and extended payload layouts.
- CSI byte lengths for 20, 40, and 80 MHz captures.
- Broadcom `bcm4366c0` packed CSI words, unpacked with NumPy.

The project does not currently support:

- pcapng input.
- IPv6.
- TCP.
- Other Nexmon chip unpacking formats.
- Automatic router setup or firmware installation.
- Long-term data storage.

## Test Command

Run the test suite from the repository root:

```bash
python -m unittest discover -s tests -v
```

