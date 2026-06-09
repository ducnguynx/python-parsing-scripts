# Project Guide

This document explains the project from the point of view of a new user who
wants to understand what the code does before trusting it in a CSI collection or
machine-learning workflow.

## Plain-English Summary

`receiving-csi` receives Channel State Information (CSI) samples produced by
NexmonCSI and converts them into Python objects.

In a typical setup:

1. A Wi-Fi device or router runs NexmonCSI.
2. NexmonCSI emits CSI samples as UDP packets.
3. The router can be queried with `tcpdump`.
4. `tcpdump` writes a binary pcap stream to stdout.
5. This project reads the pcap stream from stdin.
6. It extracts IPv4 UDP datagrams on a configured destination port.
7. It parses the NexmonCSI UDP payload.
8. It unpacks packed CSI words into a NumPy complex array.
9. It calls user code with a `CsiSample`.

The most important design choice is that the project is callback-based. It does
not store samples itself. A caller provides a function, and the package calls
that function once for each successfully parsed sample.

## Repository Layout

```text
receiving-code/
├── README.md
├── pyproject.toml
├── docs/
│   ├── API_REFERENCE.md
│   ├── DEVELOPMENT.md
│   ├── PACKET_FORMATS.md
│   └── PROJECT_GUIDE.md
├── receiving_csi/
│   ├── __init__.py
│   ├── __main__.py
│   ├── models.py
│   ├── nexmon.py
│   ├── pcap.py
│   └── receivers.py
└── tests/
    ├── test_nexmon.py
    └── test_pcap.py
```

Each file has a focused responsibility:

| File | Responsibility |
| --- | --- |
| `pyproject.toml` | Package metadata, Python version, runtime dependency list. |
| `README.md` | Short entry point, quick commands, links to detailed docs. |
| `receiving_csi/__init__.py` | Public import surface with lazy imports. |
| `receiving_csi/__main__.py` | Command-line interface for `python -m receiving_csi`. |
| `receiving_csi/models.py` | Dataclasses used to pass parsed data around. |
| `receiving_csi/receivers.py` | High-level pcap and UDP receiver functions. |
| `receiving_csi/pcap.py` | Classic pcap reader and IPv4/UDP packet extraction. |
| `receiving_csi/nexmon.py` | NexmonCSI payload parser and `bcm4366c0` CSI unpacker. |
| `tests/test_nexmon.py` | Parser and unpacking tests. |
| `tests/test_pcap.py` | pcap stream, packet extraction, and receiver integration tests. |

## Runtime Dependencies

The project requires Python `>=3.10`.

The only runtime dependency declared in `pyproject.toml` is:

```toml
dependencies = [
    "numpy>=1.24",
]
```

NumPy is used for:

- Reading CSI bytes as little-endian unsigned 32-bit words.
- Performing array-based storage of real and imaginary values.
- Returning CSI as a `np.ndarray` with dtype `np.complex64`.
- Computing amplitude summary values in the CLI JSONL output.

The package does not depend on a separate NexmonCSI decoder library.

## Main Data Flow

The package has two top-level receiving paths.

The pcap stream path:

```text
binary pcap stream
    ↓
PcapStreamReader
    ↓
PcapPacket objects
    ↓
iter_udp_payloads(...)
    ↓
(UDP payload bytes, PacketInfo)
    ↓
NexmonCsiParser.parse(...)
    ↓
CsiSample
    ↓
user callback
```

The raw UDP path:

```text
UDP socket
    ↓
sock.recvfrom(...)
    ↓
(UDP payload bytes, sender address)
    ↓
PacketInfo
    ↓
NexmonCsiParser.parse(...)
    ↓
CsiSample
    ↓
user callback
```

Both paths converge at `NexmonCsiParser.parse`. This keeps capture mechanics
separate from CSI decoding.

## Command-Line Interface

The CLI is implemented in `receiving_csi/__main__.py`, which makes this command
work:

```bash
python -m receiving_csi ...
```

There are two subcommands.

### `pcap-stdin`

`pcap-stdin` reads binary classic pcap bytes from standard input.

```bash
python -m receiving_csi pcap-stdin --port 5500
```

The expected router-side command is:

```bash
ssh admin@ROUTER 'tcpdump -i wlan0 -U -s 0 -w - udp dst port 5500' \
  | python -m receiving_csi pcap-stdin
```

The command emits one human-readable summary line per parsed sample:

```text
seq=7 core=1 spatial=1 bw=20MHz mac=00:11:22:33:44:55 csi_shape=(64,)
```

If `--dump-jsonl` is used, each sample is printed as a JSON object:

```bash
python -m receiving_csi pcap-stdin --dump-jsonl < capture.pcap
```

Example JSONL shape:

```json
{"seq": 7, "core": 1, "spatial_stream": 1, "bandwidth_mhz": 20, "mac": "00:11:22:33:44:55", "chanspec": 4660, "chip_version": 17254, "rssi": null, "frame_control": null, "header_layout": "compact", "src_ip": "10.10.10.10", "dst_ip": "255.255.255.255", "src_port": 5500, "dst_port": 5500, "timestamp_sec": 1, "timestamp_subsec": 2, "timestamp_resolution": "us", "csi_shape": [64], "amplitude_mean": 0.0, "amplitude_max": 0.0}
```

The CLI does not print the full CSI array in JSONL mode. It prints summary
statistics because full arrays are large and complex numbers are not directly
JSON serializable.

### `udp`

`udp` binds a local UDP socket and parses every datagram received on that socket:

```bash
python -m receiving_csi udp --host 0.0.0.0 --port 5500
```

This mode is useful when another process, router, or relay sends raw NexmonCSI
UDP payloads directly to this computer.

The UDP listener runs forever until interrupted.

## Public Python API

The package exposes these names from `receiving_csi.__init__`:

```python
from receiving_csi import (
    CsiSample,
    PacketInfo,
    NexmonCsiParser,
    parse_nexmon_payload,
    listen_udp,
    read_pcap_stream,
)
```

The imports for parser and receiver functions are lazy. `__init__.py` defines
`__getattr__`, so importing only the dataclasses does not immediately import
NumPy, socket receiver code, or parser internals.

## The `PacketInfo` Model

`PacketInfo` stores capture and network metadata around a UDP payload:

```python
@dataclass(frozen=True)
class PacketInfo:
    timestamp_sec: int | None = None
    timestamp_subsec: int | None = None
    timestamp_resolution: str = "us"
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
```

When data comes from pcap, the packet timestamp and IP/UDP addresses are filled
from the pcap packet and IPv4/UDP headers.

When data comes from raw UDP, only the source IP, source port, and destination
port are known:

```python
packet = PacketInfo(src_ip=address[0], src_port=address[1], dst_port=port)
```

## The `CsiSample` Model

`CsiSample` stores one parsed NexmonCSI sample:

```python
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

The dataclass is frozen. Code that receives a sample should treat it as an
immutable event. If downstream code needs a transformed version, create a new
object or store derived values separately.

The `csi` field is typed as `Any` in the dataclass to keep the model lightweight,
but the parser currently returns a NumPy array:

```python
sample.csi.dtype == np.complex64
sample.csi.shape == (64,)   # 20 MHz
sample.csi.shape == (128,)  # 40 MHz
sample.csi.shape == (256,)  # 80 MHz
```

## How pcap Reading Works

`PcapStreamReader` is an incremental reader for classic libpcap streams.

It reads:

1. A 24-byte global pcap header.
2. Repeated 16-byte packet headers.
3. `caplen` bytes of packet data for each packet.

The reader supports these pcap magic values:

| Magic bytes | Endian | Timestamp resolution |
| --- | --- | --- |
| `d4 c3 b2 a1` | little | microseconds |
| `a1 b2 c3 d4` | big | microseconds |
| `4d 3c b2 a1` | little | nanoseconds |
| `a1 b2 3c 4d` | big | nanoseconds |

If the input looks like tcpdump text output instead of binary pcap, it raises a
specific error telling the user to use:

```bash
tcpdump -U -s 0 -w -
```

This catches a common mistake: running tcpdump without `-w -` produces text
lines, not parseable pcap bytes.

## Supported pcap Link Types

`iter_udp_payloads` asks `_extract_ipv4` to interpret each packet according to
the pcap global header link type.

Supported link types:

| Link type | Meaning in this project |
| --- | --- |
| `1` | Ethernet. |
| `101` | Raw IPv4. |
| `113` | Linux cooked capture v1. |
| `276` | Linux cooked capture v2. |
| `0` | BSD null loopback. |

Unsupported link types are skipped by `iter_udp_payloads` because the extraction
error is caught for each packet.

## How UDP Extraction Works

For every pcap packet:

1. The project extracts an IPv4 packet from the link-layer frame.
2. It checks that the IPv4 version is `4`.
3. It calculates the IPv4 header length from the IHL field.
4. It requires protocol number `17`, which means UDP.
5. It reads total length from the IPv4 header.
6. It reads source port, destination port, UDP length, and checksum from the UDP
   header.
7. It validates the UDP length.
8. It yields only payloads whose destination port matches the requested port.

By default, the destination port is `5500`.

## How NexmonCSI Payload Parsing Works

`NexmonCsiParser.parse(payload, packet)` handles one UDP payload.

The parser:

1. Rejects payloads shorter than 16 bytes.
2. Looks for the NexmonCSI magic value `0x1111`.
3. Allows two magic placements:
   - payload starts with two bytes: `11 11`
   - payload starts with four bytes: `11 11 11 11`, treated as a legacy case
4. Tries the extended header layout.
5. Tries the compact header layout.
6. Infers bandwidth from the remaining CSI byte length.
7. Unpacks CSI bytes into `np.complex64`.
8. Returns a `CsiSample`.

The parser tries the extended header first. If that layout does not match a
known CSI byte length, it tries the compact layout.

## Compact Header Layout

The compact layout uses a 16-byte header when the magic offset is `0`.

```text
offset + 0   2 bytes   magic: 0x1111
offset + 2   6 bytes   transmitter MAC address
offset + 8   2 bytes   sequence number, little-endian
offset + 10  2 bytes   CSS field, little-endian
offset + 12  2 bytes   chanspec, little-endian
offset + 14  2 bytes   chip version, little-endian
offset + 16  ...       raw CSI bytes
```

The implementation:

```python
mac = _format_mac(payload[offset + 2 : offset + 8])
seq, css, chanspec, chip_version = struct.unpack_from("<HHHH", payload, offset + 8)
core = css & 0x7
spatial_stream = (css >> 3) & 0x7
```

## Extended Header Layout

The extended layout uses an 18-byte header when the magic offset is `0`.

```text
offset + 0   2 bytes   magic: 0x1111
offset + 2   1 byte    RSSI, signed
offset + 3   1 byte    frame control
offset + 4   6 bytes   transmitter MAC address
offset + 10  2 bytes   sequence number, little-endian
offset + 12  2 bytes   CSS field, little-endian
offset + 14  2 bytes   chanspec, little-endian
offset + 16  2 bytes   chip version, little-endian
offset + 18  ...       raw CSI bytes
```

The implementation:

```python
rssi = struct.unpack_from("<b", payload, offset + 2)[0]
frame_control = payload[offset + 3]
mac = _format_mac(payload[offset + 4 : offset + 10])
seq, css, chanspec, chip_version = struct.unpack_from("<HHHH", payload, offset + 10)
core = css & 0x7
spatial_stream = (css >> 3) & 0x7
```

## Bandwidth And Tone Count

The parser determines bandwidth from the number of raw CSI bytes after the
header:

| CSI bytes | 32-bit words | Bandwidth |
| --- | ---: | ---: |
| `64 * 4 = 256` | 64 | 20 MHz |
| `128 * 4 = 512` | 128 | 40 MHz |
| `256 * 4 = 1024` | 256 | 80 MHz |

This mapping is stored in `receiving_csi/nexmon.py`:

```python
_TONES_BY_CSI_BYTES = {
    64 * 4: (20, 64),
    128 * 4: (40, 128),
    256 * 4: (80, 256),
}
```

If the byte count does not match one of these values, parsing fails with
`NexmonCsiError`.

## CSI Unpacking

The `bcm4366c0` chip stores each complex CSI value in a packed 32-bit word. The
project unpacks that word using Nexmon's packed float-like format 1 parameters:

```text
nbits = 10
nman  = 12
nexp  = 6
```

The project reads the raw CSI bytes as little-endian unsigned 32-bit integers:

```python
packed = np.frombuffer(raw_csi, dtype="<u4")
```

Then it extracts:

- real mantissa
- imaginary mantissa
- shared exponent
- real sign
- imaginary sign

The final array is:

```python
iq[:, 0].astype(np.float32) + 1j * iq[:, 1].astype(np.float32)
```

and the dtype is forced to:

```python
np.complex64
```

## Error Handling

There are two project-specific error types:

```python
class PcapError(ValueError):
    """Raised for unsupported or malformed pcap streams."""


class NexmonCsiError(ValueError):
    """Raised when a UDP payload is not a supported NexmonCSI sample."""
```

High-level receiver functions accept an optional `error_callback`.

For pcap streams:

```python
read_pcap_stream(stream, callback, error_callback=handle_error)
```

For raw UDP:

```python
listen_udp("0.0.0.0", 5500, callback, error_callback=handle_error)
```

If a Nexmon payload cannot be parsed, the receiver reports the exception through
`error_callback` and keeps going.

For malformed pcap global headers, `read_pcap_stream` reports the error and
returns because the stream cannot be interpreted.

## Example: Store Amplitude Features

This example reads a pcap file, computes simple amplitude features, and stores
one JSON object per sample:

```python
import json
import numpy as np

from receiving_csi import read_pcap_stream


def sample_to_features(sample):
    amplitude = np.abs(sample.csi)
    return {
        "seq": sample.seq,
        "mac": sample.mac,
        "core": sample.core,
        "spatial_stream": sample.spatial_stream,
        "bandwidth_mhz": sample.bandwidth_mhz,
        "num_tones": int(sample.csi.shape[0]),
        "amplitude_mean": float(amplitude.mean()),
        "amplitude_std": float(amplitude.std()),
        "amplitude_max": float(amplitude.max()),
    }


with open("capture.pcap", "rb") as input_stream, open("features.jsonl", "w") as output:
    def handle_sample(sample):
        output.write(json.dumps(sample_to_features(sample)) + "\n")

    read_pcap_stream(input_stream, handle_sample)
```

## Example: Keep Full CSI In NumPy Files

This example writes one compressed NumPy archive containing CSI and selected
metadata:

```python
import numpy as np

from receiving_csi import read_pcap_stream


all_csi = []
seq = []
core = []
spatial = []


def handle_sample(sample):
    all_csi.append(sample.csi)
    seq.append(sample.seq)
    core.append(sample.core)
    spatial.append(sample.spatial_stream)


with open("capture.pcap", "rb") as stream:
    read_pcap_stream(stream, handle_sample)

np.savez_compressed(
    "capture_csi.npz",
    csi=np.asarray(all_csi),
    seq=np.asarray(seq, dtype=np.uint16),
    core=np.asarray(core, dtype=np.uint8),
    spatial_stream=np.asarray(spatial, dtype=np.uint8),
)
```

This assumes all samples have the same number of tones. If a capture mixes
bandwidths, group samples by `sample.bandwidth_mhz` before stacking.

## Example: Parse Raw Payload Bytes

If another component has already extracted UDP payload bytes, use the parser
directly:

```python
from receiving_csi import PacketInfo, parse_nexmon_payload


packet = PacketInfo(
    src_ip="192.168.1.1",
    dst_ip="192.168.1.100",
    src_port=5500,
    dst_port=5500,
)

sample = parse_nexmon_payload(raw_payload_bytes, packet=packet)
print(sample.csi.shape)
```

## Important Assumptions

The code makes several assumptions that are important during audits:

- The pcap stream is classic libpcap, not pcapng.
- The UDP payload itself contains the NexmonCSI sample.
- The destination UDP port identifies relevant CSI traffic.
- CSI byte length is enough to infer 20, 40, or 80 MHz bandwidth.
- The Broadcom packed CSI format is the `bcm4366c0` format described in the
  parser docstring.
- The compact or extended header appears at a supported magic offset.
- The receiver callback is responsible for all persistence and downstream
  processing.

## Where To Look For Specific Behavior

Use this map when auditing:

| Question | File/function |
| --- | --- |
| How does CLI argument parsing work? | `receiving_csi/__main__.py::main` |
| What does JSONL output contain? | `receiving_csi/__main__.py::_summary` |
| How are callbacks called from pcap? | `receiving_csi/receivers.py::read_pcap_stream` |
| How does the UDP listener run? | `receiving_csi/receivers.py::listen_udp` |
| How is binary pcap parsed? | `receiving_csi/pcap.py::PcapStreamReader` |
| Which pcap link types are supported? | `receiving_csi/pcap.py::_extract_ipv4` |
| How are UDP payloads filtered? | `receiving_csi/pcap.py::iter_udp_payloads` |
| How is magic detected? | `receiving_csi/nexmon.py::_detect_magic_offsets` |
| How are Nexmon headers parsed? | `receiving_csi/nexmon.py::_parse_compact_header`, `_parse_extended_header` |
| How is bandwidth inferred? | `receiving_csi/nexmon.py::_bandwidth_from_length` |
| How are CSI words unpacked? | `receiving_csi/nexmon.py::unpack_bcm4366c0` |

