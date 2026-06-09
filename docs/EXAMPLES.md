# Examples

This file shows common ways to use `receiving-csi` in real capture workflows.

The examples assume:

- NexmonCSI is already running on the router or device.
- CSI is being emitted as UDP traffic on destination port `5500`.
- The local project has been installed:

```bash
python -m pip install -e .
```

The parsed CSI values are returned as NumPy arrays:

```python
sample.csi.dtype
# dtype('complex64')

sample.csi.shape
# (64,) for 20 MHz
# (128,) for 40 MHz
# (256,) for 80 MHz
```

## 1. Read From A Saved pcap File

Use this when you already have a `.pcap` file on disk.

```python
from receiving_csi import read_pcap_stream


def handle_sample(sample):
    print("sequence:", sample.seq)
    print("mac:", sample.mac)
    print("core:", sample.core)
    print("spatial stream:", sample.spatial_stream)
    print("bandwidth:", sample.bandwidth_mhz)
    print("CSI dtype:", sample.csi.dtype)
    print("CSI shape:", sample.csi.shape)
    print("first CSI value:", sample.csi[0])
    print()


with open("capture.pcap", "rb") as stream:
    read_pcap_stream(stream, handle_sample, port=5500)
```

The callback receives one `CsiSample` at a time. The full CSI vector is available
as `sample.csi`, which is a NumPy `complex64` array.

## 2. Read From A Saved pcap And Store NumPy Arrays

Use this when you want to convert a pcap file into a NumPy archive.

```python
import numpy as np

from receiving_csi import read_pcap_stream


csi_arrays = []
sequence_numbers = []
cores = []
spatial_streams = []
bandwidths = []
mac_addresses = []


def handle_sample(sample):
    csi_arrays.append(sample.csi)
    sequence_numbers.append(sample.seq)
    cores.append(sample.core)
    spatial_streams.append(sample.spatial_stream)
    bandwidths.append(sample.bandwidth_mhz)
    mac_addresses.append(sample.mac)


with open("capture.pcap", "rb") as stream:
    read_pcap_stream(stream, handle_sample, port=5500)

np.savez_compressed(
    "capture_arrays.npz",
    csi=np.asarray(csi_arrays),
    seq=np.asarray(sequence_numbers, dtype=np.uint16),
    core=np.asarray(cores, dtype=np.uint8),
    spatial_stream=np.asarray(spatial_streams, dtype=np.uint8),
    bandwidth_mhz=np.asarray(bandwidths, dtype=np.uint8),
    mac=np.asarray(mac_addresses),
)
```

This works directly when all samples have the same bandwidth. If one capture
contains mixed bandwidths, group by `sample.bandwidth_mhz` before stacking into
a single NumPy array.

## 3. Read A Live pcap Stream Over SSH From A Router

Use this when the router can run `tcpdump` and you want to process the live pcap
stream on your computer.

```bash
ssh admin@ROUTER 'tcpdump -i wlan0 -U -s 0 -w - udp dst port 5500' \
  | python -m receiving_csi pcap-stdin
```

Replace:

- `admin` with the router SSH username.
- `ROUTER` with the router hostname or IP address.
- `wlan0` with the interface that sees NexmonCSI UDP packets.
- `5500` if your NexmonCSI stream uses a different destination port.

The important part is `-w -`. That makes `tcpdump` write binary pcap bytes to
stdout. Without it, `tcpdump` prints text and the parser cannot read it.

## 4. Read A Live SSH pcap Stream And Print JSONL Summaries

Use this when you want line-oriented logs that another process can consume.

```bash
ssh admin@ROUTER 'tcpdump -i wlan0 -U -s 0 -w - udp dst port 5500' \
  | python -m receiving_csi pcap-stdin --dump-jsonl
```

Each parsed sample prints one JSON object. The JSON output includes metadata and
simple amplitude statistics, not the full complex CSI array.

Example shape:

```json
{"seq": 7, "core": 1, "spatial_stream": 1, "bandwidth_mhz": 20, "mac": "00:11:22:33:44:55", "chanspec": 4660, "chip_version": 17254, "rssi": null, "frame_control": null, "header_layout": "compact", "src_ip": "10.10.10.10", "dst_ip": "255.255.255.255", "src_port": 5500, "dst_port": 5500, "timestamp_sec": 1, "timestamp_subsec": 2, "timestamp_resolution": "us", "csi_shape": [64], "amplitude_mean": 0.0, "amplitude_max": 0.0}
```

## 5. Use As A Python Module With A Live SSH pcap Stream

Use this when you want your own Python program to SSH into the router, run
`tcpdump`, and receive parsed `CsiSample` objects with NumPy CSI arrays.

```python
import subprocess

from receiving_csi import read_pcap_stream


ROUTER = "admin@ROUTER"
INTERFACE = "wlan0"
PORT = 5500


def handle_sample(sample):
    csi = sample.csi

    print("seq:", sample.seq)
    print("mac:", sample.mac)
    print("bandwidth:", sample.bandwidth_mhz)
    print("numpy dtype:", csi.dtype)
    print("numpy shape:", csi.shape)
    print("mean amplitude:", abs(csi).mean())
    print()


def handle_error(exc):
    print("warning:", exc)


command = [
    "ssh",
    ROUTER,
    f"tcpdump -i {INTERFACE} -U -s 0 -w - udp dst port {PORT}",
]

process = subprocess.Popen(command, stdout=subprocess.PIPE)

try:
    assert process.stdout is not None
    read_pcap_stream(
        process.stdout,
        handle_sample,
        port=PORT,
        error_callback=handle_error,
    )
finally:
    process.terminate()
    process.wait(timeout=5)
```

This is the module form of the shell pipeline:

```bash
ssh admin@ROUTER 'tcpdump -i wlan0 -U -s 0 -w - udp dst port 5500' \
  | python -m receiving_csi pcap-stdin
```

The difference is that your Python program receives the parsed object directly:

```python
sample.csi
```

That object is already a NumPy complex array and can be passed directly to
feature extraction, model input code, plotting code, or storage code.

## 6. Use As A Python Module And Batch Live Samples

Use this when downstream code wants batches of NumPy arrays instead of one
sample at a time.

```python
import subprocess

import numpy as np

from receiving_csi import read_pcap_stream


ROUTER = "admin@ROUTER"
INTERFACE = "wlan0"
PORT = 5500
BATCH_SIZE = 128

batch = []


def consume_batch(csi_batch):
    print("batch shape:", csi_batch.shape)
    print("batch dtype:", csi_batch.dtype)


def handle_sample(sample):
    batch.append(sample.csi)

    if len(batch) >= BATCH_SIZE:
        csi_batch = np.stack(batch)
        batch.clear()
        consume_batch(csi_batch)


command = [
    "ssh",
    ROUTER,
    f"tcpdump -i {INTERFACE} -U -s 0 -w - udp dst port {PORT}",
]

process = subprocess.Popen(command, stdout=subprocess.PIPE)

try:
    assert process.stdout is not None
    read_pcap_stream(process.stdout, handle_sample, port=PORT)
finally:
    process.terminate()
    process.wait(timeout=5)
```

This assumes every sample in a batch has the same CSI shape. If your stream can
mix 20, 40, and 80 MHz captures, batch by shape:

```python
batches_by_shape = {}


def handle_sample(sample):
    shape = sample.csi.shape
    current = batches_by_shape.setdefault(shape, [])
    current.append(sample.csi)

    if len(current) >= 128:
        csi_batch = np.stack(current)
        current.clear()
        consume_batch(csi_batch)
```

## 7. Listen For Raw UDP Locally

Use this when the NexmonCSI UDP payloads are sent directly to this computer
instead of being wrapped in a pcap stream over SSH.

```bash
python -m receiving_csi udp --host 0.0.0.0 --port 5500
```

Module form:

```python
from receiving_csi import listen_udp


def handle_sample(sample):
    print(sample.packet.src_ip, sample.seq, sample.csi.shape)


listen_udp("0.0.0.0", 5500, handle_sample)
```

This path expects the UDP datagram payload itself to be a NexmonCSI payload. It
does not parse pcap bytes.

## 8. Convert Samples To Simple ML Features

Use this when a model needs real-valued features instead of complex CSI.

```python
import numpy as np

from receiving_csi import read_pcap_stream


features = []
labels = []


def handle_sample(sample):
    csi = sample.csi
    amplitude = np.abs(csi)
    phase = np.angle(csi)

    feature_vector = np.concatenate(
        [
            amplitude,
            phase,
            np.array(
                [
                    sample.core,
                    sample.spatial_stream,
                    sample.bandwidth_mhz,
                ],
                dtype=np.float32,
            ),
        ]
    )

    features.append(feature_vector.astype(np.float32))
    labels.append("unlabeled")


with open("capture.pcap", "rb") as stream:
    read_pcap_stream(stream, handle_sample)

X = np.stack(features)
y = np.asarray(labels)

print(X.shape)
print(y.shape)
```

This is only a starting point. Real pipelines usually need calibration,
filtering, synchronization, labels, and train/test split logic outside this
package.

## 9. Error Handling While Streaming

Use an error callback when live data may contain unrelated UDP packets,
truncated packets, or unsupported payloads.

```python
from receiving_csi import read_pcap_stream


def handle_sample(sample):
    print("sample:", sample.seq)


def handle_error(exc):
    print("skipped:", exc)


with open("capture.pcap", "rb") as stream:
    read_pcap_stream(
        stream,
        handle_sample,
        port=5500,
        error_callback=handle_error,
    )
```

The receiver reports bad NexmonCSI payloads through `handle_error` and keeps
reading the stream.

