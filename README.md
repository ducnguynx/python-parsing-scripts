# receiving-csi

Python receiver and parser for live NexmonCSI streams from an Asus RT-AC86U.

The recommended router-side command is a binary pcap stream:

```bash
ssh admin@ROUTER 'tcpdump -i wlan0 -U -s 0 -w - udp dst port 5500' \
  | python -m receiving_csi pcap-stdin
```

The parser calls your callback with a `CsiSample` object. CSI values are left as
a NumPy complex array so downstream code can convert to JSON, tensors, files, or
whatever the ML pipeline needs.

```python
from receiving_csi import read_pcap_stream

def handle_sample(sample):
    print(sample.seq, sample.core, sample.spatial_stream, sample.csi.shape)

with open("capture.pcap", "rb") as stream:
    read_pcap_stream(stream, handle_sample)
```

For a raw UDP relay, bind directly on the computer:

```bash
python -m receiving_csi udp --host 0.0.0.0 --port 5500
```

Only NumPy is used as a runtime dependency. No Nexmon CSI decoder library is
required.
