# Single-File Nexmon CSI Rebuild Plan

## Summary

Rebuild the project into one executable `main.py`. The new app focuses on live capture from multiple SSH pcap stdout streams, pcap + Nexmon header parsing, grouping packets by sequence/core, and emitting the final JSON format to files and/or a TCP server.

The rebuild does not preserve the old package architecture, callback API, NumPy CSI unpacking, examples, or helper modules. It is a standalone Python script using the standard library.

## Key Changes

- Replace the package workflow with one executable `main.py`.
- Accept multiple SSH router targets.
- For each target, query router MAC with `ssh <target> 'cat /sys/class/net/<iface>/address'`.
- Use that router MAC as `device_id`.
- Start capture with `ssh <target> 'tcpdump -i <iface> -U -s 0 -w - udp dst port <port>'`.
- Parse each SSH stdout stream concurrently.
- Keep classic pcap stream parsing and Ethernet/IPv4/UDP extraction for tcpdump pcap output.
- Parse Nexmon extended headers only.
- Parse sequence from upper 12 bits of sequence-control.
- Parse core from CSS bits.
- Decode channel from Broadcom `chanspec`.
- Do not implement CSI unpacking.
- Convert each 32-bit CSI word into one 32-character ASCII bit string.
- Group packets by `device_id`, `seq`, bandwidth, and channel.
- Assume all expected cores arrive; no timeout/drop/partial-output behavior is required.

## Output

Final JSON shape:

```json
{
  "device_id": "02:1A:2B:3C:4D:5E",
  "seq": 1,
  "timestamp": 1716280000123456,
  "bw": 20,
  "ch": 157,
  "agc": [0, 0, 0, 0],
  "rssi": [2, 3, 4, 5],
  "csi": {
    "c0": ["01010101010101010101010101010101"],
    "c1": [],
    "c2": [],
    "c3": []
  }
}
```

- File output writes numbered JSON files, e.g. `sample_0001.json`.
- TCP output runs as a server and sends newline-delimited JSON records to connected clients.
- File-only, TCP-only, and combined outputs are supported.

## CLI

- `--router TARGET|ID=TARGET`, repeatable
- `--interface <name>`, default `wlan0`
- `--port <udp-port>`, default `5500`
- `--expected-cores <n>`, default `4`
- `--output-dir <path>`, optional
- `--tcp-listen <host:port>`, optional
- `--count <n>`, optional stop condition

## Test Plan

- Unit test pcap parsing from chunky binary streams.
- Unit test rejection of tcpdump text output.
- Unit test UDP payload extraction for destination port `5500`.
- Unit test Nexmon header parsing: magic, RSSI, MAC, sequence, core, bandwidth, channel, and raw CSI bit strings.
- Unit test grouped JSON output for four cores.
- Unit test file sink writes the expected JSON file.
- Unit test TCP server streams JSONL to a connected client.
- Integration-style test using fake SSH subprocesses or local fixtures instead of real routers.

## Assumptions

- Router MAC discovery uses SSH and must succeed before capture starts.
- Missing cores are not expected, so no grouping timeout is implemented.
- CSI values are raw packed 32-bit words encoded as fixed-width bit strings.
- Runtime dependency is standard library only.
