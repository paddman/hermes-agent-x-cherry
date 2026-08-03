# Cherry PCAP C++ Sensor

A small native network-forensics component for Hermes Agent. It reads offline
PCAP/PCAPNG captures or a live interface through libpcap/Npcap, reduces packets
to metadata, and emits bounded JSON that an agent can inspect without dumping
raw payloads into its context window.

This lives under `native/` deliberately. Hermes can invoke it through the
existing terminal tool and the bundled `cherry-pcap` skill, so the capability
does not add another permanent model-tool schema to every conversation.

## What it does

- C++17 parser and flow aggregator
- Offline PCAP/PCAPNG input through libpcap
- Live capture through libpcap or Npcap
- BPF filters and packet/time limits
- Ethernet, VLAN/QinQ, Linux cooked v1/v2, raw IP, and loopback framing
- IPv4 and IPv6, including common IPv6 extension headers and fragments
- TCP, UDP, ICMP, ICMPv6, ESP/AH identification
- DNS query-name extraction for UDP/53
- Top sources, destinations, destination ports, DNS names, and flows
- Basic SYN-scan and high DNS-volume heuristics
- JSON-only report output suitable for agent ingestion

It does **not** reconstruct TCP streams, decrypt TLS, extract files, inspect
application payloads beyond DNS question names, or claim that a heuristic is a
confirmed incident. Those capabilities belong in later analysis layers; this
component intentionally stays focused on metadata extraction and bounded
aggregation.

## Build

### Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libpcap-dev
bash native/cherry_pcap/build.sh
```

### RHEL / Rocky / AlmaLinux / Fedora

```bash
sudo dnf install -y gcc-c++ cmake pkgconf-pkg-config libpcap-devel
bash native/cherry_pcap/build.sh
```

### Windows with Npcap

1. Install the Npcap runtime.
2. Download and extract the Npcap SDK.
3. Set `PCAP_ROOT` to the SDK directory containing `Include` and `Lib`.
4. Build from a Visual Studio Developer PowerShell:

```powershell
$env:PCAP_ROOT = "C:\SDKs\npcap-sdk"
.\native\cherry_pcap\build.ps1 -Configuration Release
```

The resulting executable is normally one of:

```text
native/cherry_pcap/build/cherry-pcap
native/cherry_pcap/build/Release/cherry-pcap.exe
```

### Manual CMake

```bash
cmake -S native/cherry_pcap -B native/cherry_pcap/build -DCMAKE_BUILD_TYPE=Release
cmake --build native/cherry_pcap/build --parallel
ctest --test-dir native/cherry_pcap/build --output-on-failure
```

## Usage

### Analyze a capture

```bash
native/cherry_pcap/build/cherry-pcap \
  --file incident.pcap \
  --pretty \
  --output incident-report.json
```

### Restrict a large capture

```bash
native/cherry_pcap/build/cherry-pcap \
  --file edge-router.pcapng \
  --filter "tcp or udp port 53" \
  --limit 500000 \
  --top 30 \
  --flows 50 \
  --output dns-network-report.json
```

### List capture interfaces

```bash
native/cherry_pcap/build/cherry-pcap --list-interfaces --pretty
```

### Capture live traffic

Linux usually requires root or the appropriate capture capability. Windows
requires Npcap and may require an elevated shell.

```bash
sudo native/cherry_pcap/build/cherry-pcap \
  --interface eth0 \
  --duration 60 \
  --promiscuous \
  --filter "ip or ip6" \
  --pretty \
  --output live-60s.json
```

Run live capture only on systems and networks you own or are explicitly
authorized to monitor.

## Report shape

```json
{
  "schema_version": 1,
  "engine": "cherry-pcap-cpp",
  "capture": {
    "mode": "offline",
    "source": "incident.pcap",
    "bpf_filter": "",
    "datalink_value": 1,
    "datalink_name": "EN10MB",
    "packets_seen": 12345,
    "first_packet_epoch": 1785600000.123456,
    "last_packet_epoch": 1785600060.654321,
    "elapsed_wall_seconds": 0.842
  },
  "summary": {
    "total_packets": 12345,
    "parsed_packets": 12290,
    "truncated_packets": 4,
    "dns_queries": 411,
    "dropped_new_flows": 0
  },
  "protocols": [],
  "top_sources": [],
  "top_destinations": [],
  "top_destination_ports": [],
  "top_dns_queries": [],
  "alerts": [],
  "top_flows": []
}
```

The report is bounded by `--top`, `--flows`, and `--max-flows`. The analyzer
counts every packet it sees but does not emit every packet, preventing a large
capture from exhausting the model context.

## Detection notes

`tcp_syn_scan` counts unique `destination IP:port` targets reached by TCP SYN
packets without ACK from one source. `dns_query_volume` counts DNS questions
from one source within the analyzed capture. Thresholds are capture-relative,
not universal truth:

```bash
cherry-pcap --file sample.pcap \
  --scan-threshold 50 \
  --dns-threshold 1000 \
  --output report.json
```

Set either threshold to `0` to disable that heuristic. Validate alerts against
asset roles, capture duration, NAT, vulnerability scanners, and normal service
behavior before escalating anything.

## Tests

The core packet parser and analyzer tests do not require libpcap at runtime.
They cover IPv4/TCP SYN parsing, VLAN DNS extraction, truncated frames, scan
aggregation, and JSON escaping:

```bash
ctest --test-dir native/cherry_pcap/build --output-on-failure
```

## License

MIT, matching the parent repository. New Cherry PCAP code is copyright © 2026
paddman. Existing Hermes Agent code and notices remain under their original
copyrights and license terms.
