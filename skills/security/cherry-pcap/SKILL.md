---
name: cherry-pcap
description: "Analyze authorized PCAP/PCAPNG files or short live captures with the bundled C++ Cherry PCAP sensor and produce a bounded network-forensics report."
version: 1.0.0
author: paddman
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, pcap, packet-capture, network-forensics, incident-response, dns, tcp, cpp]
    related_skills: [systematic-debugging, plan]
---

# Cherry PCAP

Use this skill when the user asks Hermes to inspect an authorized packet capture,
summarize network traffic, investigate suspicious connections, review DNS
activity, or perform a short live capture on a system they are permitted to
monitor.

The bundled native sensor is located at `native/cherry_pcap`. It emits bounded
JSON metadata rather than packet payloads, which keeps large captures from
flooding the model context.

## Safety and scope

- Analyze only captures and interfaces the user owns or is explicitly authorized
  to monitor.
- Prefer an existing offline PCAP/PCAPNG file. Live capture requires explicit
  authorization and a finite `--duration` or `--limit`.
- Do not upload packet captures to external services unless the user explicitly
  requests it and understands the privacy impact.
- Treat every alert as a heuristic requiring validation. A scanner, NAT gateway,
  monitoring platform, or busy resolver can resemble hostile behavior.
- Do not expose packet payloads, credentials, session tokens, or personal data in
  the final report.

## Locate and build the sensor

Resolve the repository root first:

```bash
REPO_ROOT="$(git rev-parse --show-toplevel)"
```

On Linux or macOS, build with:

```bash
bash "$REPO_ROOT/native/cherry_pcap/build.sh"
BIN="$REPO_ROOT/native/cherry_pcap/build/cherry-pcap"
```

On Windows PowerShell, build with:

```powershell
$RepoRoot = (git rev-parse --show-toplevel).Trim()
& "$RepoRoot\native\cherry_pcap\build.ps1" -Configuration Release
$Bin = "$RepoRoot\native\cherry_pcap\build\Release\cherry-pcap.exe"
if (-not (Test-Path $Bin)) {
    $Bin = "$RepoRoot\native\cherry_pcap\build\cherry-pcap.exe"
}
```

If configuration fails, install the platform dependency named in
`native/cherry_pcap/README.md`: libpcap development headers on Linux/macOS or the
Npcap runtime and SDK on Windows.

## Offline analysis workflow

### 1. Preserve evidence context

Before analysis, record the file path, size, and a cryptographic hash. Do not
modify the original capture.

Linux/macOS:

```bash
PCAP="/path/to/capture.pcapng"
stat "$PCAP"
sha256sum "$PCAP"
```

Windows PowerShell:

```powershell
$Pcap = "C:\path\to\capture.pcapng"
Get-Item $Pcap | Format-List FullName,Length,CreationTimeUtc,LastWriteTimeUtc
Get-FileHash $Pcap -Algorithm SHA256
```

### 2. Run a bounded first pass

Use a packet limit for an unfamiliar or very large capture. Write JSON to a file
instead of printing it into the conversation.

```bash
REPORT="${PCAP%.*}.cherry-pcap.json"
"$BIN" \
  --file "$PCAP" \
  --limit 500000 \
  --top 25 \
  --flows 40 \
  --max-flows 250000 \
  --pretty \
  --output "$REPORT"
```

Read the report file with the file tool. Do not load the original PCAP into the
model context.

### 3. Check capture quality before interpreting traffic

Review these fields first:

- `capture.packets_seen`, capture time range, BPF filter, and datalink type
- `summary.parsed_packets` versus `summary.total_packets`
- `summary.truncated_packets`
- `summary.unsupported_link_packets`
- `summary.dropped_new_flows`

If parse failures, truncation, or dropped flows are material, state that the
results are partial before discussing threats.

### 4. Run focused passes when needed

Use a BPF filter based on first-pass findings. Keep the scope reproducible by
recording the exact command.

DNS traffic:

```bash
"$BIN" --file "$PCAP" --filter "udp port 53" --top 50 --flows 50 \
  --pretty --output "${PCAP%.*}.dns.json"
```

TCP connection attempts:

```bash
"$BIN" --file "$PCAP" --filter "tcp[tcpflags] & tcp-syn != 0" \
  --scan-threshold 50 --pretty --output "${PCAP%.*}.syn.json"
```

One suspected host:

```bash
"$BIN" --file "$PCAP" --filter "host 10.10.10.25" \
  --top 50 --flows 100 --pretty --output "${PCAP%.*}.host.json"
```

Do not assume every libpcap build accepts identical advanced BPF syntax. If a
filter is rejected, simplify it and record the limitation.

## Live capture workflow

Use live capture only after the user explicitly identifies an authorized
interface or asks to list interfaces.

List interfaces:

```bash
"$BIN" --list-interfaces --pretty
```

Default to a short, finite capture such as 60 seconds:

```bash
sudo "$BIN" \
  --interface eth0 \
  --duration 60 \
  --filter "ip or ip6" \
  --top 25 \
  --flows 40 \
  --pretty \
  --output cherry-live-60s.json
```

Do not start an indefinite capture by default. Explain when elevated privileges
or Linux capture capabilities are required rather than silently weakening host
security.

## Interpret the report

Analyze in this order:

1. **Scope and reliability**: source, duration, filters, packet counts, parser
   coverage, truncation, and dropped-flow limits.
2. **Traffic composition**: protocols, top sources, destinations, and destination
   ports.
3. **DNS behavior**: top query names and high-volume sources. DNS names alone do
   not establish maliciousness.
4. **Flow evidence**: identify the exact source, destination, ports, protocol,
   packets, bytes, and TCP flags supporting each observation.
5. **Heuristic alerts**: explain the threshold and plausible benign causes.
6. **Next validation step**: suggest a narrower BPF pass, endpoint log review,
   asset-owner confirmation, or enrichment from an approved internal source.

`tcp_syn_scan` counts unique destination-IP-and-port targets contacted with SYN
without ACK by one source. `dns_query_volume` counts DNS questions from one
source inside the analyzed capture. Both are capture-relative signals, not
incident verdicts.

## Final response format

Provide a compact evidence-led report with these sections:

```markdown
# PCAP Analysis

## Scope and confidence
- Capture, hash, analyzed packet range, filters, and notable limitations

## Key findings
- Finding with exact IPs, ports, protocol, counts, and supporting flow evidence

## Heuristic alerts
- Alert, configured threshold, observed value, confidence, and benign alternatives

## Recommended validation
- Focused capture query or host/network evidence needed next

## Commands used
- Exact reproducible commands, excluding secrets
```

Separate facts observed in the report from inferences. Never label a host
compromised solely because it crossed a heuristic threshold.
