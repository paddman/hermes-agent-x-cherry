<div align="center">

# 🍒 Cherry Agent

**A security-ready, self-improving AI agent for local, cloud, and multi-channel automation.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Main CI](https://github.com/paddman/hermes-agent-x-cherry/actions/workflows/ci.yml/badge.svg)](https://github.com/paddman/hermes-agent-x-cherry/actions/workflows/ci.yml)
[![Cherry PCAP C++](https://github.com/paddman/hermes-agent-x-cherry/actions/workflows/cherry-pcap-cpp.yml/badge.svg)](https://github.com/paddman/hermes-agent-x-cherry/actions/workflows/cherry-pcap-cpp.yml)
[![Python 3.11-3.13](https://img.shields.io/badge/Python-3.11--3.13-blue.svg)](pyproject.toml)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](native/cherry_pcap)

</div>

> [!IMPORTANT]
> **Cherry Agent is an independent fork and derivative work of [Hermes Agent](https://github.com/NousResearch/hermes-agent) by Nous Research.**
> The original MIT copyright and permission notice are preserved in [`LICENSE`](LICENSE).
> Cherry Agent is not affiliated with, sponsored by, or endorsed by Nous Research.

## What is Cherry Agent?

Cherry Agent is an extensible AI-agent platform built for practical automation, persistent memory, multi-agent delegation, messaging gateways, terminal work, and security operations.

This fork keeps the proven Hermes Agent runtime while adding Cherry-specific direction and components, including a native C++ packet-capture analyzer for bounded network-forensics workflows.

### Cherry additions

- **Cherry PCAP C++ sensor** for offline PCAP/PCAPNG analysis and bounded live capture
- Flow, protocol, DNS, talker, destination, and port summaries
- Basic SYN-scan, DNS-volume, and flow-capacity heuristics
- JSON output designed for safe ingestion by an AI agent
- A bundled `cherry-pcap` security skill with evidence-preservation and privacy guidance
- Cherry-focused security-agent development and branding

### Core agent capabilities

- Persistent conversation memory and cross-session search
- Skills that can be created and improved from experience
- CLI, TUI, desktop, API, and messaging-gateway operation
- Telegram, Discord, Slack, WhatsApp, Signal, Email, and other platform adapters
- Scheduled jobs and natural-language automation
- Isolated subagents for parallel work
- Local, Docker, SSH, Singularity, Modal, Daytona, and Vercel Sandbox terminal backends
- OpenAI-compatible model endpoints and multiple model providers
- Plugin and MCP integration

## Branding and compatibility

The public product name of this fork is **Cherry Agent**. Some runtime identifiers still retain their upstream names so the existing code, plugins, scripts, profiles, and user data continue to work.

| Area | Current identifier | Meaning |
|---|---|---|
| Product and fork | `Cherry Agent` | Cherry branding |
| Repository | `hermes-agent-x-cherry` | Fork source repository |
| Python project | `hermes-agent` | Retained for package compatibility |
| CLI command | `hermes` | Retained until a compatibility-safe CLI migration is completed |
| User data directory | `~/.hermes` | Retained to avoid breaking existing profiles |
| Existing environment/config keys | `HERMES_*` and Hermes config names | Retained where changing them would break users |
| Upstream service names | Nous Portal, Hermes upstream documentation | Their original names are preserved when referring to those actual services |

This distinction is deliberate. Replacing every occurrence of `Hermes` in documentation while the executable is still named `hermes` would produce attractive branding and unusable instructions, a familiar triumph of marketing over reality.

## Architecture

```text
CLI / TUI / Desktop / API / Messaging Platforms
                    |
                    v
             Cherry Agent Runtime
        +-----------+------------+
        |                        |
        v                        v
 Models and Providers       Tools and Skills
        |                        |
        +-----------+------------+
                    |
        Memory / Sessions / Scheduling
                    |
        Security and Native Components
                    |
            Cherry PCAP C++
```

## Install from this fork

The upstream one-line installer installs the upstream Hermes Agent release. To run **this Cherry fork**, clone this repository and install from its source tree.

### Linux, macOS, or WSL2

Requirements:

- Python 3.11, 3.12, or 3.13
- Git
- A C/C++ build toolchain only when building native components

```bash
git clone https://github.com/paddman/hermes-agent-x-cherry.git
cd hermes-agent-x-cherry

python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip uv
uv pip install -e ".[all]"

hermes setup
hermes
```

### Windows PowerShell

```powershell
git clone https://github.com/paddman/hermes-agent-x-cherry.git
Set-Location hermes-agent-x-cherry

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip uv
uv pip install -e ".[all]"

hermes setup
hermes
```

> [!NOTE]
> The command remains `hermes` in the current compatibility phase. The README uses the Cherry product name without pretending a `cherry` executable already exists.

## Common commands

```bash
hermes                 # Start the interactive agent
hermes setup           # Configure model providers, tools, and gateways
hermes model           # Select a model/provider
hermes tools           # Configure available tools
hermes config get      # Read configuration
hermes config set      # Change configuration
hermes gateway         # Run messaging gateways
hermes doctor          # Diagnose installation and configuration
hermes update          # Update a managed installation
```

## Cherry PCAP C++ security sensor

The native sensor lives in [`native/cherry_pcap`](native/cherry_pcap). It reads authorized packet captures through libpcap or Npcap and emits bounded metadata as JSON instead of dumping raw payloads into model context.

### Build on Ubuntu or Debian

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libpcap-dev
bash native/cherry_pcap/build.sh
```

### Analyze a capture

```bash
native/cherry_pcap/build/cherry-pcap \
  --file incident.pcapng \
  --limit 500000 \
  --top 30 \
  --flows 50 \
  --max-flows 250000 \
  --pretty \
  --output incident-report.json
```

### Capture a bounded live sample

```bash
sudo native/cherry_pcap/build/cherry-pcap \
  --interface eth0 \
  --duration 60 \
  --filter "ip or ip6" \
  --pretty \
  --output live-60s.json
```

Live capture must be used only on systems and networks you own or are explicitly authorized to monitor. For Windows/Npcap instructions and the complete report schema, read [`native/cherry_pcap/README.md`](native/cherry_pcap/README.md).

The bundled Hermes skill is located at [`skills/security/cherry-pcap/SKILL.md`](skills/security/cherry-pcap/SKILL.md).

## Security model

Cherry Agent can execute commands, access files, connect to remote systems, and process potentially sensitive network evidence. Treat it as privileged automation software.

- Use least-privilege accounts and narrowly scoped API tokens.
- Keep command approval enabled for risky operations.
- Prefer isolated Docker, SSH, or sandbox backends for untrusted tasks.
- Do not upload PCAP files, credentials, tokens, customer data, or private documents to external services without explicit authorization.
- Hash and preserve original evidence before analysis.
- Treat detections and LLM conclusions as hypotheses requiring validation.
- Review [`SECURITY.md`](SECURITY.md) before production deployment.

## Development

```bash
git clone https://github.com/paddman/hermes-agent-x-cherry.git
cd hermes-agent-x-cherry

python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip uv
uv pip install -e ".[all,dev]"

scripts/run_tests.sh
```

Build and test the C++ sensor separately:

```bash
bash native/cherry_pcap/build.sh
ctest --test-dir native/cherry_pcap/build --output-on-failure
```

Read [`AGENTS.md`](AGENTS.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md) before changing the agent core. The runtime intentionally keeps its core tool surface narrow; most new Cherry capabilities should be implemented as skills, plugins, MCP services, CLI commands, or native components invoked through existing tools.

## Documentation

- [Cherry PCAP C++ documentation](native/cherry_pcap/README.md)
- [Cherry PCAP security skill](skills/security/cherry-pcap/SKILL.md)
- [Security policy](SECURITY.md)
- [Contribution guide](CONTRIBUTING.md)
- [Developer instructions](AGENTS.md)
- [Upstream Hermes Agent documentation](https://hermes-agent.nousresearch.com/docs/), useful for compatibility features that Cherry has not documented separately yet

## Upstream attribution and MIT license

Cherry Agent includes and modifies software originally developed as **Hermes Agent** by **Nous Research**.

```text
Copyright (c) 2025 Nous Research
```

The upstream software is licensed under the MIT License. The complete original copyright notice, permission notice, warranty disclaimer, and liability disclaimer are preserved in [`LICENSE`](LICENSE). That file must remain included when distributing copies or substantial portions of this software.

Cherry-specific modifications and newly authored components may carry additional copyright notices from paddman and other contributors. Those additional notices do not remove or replace the original Nous Research notice.

The names **Nous Research**, **Hermes Agent**, and **Nous Portal** are used in this repository only for attribution, compatibility documentation, and identification of the actual upstream project or service. They are not Cherry Agent branding and do not imply endorsement.

Additional attribution information is recorded in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## License

This repository is distributed under the [MIT License](LICENSE), subject to the preserved upstream notices and any separately identified licenses for bundled third-party components.
