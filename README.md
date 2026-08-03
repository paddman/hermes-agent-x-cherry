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
| Preferred CLI command | `cherry` | Cherry-branded compatibility launcher |
| Legacy CLI command | `hermes` | Still supported for scripts and existing deployments |
| User data directory | `~/.hermes` | Retained to avoid breaking existing profiles |
| Home override | `CHERRY_HOME` or `HERMES_HOME` | `HERMES_HOME` wins when both are set |
| Existing environment/config keys | `HERMES_*` and Hermes config names | Retained where changing them would break users |
| Upstream service names | Nous Portal, Hermes upstream documentation | Their original names are preserved when referring to those actual services |

This distinction is deliberate. Cherry now has a real `cherry` launcher, while the original identifiers remain available wherever removing them would break compatibility. Package, protocol, and storage renames will be handled through staged migrations rather than global replacements.

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

The upstream one-line installer installs the upstream Hermes Agent release. To run **this Cherry fork**, install from this repository instead.

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

cherry setup
cherry
```

### Windows PowerShell

Requirements:

- Windows PowerShell 5.1 or PowerShell 7+
- Git for Windows
- Python 3.11, 3.12, or 3.13

Run the fork-safe Cherry installer:

```powershell
iex (irm https://raw.githubusercontent.com/paddman/hermes-agent-x-cherry/main/scripts/cherry/install.ps1)
```

The installer source is [`scripts/cherry/install.ps1`](scripts/cherry/install.ps1). It clones this repository, refuses to update an unrelated or dirty checkout, creates an isolated virtual environment, installs the Cherry launch commands, and then starts setup. It does not silently move existing profiles or memory.

To install without starting the setup wizard:

```powershell
$Installer = Join-Path $env:TEMP "cherry-install.ps1"
Invoke-WebRequest `
  "https://raw.githubusercontent.com/paddman/hermes-agent-x-cherry/main/scripts/cherry/install.ps1" `
  -OutFile $Installer
& $Installer -SkipSetup
```

> [!WARNING]
> The inherited root script [`scripts/install.ps1`](scripts/install.ps1) remains part of the upstream-compatible runtime and currently targets the Nous Research repository. Cherry users should use `scripts/cherry/install.ps1`; using the root installer may install the upstream project instead of this fork.

Manual source installation remains available:

```powershell
git clone https://github.com/paddman/hermes-agent-x-cherry.git
Set-Location hermes-agent-x-cherry

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip uv
uv pip install -e ".[all]"

cherry setup
cherry
```

> [!NOTE]
> `cherry` is now the preferred command. `hermes` remains installed as a backward-compatible alias, and both currently execute the same runtime. Internal package names, the default `~/.hermes` directory, and some output text remain unchanged in this phase.

## Common commands

```bash
cherry                 # Start the interactive agent
cherry setup           # Configure model providers, tools, and gateways
cherry model           # Select a model/provider
cherry tools           # Configure available tools
cherry config get      # Read configuration
cherry config set      # Change configuration
cherry gateway         # Run messaging gateways
cherry doctor          # Diagnose installation and configuration

hermes version         # Legacy command remains supported
```

Use a separate Cherry home only when you deliberately want isolated profiles and memory:

```bash
CHERRY_HOME="$HOME/.cherry-agent-dev" cherry
```

Windows PowerShell equivalent:

```powershell
$env:CHERRY_HOME = "$env:LOCALAPPDATA\cherry-agent-dev"
cherry
```

See [`docs/cherry-compatibility.md`](docs/cherry-compatibility.md) for naming, environment precedence, and the staged migration plan.

### Update this source fork

Use Git for this fork. Do not rely on `cherry update` or `hermes update`, because both currently reach the managed upstream update flow and may replace fork-specific code.

```bash
git pull --ff-only origin main
source .venv/bin/activate
uv pip install -e ".[all]"
```

On Windows, rerun `scripts/cherry/install.ps1`, or activate the environment with `.\.venv\Scripts\Activate.ps1` before running the final install command.

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

The bundled Cherry security skill is located at [`skills/security/cherry-pcap/SKILL.md`](skills/security/cherry-pcap/SKILL.md).

## Security model

Cherry Agent can execute commands, access files, connect to remote systems, and process potentially sensitive network evidence. Treat it as privileged automation software.

- Use least-privilege accounts and narrowly scoped API tokens.
- Keep command approval enabled for risky operations.
- Prefer isolated Docker, SSH, or sandbox backends for untrusted tasks.
- Do not upload PCAP files, credentials, tokens, customer data, or private documents to external services without explicit authorization.
- Hash and preserve original evidence before analysis.
- Treat detections and LLM conclusions as hypotheses requiring validation.
- Report vulnerabilities privately through [GitHub Security Advisories for this fork](https://github.com/paddman/hermes-agent-x-cherry/security/advisories/new), not through a public issue.

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
- [Cherry compatibility and migration](docs/cherry-compatibility.md)
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
