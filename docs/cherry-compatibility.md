# Cherry compatibility and migration

Cherry Agent is a derivative fork of Hermes Agent. The public product
name and preferred launch commands are Cherry-branded, while selected
runtime identifiers remain unchanged so existing installations do not
lose profiles, memory, plugins, credentials, or automation scripts.

## Commands

After installing this fork, the following command pairs are equivalent:

| Preferred Cherry command | Backward-compatible command |
|---|---|
| `cherry` | `hermes` |
| `cherry-agent` | `hermes-agent` |
| `cherry-acp` | `hermes-acp` |

The original commands are intentionally retained. Removing them would
break shell scripts, services, scheduled jobs, containers, and external
integrations for no operational benefit.

## Home directory

The default data directory remains `~/.hermes` on POSIX and
`%LOCALAPPDATA%\hermes` on Windows. Cherry Agent does not silently move
data because an interrupted or partial migration could split memory,
credentials, and session state across two locations.

The Cherry launcher accepts a new stable alias:

```bash
CHERRY_HOME="$HOME/.cherry-agent-dev" cherry
```

Internally the launcher maps `CHERRY_HOME` to `HERMES_HOME` before the
runtime imports. When both variables are set, `HERMES_HOME` wins to
preserve existing deployment behavior.

## Current compatibility boundary

These identifiers remain unchanged in this phase:

- Python distribution name: `hermes-agent`
- internal Python packages such as `hermes_cli`
- default profile directory: `~/.hermes`
- existing `HERMES_*` environment and configuration keys
- service, plugin, and protocol identifiers consumed by integrations

Some command output may still say Hermes while the compatibility layer
is being converted. This is cosmetic; `cherry` and `hermes` currently
execute the same runtime.

## Planned migration phases

1. **Command aliases:** ship `cherry`, `cherry-agent`, and `cherry-acp`
   while retaining all legacy commands.
2. **User-facing text:** convert banners, help, desktop labels, and
   documentation where the change does not alter protocol contracts.
3. **Explicit data migration:** add a dry-run and rollback-capable command
   before offering a new default Cherry home directory.
4. **Package or protocol rename:** consider only in a major release with
   deprecation notices and compatibility shims.

## Licensing

Rebranding does not remove upstream attribution. The original Nous
Research copyright and MIT permission notice remain in `LICENSE`, and
the repository records upstream lineage in `THIRD_PARTY_NOTICES.md`.
