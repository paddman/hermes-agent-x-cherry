"""Compatibility-safe Cherry command entry points.

The fork still uses the upstream Hermes runtime, package name, profile
layout, and internal configuration identifiers. These wrappers provide
Cherry-branded console commands without breaking existing ``hermes``
commands or moving user data behind the operator's back.
"""

from __future__ import annotations

import os
from collections.abc import MutableMapping


def bridge_environment(
    environ: MutableMapping[str, str] | None = None,
) -> MutableMapping[str, str]:
    """Bridge stable Cherry environment aliases to runtime names.

    ``CHERRY_HOME`` is accepted by the Cherry launchers and copied to
    ``HERMES_HOME`` only when the legacy variable is unset. Therefore:

    - existing deployments keep their current ``HERMES_HOME`` behavior;
    - new Cherry invocations may choose a custom home with ``CHERRY_HOME``;
    - no automatic migration from ``~/.hermes`` occurs.

    The mapping is applied before importing runtime entry points because
    several modules resolve the home directory during import.
    """
    env = os.environ if environ is None else environ
    cherry_home = env.get("CHERRY_HOME", "").strip()
    hermes_home = env.get("HERMES_HOME", "").strip()
    if cherry_home and not hermes_home:
        env["HERMES_HOME"] = cherry_home
    return env


def cli_main() -> object:
    """Run the full CLI through the Cherry-branded launcher."""
    bridge_environment()
    from hermes_cli.main import main as delegated_main

    return delegated_main()


def agent_main() -> object:
    """Run the low-level agent entry point through the Cherry launcher."""
    bridge_environment()
    from run_agent import main as delegated_main

    return delegated_main()


def acp_main() -> object:
    """Run the ACP adapter through the Cherry-branded launcher."""
    bridge_environment()
    from acp_adapter.entry import main as delegated_main

    return delegated_main()


__all__ = ["acp_main", "agent_main", "bridge_environment", "cli_main"]
