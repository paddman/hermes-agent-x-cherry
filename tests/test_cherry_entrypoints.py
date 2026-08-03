from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path
from types import ModuleType

from hermes_cli import cherry_entrypoints


ROOT = Path(__file__).resolve().parents[1]


def test_project_exposes_cherry_and_legacy_console_scripts() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = project["project"]["scripts"]

    assert scripts["cherry"] == "hermes_cli.cherry_entrypoints:cli_main"
    assert scripts["cherry-agent"] == "hermes_cli.cherry_entrypoints:agent_main"
    assert scripts["cherry-acp"] == "hermes_cli.cherry_entrypoints:acp_main"
    assert scripts["hermes"] == "hermes_cli.main:main"
    assert scripts["hermes-agent"] == "run_agent:main"
    assert scripts["hermes-acp"] == "acp_adapter.entry:main"


def test_cherry_home_fills_legacy_runtime_variable() -> None:
    env = {"CHERRY_HOME": "/srv/cherry-agent"}

    result = cherry_entrypoints.bridge_environment(env)

    assert result is env
    assert env["HERMES_HOME"] == "/srv/cherry-agent"


def test_existing_hermes_home_wins_when_both_are_set() -> None:
    env = {
        "CHERRY_HOME": "/srv/cherry-agent",
        "HERMES_HOME": "/srv/existing-hermes-profile",
    }

    cherry_entrypoints.bridge_environment(env)

    assert env["HERMES_HOME"] == "/srv/existing-hermes-profile"


def test_cli_launcher_bridges_environment_before_lazy_delegate(monkeypatch) -> None:
    fake_module = ModuleType("hermes_cli.main")

    def fake_main() -> int:
        assert os.environ["HERMES_HOME"] == "/tmp/cherry-home"
        return 23

    fake_module.main = fake_main  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "hermes_cli.main", fake_module)
    monkeypatch.setenv("CHERRY_HOME", "/tmp/cherry-home")
    monkeypatch.delenv("HERMES_HOME", raising=False)

    assert cherry_entrypoints.cli_main() == 23
