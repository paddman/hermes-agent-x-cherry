from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "cherry" / "install.ps1"
README = ROOT / "README.md"


def test_cherry_windows_installer_targets_this_fork() -> None:
    source = INSTALLER.read_text(encoding="utf-8")

    assert "https://github.com/paddman/hermes-agent-x-cherry.git" in source
    assert "git@github.com:paddman/hermes-agent-x-cherry.git" in source
    assert "NousResearch/hermes-agent.git" not in source


def test_cherry_windows_installer_preserves_runtime_home_compatibility() -> None:
    source = INSTALLER.read_text(encoding="utf-8")

    assert "$env:CHERRY_HOME" in source
    assert "$env:HERMES_HOME" in source
    assert 'Join-Path $env:LOCALAPPDATA "hermes"' in source


def test_cherry_windows_installer_has_update_safety_guards() -> None:
    source = INSTALLER.read_text(encoding="utf-8")

    assert "status --porcelain" in source
    assert '"merge", "--ff-only"' in source
    assert "Refusing to update an unrelated repository" in source


def test_readme_points_windows_users_to_cherry_installer() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "scripts/cherry/install.ps1" in readme
    assert (
        "raw.githubusercontent.com/paddman/hermes-agent-x-cherry/main/"
        "scripts/cherry/install.ps1"
    ) in readme
