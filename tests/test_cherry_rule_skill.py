"""Contract tests for the bundled CherryRule Thai knowledge skill."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = ROOT / "skills" / "security" / "cherry-rule"
CATALOG_PATH = SKILL_ROOT / "data" / "cherry-rules.th.json"
PROVENANCE_PATH = SKILL_ROOT / "data" / "provenance.json"
SCRIPT_PATH = SKILL_ROOT / "scripts" / "cherry_rule.py"
THAI_RE = re.compile(r"[\u0E00-\u0E7F]")
EXPECTED_SOURCE_COMMIT = "b38a9d17467e3ecf853b7232482c4b823a8a21ce"
REQUIRED_EXPLANATION_FIELDS = {
    "summary",
    "detection_logic",
    "risk_and_impact",
    "enforcement",
    "false_positive",
    "requirements",
    "tuning",
    "validation",
}
THAI_REQUIRED_FIELDS = {
    "summary",
    "detection_logic",
    "risk_and_impact",
    "enforcement",
    "tuning",
    "validation",
}


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def test_catalog_has_512_unique_explainable_rules() -> None:
    catalog = load_json(CATALOG_PATH)
    rules = catalog["rules"]

    assert catalog["total_rules"] == 512
    assert len(rules) == 512
    assert len({rule["id"] for rule in rules}) == 512
    assert catalog["native_thai_rules"] == 455
    assert catalog["generated_thai_rules"] == 57

    for rule in rules:
        assert THAI_RE.search(rule["name_th"]), rule["id"]
        assert THAI_RE.search(rule["description_th"]), rule["id"]

        explanation = rule["explanation_th"]
        assert REQUIRED_EXPLANATION_FIELDS <= explanation.keys(), rule["id"]
        for field in THAI_REQUIRED_FIELDS:
            assert THAI_RE.search(explanation[field]), f"{rule['id']}:{field}"

        assert rule["source_pack"]["id"]
        assert rule["localization"]["status"] in {"native", "generated"}


def test_provenance_is_pinned_to_validated_cherryrule_commit() -> None:
    provenance = load_json(PROVENANCE_PATH)

    assert provenance["source_repository"] == "paddman/CherryRule"
    assert provenance["source_ref"] == "recovery/catalog-source-20260814"
    assert provenance["source_commit"] == EXPECTED_SOURCE_COMMIT
    assert provenance["validated_rules"] == 512
    assert provenance["re2_regex_rules_checked"] == 281
    assert provenance["re2_compile_failures"] == 0
    assert len(provenance["source_artifact_sha256"]) == 64


def test_cli_validate_reports_complete_catalog() -> None:
    result = run_cli("validate")

    assert result.returncode == 0, result.stderr or result.stdout
    assert "512 Rule" in result.stdout
    assert "ภาษาไทยครบ" in result.stdout


def test_cli_explains_known_rule_in_detailed_thai() -> None:
    result = run_cli("explain", "CR-100001")

    assert result.returncode == 0, result.stderr
    assert "# CR-100001:" in result.stdout
    assert "## 1. กฎนี้ตรวจอะไร" in result.stdout
    assert "## 3. หลักการตรวจจับ" in result.stdout
    assert "## 5. False positive ที่ต้องระวัง" in result.stdout
    assert "## 7. วิธีตรวจยืนยันเหตุการณ์" in result.stdout
    assert "ไม่ใช่หลักฐานว่าการโจมตีสำเร็จ" in result.stdout
    assert len(THAI_RE.findall(result.stdout)) >= 50


def test_cli_search_returns_machine_readable_results() -> None:
    result = run_cli("search", "CR-100001", "--json")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload[0]["id"] == "CR-100001"
    assert THAI_RE.search(payload[0]["name_th"])


def test_cli_unknown_rule_fails_without_inventing_an_answer() -> None:
    result = run_cli("explain", "CR-NOT-A-REAL-RULE")

    assert result.returncode == 2
    assert "ไม่พบ Rule ID" in result.stderr
