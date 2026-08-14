#!/usr/bin/env python3
"""Search and explain the bundled CherryRule catalog in detailed Thai."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence, TextIO

SKILL_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = SKILL_ROOT / "data" / "cherry-rules.th.json"
THAI_RE = re.compile(r"[\u0E00-\u0E7F]")
REQUIRED_EXPLANATION_FIELDS = (
    "summary",
    "detection_logic",
    "risk_and_impact",
    "enforcement",
    "false_positive",
    "requirements",
    "tuning",
    "validation",
)
THAI_REQUIRED_EXPLANATION_FIELDS = (
    "summary",
    "detection_logic",
    "risk_and_impact",
    "enforcement",
    "tuning",
    "validation",
)

JsonObject = dict[str, Any]


class CatalogError(RuntimeError):
    """Raised when the bundled catalog cannot be loaded or trusted."""


def load_catalog(path: Path) -> JsonObject:
    """Load a JSON catalog and perform basic root-level type checks."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CatalogError(f"ไม่พบไฟล์ฐานความรู้ CherryRule: {path}") from exc
    except UnicodeDecodeError as exc:
        message = f"ไฟล์ฐานความรู้ไม่ใช่ UTF-8 ที่ถูกต้อง: {path}"
        raise CatalogError(message) from exc
    except json.JSONDecodeError as exc:
        message = (
            "ไฟล์ฐานความรู้ JSON เสียที่บรรทัด "
            f"{exc.lineno} คอลัมน์ {exc.colno}: {exc.msg}"
        )
        raise CatalogError(message) from exc

    if not isinstance(payload, dict):
        raise CatalogError(
            "โครงสร้างฐานความรู้ต้องเป็น JSON object"
        )
    if not isinstance(payload.get("rules"), list):
        raise CatalogError(
            "โครงสร้างฐานความรู้ต้องมี rules เป็นรายการ"
        )
    return payload


def iter_rules(catalog: Mapping[str, Any]) -> Iterable[JsonObject]:
    """Yield catalog rules that are JSON objects."""
    rules = catalog.get("rules", [])
    if not isinstance(rules, list):
        return
    for rule in rules:
        if isinstance(rule, dict):
            yield rule


def text(value: Any, default: str = "ไม่ระบุ") -> str:
    """Render an arbitrary catalog value without losing exact technical values."""
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return "ใช่" if value else "ไม่ใช่"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def list_text(value: Any, default: str = "ไม่ระบุ") -> str:
    """Render a list as a comma-separated value."""
    if not isinstance(value, list) or not value:
        return default
    return ", ".join(str(item) for item in value)


def contains_thai(value: Any) -> bool:
    return isinstance(value, str) and bool(THAI_RE.search(value))


def action_mode(rule: Mapping[str, Any]) -> str:
    action = rule.get("action")
    if isinstance(action, dict):
        return str(action.get("mode", "unknown"))
    return "unknown"


def source_pack(rule: Mapping[str, Any]) -> Mapping[str, Any]:
    value = rule.get("source_pack")
    return value if isinstance(value, dict) else {}


def localization_status(rule: Mapping[str, Any]) -> str:
    localization = rule.get("localization")
    if isinstance(localization, dict):
        return str(localization.get("status", "unknown"))
    return "unknown"


def validate_catalog(catalog: Mapping[str, Any]) -> list[str]:
    """Return all catalog integrity errors without stopping at the first one."""
    errors: list[str] = []
    raw_rules = catalog.get("rules")
    if not isinstance(raw_rules, list):
        return ["catalog.rules ต้องเป็นรายการ"]

    declared_total = catalog.get("total_rules")
    if declared_total != len(raw_rules):
        errors.append(
            f"จำนวน Rule ไม่ตรงกัน: total_rules={declared_total!r}, rules={len(raw_rules)}"
        )

    seen_ids: set[str] = set()
    for index, raw_rule in enumerate(raw_rules):
        prefix = f"rules[{index}]"
        if not isinstance(raw_rule, dict):
            errors.append(f"{prefix} ต้องเป็น object")
            continue

        rule_id = raw_rule.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            errors.append(f"{prefix}.id ต้องเป็นข้อความที่ไม่ว่าง")
            rule_id = prefix
        elif rule_id in seen_ids:
            errors.append(f"{prefix}.id ซ้ำ: {rule_id}")
        else:
            seen_ids.add(rule_id)

        if not contains_thai(raw_rule.get("name_th")):
            errors.append(f"{rule_id}.name_th ไม่มีข้อความภาษาไทย")
        if not contains_thai(raw_rule.get("description_th")):
            errors.append(f"{rule_id}.description_th ไม่มีข้อความภาษาไทย")

        explanation = raw_rule.get("explanation_th")
        if not isinstance(explanation, dict):
            errors.append(f"{rule_id}.explanation_th ต้องเป็น object")
            continue

        for field in REQUIRED_EXPLANATION_FIELDS:
            value = explanation.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(
                    f"{rule_id}.explanation_th.{field} ต้องเป็นข้อความที่ไม่ว่าง"
                )

        for field in THAI_REQUIRED_EXPLANATION_FIELDS:
            if not contains_thai(explanation.get(field)):
                errors.append(
                    f"{rule_id}.explanation_th.{field} ไม่มีข้อความภาษาไทย"
                )

        pack = raw_rule.get("source_pack")
        if not isinstance(pack, dict) or not pack.get("id"):
            errors.append(f"{rule_id}.source_pack.id หายไป")

    return errors


def get_rule(catalog: Mapping[str, Any], rule_id: str) -> JsonObject | None:
    wanted = rule_id.casefold()
    for rule in iter_rules(catalog):
        if str(rule.get("id", "")).casefold() == wanted:
            return rule
    return None


def searchable_parts(rule: Mapping[str, Any]) -> dict[str, str]:
    tags = rule.get("tags")
    references = rule.get("references")
    operator = rule.get("operator")
    pack = source_pack(rule)
    explanation = rule.get("explanation_th")
    return {
        "id": str(rule.get("id", "")),
        "name": str(rule.get("name", "")),
        "name_th": str(rule.get("name_th", "")),
        "description_th": str(rule.get("description_th", "")),
        "category": str(rule.get("category", "")),
        "engine": str(rule.get("engine", "")),
        "severity": str(rule.get("severity", "")),
        "action": action_mode(rule),
        "tags": " ".join(str(item) for item in tags) if isinstance(tags, list) else "",
        "references": " ".join(str(item) for item in references)
        if isinstance(references, list)
        else "",
        "operator": json.dumps(operator, ensure_ascii=False, sort_keys=True)
        if isinstance(operator, dict)
        else "",
        "pack": " ".join(str(pack.get(key, "")) for key in ("id", "slug", "version")),
        "explanation": json.dumps(explanation, ensure_ascii=False, sort_keys=True)
        if isinstance(explanation, dict)
        else "",
    }


def score_rule(rule: Mapping[str, Any], query: str) -> int:
    normalized_query = query.casefold().strip()
    if not normalized_query:
        return 0
    terms = [term for term in normalized_query.split() if term]
    parts = {key: value.casefold() for key, value in searchable_parts(rule).items()}

    if normalized_query == parts["id"]:
        return 100_000

    combined = " ".join(parts.values())
    if not all(term in combined for term in terms):
        return 0

    score = 0
    for term in terms:
        if parts["id"].startswith(term):
            score += 5_000
        elif term in parts["id"]:
            score += 2_500

        if parts["name"] == term or parts["name_th"] == term:
            score += 2_000
        elif parts["name"].startswith(term) or parts["name_th"].startswith(term):
            score += 1_000
        elif term in parts["name"] or term in parts["name_th"]:
            score += 500

        if term in parts["category"] or term in parts["tags"] or term in parts["pack"]:
            score += 180
        if term in parts["description_th"] or term in parts["explanation"]:
            score += 80
        if term in parts["operator"] or term in parts["references"]:
            score += 40

    return score


def matches_filters(rule: Mapping[str, Any], args: argparse.Namespace) -> bool:
    category = getattr(args, "category", None)
    if category and not str(rule.get("category", "")).casefold().startswith(category.casefold()):
        return False

    engine = getattr(args, "engine", None)
    if engine and str(rule.get("engine", "")).casefold() != engine.casefold():
        return False

    severity = getattr(args, "severity", None)
    if severity and str(rule.get("severity", "")).casefold() != severity.casefold():
        return False

    action = getattr(args, "action", None)
    return not action or action_mode(rule).casefold() == action.casefold()


def search_rules(catalog: Mapping[str, Any], query: str, args: argparse.Namespace) -> list[tuple[int, JsonObject]]:
    scored: list[tuple[int, JsonObject]] = []
    for rule in iter_rules(catalog):
        if not matches_filters(rule, args):
            continue
        score = score_rule(rule, query)
        if score:
            scored.append((score, rule))
    scored.sort(
        key=lambda item: (
            -item[0],
            str(item[1].get("id", "")),
        )
    )
    return scored[: args.limit]


def print_json(value: Any, out: TextIO) -> None:
    json.dump(value, out, ensure_ascii=False, indent=2, sort_keys=True)
    out.write("\n")


def search_result_record(score: int, rule: Mapping[str, Any]) -> JsonObject:
    return {
        "score": score,
        "id": rule.get("id"),
        "name_th": rule.get("name_th"),
        "name": rule.get("name"),
        "category": rule.get("category"),
        "engine": rule.get("engine"),
        "severity": rule.get("severity"),
        "action": action_mode(rule),
        "source_pack": source_pack(rule),
        "localization_status": localization_status(rule),
    }


def render_search(results: Sequence[tuple[int, JsonObject]], out: TextIO) -> None:
    if not results:
        out.write("ไม่พบ Rule ที่ตรงกับคำค้นและตัวกรอง\n")
        return

    out.write(f"พบ {len(results)} Rule\n\n")
    for score, rule in results:
        out.write(
            f"- {text(rule.get('id'))} | {text(rule.get('severity'))} | "
            f"{text(rule.get('engine'))} | {text(rule.get('name_th'))}\n"
        )
        out.write(
            f"  หมวด: {text(rule.get('category'))} | Action: {action_mode(rule)} "
            f"| คะแนนค้นหา: {score}\n"
        )


def operator_lines(rule: Mapping[str, Any]) -> list[str]:
    operator = rule.get("operator")
    if not isinstance(operator, dict):
        return ["- Operator: ไม่ระบุ"]

    lines = [f"- Operator type: `{text(operator.get('type'))}`"]
    for key in ("pattern", "check", "value", "values", "params"):
        if key in operator:
            lines.append(f"- Operator {key}: `{text(operator.get(key))}`")
    return lines


def action_lines(rule: Mapping[str, Any]) -> list[str]:
    action = rule.get("action")
    if not isinstance(action, dict):
        return ["- Action: ไม่ระบุ"]
    return [f"- Action {key}: `{text(value)}`" for key, value in action.items()]


def thai_source_note(value: Any) -> str:
    rendered = text(value)
    if contains_thai(rendered):
        return rendered
    return (
        "ข้อความต้นฉบับส่วนนี้เป็นภาษาอังกฤษ "
        "จึงคงค่าเดิมไว้เพื่อไม่ให้ความหมายทางเทคนิคคลาดเคลื่อน: "
        f"{rendered}"
    )


def explanation_payload(rule: Mapping[str, Any]) -> JsonObject:
    explanation = rule.get("explanation_th")
    explanation_map = explanation if isinstance(explanation, dict) else {}
    return {
        "id": rule.get("id"),
        "name_th": rule.get("name_th"),
        "name": rule.get("name"),
        "description_th": rule.get("description_th"),
        "category": rule.get("category"),
        "phase": rule.get("phase"),
        "targets": rule.get("targets"),
        "engine": rule.get("engine"),
        "operator": rule.get("operator"),
        "transforms": rule.get("transforms"),
        "severity": rule.get("severity"),
        "confidence": rule.get("confidence"),
        "action": rule.get("action"),
        "default_enabled": rule.get("default_enabled"),
        "explanation_th": explanation_map,
        "tags": rule.get("tags"),
        "references": rule.get("references"),
        "source_pack": source_pack(rule),
        "localization": rule.get("localization"),
    }


def render_explanation(rule: Mapping[str, Any], out: TextIO) -> None:
    explanation = rule.get("explanation_th")
    explanation_map = explanation if isinstance(explanation, dict) else {}
    pack = source_pack(rule)
    localization = rule.get("localization")
    localization_map = localization if isinstance(localization, dict) else {}

    out.write(f"# {text(rule.get('id'))}: {text(rule.get('name_th'))}\n\n")
    out.write(f"ชื่ออังกฤษ: {text(rule.get('name'))}\n")
    out.write(f"คำอธิบายสั้น: {text(rule.get('description_th'))}\n\n")

    out.write("## 1. กฎนี้ตรวจอะไร\n")
    out.write(f"{text(explanation_map.get('summary'))}\n\n")

    out.write("## 2. จุดและช่วงที่ตรวจ\n")
    out.write(f"- Phase: `{text(rule.get('phase'))}`\n")
    out.write(f"- Targets: `{list_text(rule.get('targets'))}`\n")
    out.write(f"- Engine: `{text(rule.get('engine'))}`\n")
    out.write(f"- Requirements: {thai_source_note(explanation_map.get('requirements'))}\n\n")

    out.write("## 3. หลักการตรวจจับ\n")
    out.write(f"{text(explanation_map.get('detection_logic'))}\n")
    out.write(f"- Transforms: `{list_text(rule.get('transforms'), 'ไม่มี')}`\n")
    for line in operator_lines(rule):
        out.write(f"{line}\n")
    out.write("\n")

    out.write("## 4. ระดับความเสี่ยงและการตอบสนอง\n")
    out.write(f"- Severity: `{text(rule.get('severity'))}`\n")
    out.write(f"- Confidence: `{text(rule.get('confidence'))}`\n")
    out.write(f"- Default enabled: `{text(rule.get('default_enabled'))}`\n")
    for line in action_lines(rule):
        out.write(f"{line}\n")
    out.write(f"\n{textexplanation(explanation_map, 'risk_and_impact')}\n")
    out.write(f"{textexplanation(explanation_map, 'enforcement')}\n\n")

    out.write("## 5. False positive ที่ต้องระวัง\n")
    out.write(f"{thai_source_note(explanation_map.get('false_positive'))}\n\n")

    out.write("## 6. วิธีปรับแต่ง Rule\n")
    out.write(f"{textexplanation(explanation_map, 'tuning')}\n\n")

    out.write("## 7. วิธีตรวจยืนยันเหตุการณ์\n")
    out.write(f"{textexplanation(explanation_map, 'validation')}\n\n")

    out.write("## 8. แหล่งที่มาและสถานะภาษา\n")
    out.write(f"- Source pack ID: `{text(pack.get('id'))}`\n")
    out.write(f"- Source pack slug: `{text(pack.get('slug'))}`\n")
    out.write(f"- Source pack version: `{text(pack.get('version'))}`\n")
    out.write(f"- Localization status: `{text(localization_map.get('status'))}`\n")
    out.write(f"- Tags: `{list_text(rule.get('tags'))}`\n")
    out.write(f"- References: `{list_text(rule.get('references'))}`\n\n")

    out.write(
        "> ข้อสรุปสำคัญ: การ match Rule เป็นสัญญาณให้ตรวจสอบ "
        "ไม่ใช่หลักฐานว่าการโจมตีสำเร็จ ต้องยืนยันด้วย request/response "
        "ที่ปกปิดข้อมูลลับ, correlation ID, log ปลายทาง "
        "และบริบทของ asset ก่อนสรุปเหตุการณ์\n"
    )


def textexplanation(explanation: Mapping[str, Any], field: str) -> str:
    value = explanation.get(field)
    return text(value, "ไม่มีคำอธิบายส่วนนี้ใน catalog")


def render_show(rule: Mapping[str, Any], out: TextIO) -> None:
    out.write(f"# ข้อมูล Rule {text(rule.get('id'))}\n\n")
    for label, key in (
        ("ชื่อไทย", "name_th"),
        ("ชื่ออังกฤษ", "name"),
        ("คำอธิบายไทย", "description_th"),
        ("หมวด", "category"),
        ("Phase", "phase"),
        ("Targets", "targets"),
        ("Engine", "engine"),
        ("Transforms", "transforms"),
        ("Severity", "severity"),
        ("Confidence", "confidence"),
        ("Default enabled", "default_enabled"),
        ("Tags", "tags"),
        ("References", "references"),
    ):
        value = rule.get(key)
        rendered = list_text(value) if isinstance(value, list) else text(value)
        out.write(f"- {label}: `{rendered}`\n")

    for line in operator_lines(rule):
        out.write(f"{line}\n")
    for line in action_lines(rule):
        out.write(f"{line}\n")

    pack = source_pack(rule)
    out.write(f"- Source pack: `{text(pack.get('id'))}/{text(pack.get('version'))}`\n")
    out.write(f"- Localization: `{localization_status(rule)}`\n")


def render_stats(catalog: Mapping[str, Any], out: TextIO, as_json: bool) -> None:
    rules = list(iter_rules(catalog))
    stats = {
        "total_rules": len(rules),
        "catalog_version": catalog.get("catalog_version"),
        "native_thai_rules": catalog.get("native_thai_rules"),
        "generated_thai_rules": catalog.get("generated_thai_rules"),
        "engine": dict(sorted(Counter(str(rule.get("engine", "unknown")) for rule in rules).items())),
        "severity": dict(sorted(Counter(str(rule.get("severity", "unknown")) for rule in rules).items())),
        "action": dict(sorted(Counter(action_mode(rule) for rule in rules).items())),
        "source": catalog.get("source"),
    }
    if as_json:
        print_json(stats, out)
        return

    out.write("# สถิติฐานความรู้ CherryRule\n\n")
    out.write(f"- Rule ทั้งหมด: {stats['total_rules']}\n")
    out.write(f"- Catalog version: {text(stats['catalog_version'])}\n")
    out.write(f"- ภาษาไทยจากต้นฉบับ: {text(stats['native_thai_rules'])}\n")
    out.write(
        "- ภาษาไทย fallback ที่สร้างจากโครงสร้าง Rule: "
        f"{text(stats['generated_thai_rules'])}\n"
    )
    out.write(f"- Engine: {json.dumps(stats['engine'], ensure_ascii=False, sort_keys=True)}\n")
    out.write(f"- Severity: {json.dumps(stats['severity'], ensure_ascii=False, sort_keys=True)}\n")
    out.write(f"- Action: {json.dumps(stats['action'], ensure_ascii=False, sort_keys=True)}\n")


def suggest_rules(catalog: Mapping[str, Any], rule_id: str, out: TextIO) -> None:
    namespace = argparse.Namespace(category=None, engine=None, severity=None, action=None, limit=5)
    suggestions = search_rules(catalog, rule_id, namespace)
    if not suggestions:
        return
    out.write("Rule ที่ใกล้เคียง:\n")
    for _, rule in suggestions:
        out.write(f"- {text(rule.get('id'))}: {text(rule.get('name_th'))}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "ค้นหา ตรวจสอบ และอธิบาย CherryRule เป็นภาษาไทย "
            "จาก catalog ที่ผ่าน validation"
        )
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        default=DEFAULT_CATALOG,
        help=f"ตำแหน่ง catalog JSON (ค่าเริ่มต้น: {DEFAULT_CATALOG})",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    stats_parser = subparsers.add_parser("stats", help="แสดงสถิติ catalog")
    stats_parser.add_argument("--json", action="store_true", help="ส่งออกเป็น JSON")

    search_parser = subparsers.add_parser("search", help="ค้นหา Rule")
    search_parser.add_argument(
        "query",
        nargs="+",
        help="คำค้น เช่น CWAF-GUI-200001, SQL injection หรือ prompt injection",
    )
    search_parser.add_argument("--category", help="กรอง category แบบ prefix")
    search_parser.add_argument("--engine", help="กรอง engine แบบตรงค่า")
    search_parser.add_argument("--severity", choices=("info", "low", "medium", "high", "critical"))
    search_parser.add_argument(
        "--action",
        choices=("score", "block", "challenge", "throttle", "sanitize", "redact", "allow"),
    )
    search_parser.add_argument("--limit", type=int, default=10, choices=range(1, 101), metavar="1-100")
    search_parser.add_argument("--json", action="store_true", help="ส่งออกเป็น JSON")

    show_parser = subparsers.add_parser(
        "show", help="แสดงข้อมูลดิบที่สำคัญของ Rule"
    )
    show_parser.add_argument("rule_id")
    show_parser.add_argument(
        "--json", action="store_true", help="ส่งออก Rule เต็มเป็น JSON"
    )

    explain_parser = subparsers.add_parser(
        "explain", help="อธิบาย Rule เป็นภาษาไทยแบบละเอียด"
    )
    explain_parser.add_argument("rule_id")
    explain_parser.add_argument(
        "--json", action="store_true", help="ส่งออกข้อมูลคำอธิบายเป็น JSON"
    )

    validate_parser = subparsers.add_parser(
        "validate", help="ตรวจความครบถ้วนของฐานความรู้"
    )
    validate_parser.add_argument(
        "--json", action="store_true", help="ส่งออกผล validation เป็น JSON"
    )

    return parser


def run(args: argparse.Namespace, out: TextIO = sys.stdout, err: TextIO = sys.stderr) -> int:
    try:
        catalog = load_catalog(args.catalog)
    except CatalogError as exc:
        err.write(f"ข้อผิดพลาด: {exc}\n")
        return 3

    if args.command == "validate":
        errors = validate_catalog(catalog)
        result = {
            "ok": not errors,
            "total_rules": len(list(iter_rules(catalog))),
            "errors": errors,
        }
        if args.json:
            print_json(result, out)
        elif errors:
            out.write(f"ฐานความรู้ไม่ผ่าน validation: {len(errors)} จุด\n")
            for item in errors[:100]:
                out.write(f"- {item}\n")
            if len(errors) > 100:
                out.write(f"- ยังมีอีก {len(errors) - 100} จุด\n")
        else:
            out.write(
                f"ฐานความรู้ผ่าน validation: {result['total_rules']} Rule "
                "มีชื่อ คำอธิบาย และโครงสร้างอธิบายภาษาไทยครบ\n"
            )
        return 0 if not errors else 1

    if args.command == "stats":
        render_stats(catalog, out, args.json)
        return 0

    if args.command == "search":
        results = search_rules(catalog, " ".join(args.query), args)
        if args.json:
            print_json([search_result_record(score, rule) for score, rule in results], out)
        else:
            render_search(results, out)
        return 0 if results else 1

    if args.command in {"show", "explain"}:
        rule = get_rule(catalog, args.rule_id)
        if rule is None:
            err.write(f"ไม่พบ Rule ID `{args.rule_id}` ใน catalog\n")
            suggest_rules(catalog, args.rule_id, err)
            return 2

        if args.command == "show":
            if args.json:
                print_json(rule, out)
            else:
                render_show(rule, out)
            return 0

        if args.json:
            print_json(explanation_payload(rule), out)
        else:
            render_explanation(rule, out)
        return 0

    err.write(f"คำสั่งที่ไม่รองรับ: {args.command}\n")
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
