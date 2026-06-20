#!/usr/bin/env python3
"""Final archive report helpers for CloverSec CTF workflows."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path
from typing import Any

import cloversec_ctf_data as data


YUQUE_FIELDS = [
    "HUB编号",
    "赛事来源",
    "题目来源",
    "名称",
    "分类",
    "题目类型",
    "Flag类型",
    "Flag",
    "难度编号",
    "星级",
    "分值",
    "资源等级",
    "开放端口",
    "是否通过",
    "验证状态",
    "归档目录",
    "环境包/附件包路径",
    "备注",
]

ESSENTIAL_PASS_FIELDS = ["赛事来源", "题目来源", "名称", "分类", "题目类型", "Flag类型", "Flag", "验证状态", "解题工具"]
FORMAL_HUB_ID_RE = re.compile(r"^CTF-\d{6,}$", re.I)


def create_final_outputs(
    cases: list[dict[str, Any]],
    output_dir: str | Path,
    *,
    base_dir: str | Path | None = None,
) -> dict[str, Any]:
    output = Path(output_dir)
    path_base = Path(base_dir).expanduser().resolve() if base_dir else None
    output.mkdir(parents=True, exist_ok=True)
    xlsx_path = output / "最终归档表.xlsx"
    yuque_path = output / "语雀粘贴表.md"
    report_path = output / "最终报告.md"
    json_path = output / "最终报告.json"
    legacy_xlsx_path = output / "archive.xlsx"
    legacy_yuque_path = output / "yuque_table.md"
    legacy_report_path = output / "final_report.md"
    legacy_json_path = output / "final_report.json"

    rows = [finalized_xlsx_row(case, path_base) for case in cases]
    validation_errors = []
    for index, case in enumerate(cases, start=1):
        validation_errors.extend(f"case {index}: {error}" for error in data.validate_case(case))
    data.write_rows_xlsx(rows, xlsx_path)
    shutil.copyfile(xlsx_path, legacy_xlsx_path)
    read_back = data.read_xlsx(xlsx_path)
    xlsx_validation_errors = validate_final_xlsx_readback(rows, read_back)

    entries = [_final_entry(case, row, path_base) for case, row in zip(cases, rows)]
    remaining_actions = []
    for entry in entries:
        remaining_actions.extend(entry["remaining_actions"])
    if validation_errors:
        remaining_actions.extend(validation_errors)
    if xlsx_validation_errors:
        remaining_actions.extend(xlsx_validation_errors)

    summary = {
        "total": len(cases),
        "xlsx_path": xlsx_path.as_posix(),
        "yuque_table_path": yuque_path.as_posix(),
        "report_path": report_path.as_posix(),
        "json_path": json_path.as_posix(),
        "legacy_xlsx_path": legacy_xlsx_path.as_posix(),
        "legacy_yuque_table_path": legacy_yuque_path.as_posix(),
        "legacy_report_path": legacy_report_path.as_posix(),
        "legacy_json_path": legacy_json_path.as_posix(),
        "legacy_paths": {
            "archive_xlsx": legacy_xlsx_path.as_posix(),
            "yuque_table": legacy_yuque_path.as_posix(),
            "final_report_md": legacy_report_path.as_posix(),
            "final_report_json": legacy_json_path.as_posix(),
        },
        "human_handoff_paths": {
            "最终归档表": xlsx_path.as_posix(),
            "语雀粘贴表": yuque_path.as_posix(),
            "最终报告": report_path.as_posix(),
        },
        "xlsx_readback_rows": len(read_back),
        "xlsx_validation_errors": len(xlsx_validation_errors),
        "remaining_actions": len(remaining_actions),
    }
    payload = {
        "summary": summary,
        "entries": entries,
        "remaining_actions": remaining_actions,
    }
    yuque_content = render_yuque_table(rows)
    report_content = render_final_report(payload)
    json_content = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    yuque_path.write_text(yuque_content, encoding="utf-8")
    report_path.write_text(report_content, encoding="utf-8")
    json_path.write_text(json_content, encoding="utf-8")
    legacy_yuque_path.write_text(yuque_content, encoding="utf-8")
    legacy_report_path.write_text(report_content, encoding="utf-8")
    legacy_json_path.write_text(json_content, encoding="utf-8")
    return payload


def render_yuque_table(rows: list[dict[str, str]]) -> str:
    lines = [
        "| " + " | ".join(YUQUE_FIELDS) + " |",
        "| " + " | ".join(["---"] * len(YUQUE_FIELDS)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_escape_table(row.get(field, "")) for field in YUQUE_FIELDS) + " |")
    return "\n".join(lines) + "\n"


def render_final_report(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines = [
        "# 最终归档报告",
        "",
        f"- 题目数量：{summary.get('total', 0)}",
        f"- 最终归档表：{summary.get('xlsx_path', '')}",
        f"- 语雀粘贴表：{summary.get('yuque_table_path', '')}",
        f"- 最终报告：{summary.get('report_path', '')}",
        f"- xlsx 回读行数：{summary.get('xlsx_readback_rows', 0)}",
        f"- xlsx 内容问题：{summary.get('xlsx_validation_errors', 0)}",
        f"- 待处理事项：{summary.get('remaining_actions', 0)}",
        "",
        "## 对人交付文件",
        "",
        f"- 最终归档表：`{summary.get('human_handoff_paths', {}).get('最终归档表', '')}`",
        f"- 语雀粘贴表：`{summary.get('human_handoff_paths', {}).get('语雀粘贴表', '')}`",
        f"- 最终报告：`{summary.get('human_handoff_paths', {}).get('最终报告', '')}`",
        "",
        "| 题目 | HUB编号 | 验证状态 | 归档目录 | 环境包/附件包 |",
        "|---|---|---|---|---|",
    ]
    for entry in payload.get("entries", []):
        lines.append(
            "| "
            + " | ".join(
                _escape_table(value)
                for value in [
                    entry.get("name", ""),
                    entry.get("hub_id", ""),
                    entry.get("validation_status", ""),
                    entry.get("archive_dir", ""),
                    entry.get("resource_path", ""),
                ]
            )
            + " |"
        )
    if payload.get("remaining_actions"):
        lines.extend(["", "## 待处理事项", ""])
        for item in payload["remaining_actions"]:
            lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def _final_entry(case: dict[str, Any], row: dict[str, str], base_dir: Path | None = None) -> dict[str, Any]:
    archive_dir = row.get("归档目录", "")
    resource_path = row.get("环境包/附件包路径", "")
    name = row.get("名称") or str(case.get("case_id") or "unknown")
    validation_status = row.get("验证状态", "").strip()
    actions = []
    for field in ESSENTIAL_PASS_FIELDS:
        if not row.get(field, "").strip():
            actions.append(f"{name} 缺少 {field}")
    if row.get("题目类型", "").strip() == "环境型" and not row.get("开放端口", "").strip():
        actions.append(f"{name} 环境型题目缺少开放端口")
    if validation_status in {"失败", "未验证"}:
        actions.append(f"{name} 验证状态为 {validation_status}，需要复核后再交付")
    elif validation_status == "部分通过":
        actions.append(f"{name} 验证状态为部分通过，需要查看质量检查报告和未执行项")
    if not row.get("HUB编号", "").strip():
        actions.append(f"{name} 缺少 HUB编号，Hub 审核通过后需要回填")
    archive_exists = any(path.exists() for path in _path_candidates(archive_dir, base_dir)) if archive_dir else False
    if archive_dir and not archive_exists:
        actions.append(f"{name} 归档目录不存在：{archive_dir}")
    elif not archive_dir:
        actions.append(f"{name} 缺少归档目录")

    for path in _split_paths(resource_path):
        if not _resource_exists(path, archive_dir, base_dir):
            actions.append(f"{name} 资源路径不存在：{path}")
    if not resource_path.strip():
        actions.append(f"{name} 缺少环境包/附件包路径")

    return {
        "case_id": str(case.get("case_id") or ""),
        "name": row.get("名称", ""),
        "hub_id": row.get("HUB编号", ""),
        "validation_status": row.get("验证状态", ""),
        "archive_dir": archive_dir,
        "resource_path": resource_path,
        "remaining_actions": actions,
    }


def finalized_xlsx_row(case: dict[str, Any], base_dir: Path | None = None) -> dict[str, str]:
    row = data.case_to_xlsx_row(case)
    issues = hub_id_issues(case, row) + row_missing_issues(row, base_dir)
    if issues:
        if row.get("是否通过") == "是":
            row["是否通过"] = "否"
        if row.get("是否归档") == "是":
            row["是否归档"] = "否"
        if row.get("验证状态") == "通过":
            row["验证状态"] = "部分通过"
        existing = row.get("问题", "").strip()
        merged = ";".join(item for item in [existing, *issues] if item)
        row["问题"] = merged[:1000]
    return row


def hub_id_issues(case: dict[str, Any], row: dict[str, str]) -> list[str]:
    value = row.get("HUB编号", "").strip()
    gates = hub_gate_candidates(case)
    if gates:
        allowed = next((gate for gate in gates if gate.get("can_backfill_xlsx") is True), {})
        if allowed:
            hub_id = str(allowed.get("hub_id") or value).strip()
            if hub_id and FORMAL_HUB_ID_RE.match(hub_id):
                row["HUB编号"] = hub_id
                return []
        if value:
            row["HUB编号"] = ""
            return ["HUB编号未确认，不能回填最终表"]
        return []
    if not value:
        return []
    if not FORMAL_HUB_ID_RE.match(value):
        row["HUB编号"] = ""
        return ["HUB编号不是正式 CTF 编号，不能回填最终表"]
    if case.get("hub_id_confirmed") is True or case.get("HUB编号已确认") is True:
        return []
    row["HUB编号"] = ""
    return ["HUB编号缺少用户确认，不能回填最终表"]


def hub_gate_candidates(case: dict[str, Any]) -> list[dict[str, Any]]:
    gates: list[dict[str, Any]] = []
    for key in ["hub_id_gate", "hub_gate"]:
        value = case.get(key)
        if isinstance(value, dict):
            gates.append(value)
    for key in ["hub_state", "hub_review", "retag_plan", "hub_submission"]:
        value = case.get(key)
        if isinstance(value, dict) and isinstance(value.get("hub_id_gate"), dict):
            gates.append(value["hub_id_gate"])
    return gates


def row_missing_issues(row: dict[str, str], base_dir: Path | None = None) -> list[str]:
    name = row.get("名称") or "未命名题目"
    issues = []
    if row.get("是否通过") == "是" or row.get("验证状态") == "通过":
        for field in ESSENTIAL_PASS_FIELDS:
            if not row.get(field, "").strip():
                issues.append(f"{name} 缺少 {field}")
        if row.get("题目类型", "").strip() == "环境型" and not row.get("开放端口", "").strip():
            issues.append(f"{name} 环境型题目缺少开放端口")
    if row.get("是否归档") == "是":
        archive_dir = row.get("归档目录", "")
        resource_path = row.get("环境包/附件包路径", "")
        if not archive_dir.strip():
            issues.append(f"{name} 缺少归档目录")
        elif not any(path.exists() for path in _path_candidates(archive_dir, base_dir)):
            issues.append(f"{name} 归档目录不存在：{archive_dir}")
        if not resource_path.strip():
            issues.append(f"{name} 缺少环境包/附件包路径")
        else:
            for path in _split_paths(resource_path):
                if not _resource_exists(path, archive_dir, base_dir):
                    issues.append(f"{name} 资源路径不存在：{path}")
            if row.get("题目类型", "").strip() == "环境型" and not any(path.lower().endswith((".tar", ".tar.gz", ".tgz")) for path in _split_paths(resource_path)):
                issues.append(f"{name} 环境型题目缺少镜像 tar 路径")
    return issues


def validate_final_xlsx_readback(expected_rows: list[dict[str, str]], actual_rows: list[dict[str, str]]) -> list[str]:
    errors: list[str] = []
    if len(actual_rows) != len(expected_rows):
        errors.append(f"xlsx 回读行数不一致：期望 {len(expected_rows)}，实际 {len(actual_rows)}")
    key_fields = ["名称", "赛事来源", "题目来源", "分类", "题目类型", "Flag", "验证状态", "归档目录", "环境包/附件包路径"]
    for index, expected in enumerate(expected_rows, start=1):
        if index > len(actual_rows):
            break
        actual = actual_rows[index - 1]
        for field in key_fields:
            expected_value = str(expected.get(field) or "").strip()
            actual_value = str(actual.get(field) or "").strip()
            if expected_value != actual_value:
                errors.append(f"xlsx 第 {index} 行字段 {field} 回读不一致")
    return errors


def _split_paths(value: str) -> list[str]:
    return [item.strip() for item in value.split(";") if item.strip()]


def _resource_exists(value: str, archive_dir: str, base_dir: Path | None = None) -> bool:
    for path in _resource_candidates(value, archive_dir, base_dir):
        if path.exists():
            return True
    return False


def _path_candidates(value: str, base_dir: Path | None = None) -> list[Path]:
    if not value:
        return []
    path = Path(value)
    candidates = [path]
    if base_dir and not path.is_absolute():
        candidates.append(base_dir / path)
    return candidates


def _resource_candidates(value: str, archive_dir: str, base_dir: Path | None = None) -> list[Path]:
    path = Path(value)
    if path.is_absolute():
        return [path]
    candidates = [path]
    for archive_path in _path_candidates(archive_dir, base_dir):
        candidates.append(archive_path / path)
    if base_dir:
        candidates.append(base_dir / path)
    return candidates


def _escape_table(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF final report utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser("generate", help="write final xlsx, Yuque table, and report")
    generate_parser.add_argument("--cases", required=True)
    generate_parser.add_argument("--output-dir", required=True)
    generate_parser.add_argument("--base-dir", help="base directory for relative archive/resource paths")

    args = parser.parse_args(argv)
    if args.command == "generate":
        cases = data.load_cases(args.cases)
        payload = create_final_outputs(cases, args.output_dir, base_dir=args.base_dir)
        print(f"wrote {payload['summary']['report_path']}")
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
