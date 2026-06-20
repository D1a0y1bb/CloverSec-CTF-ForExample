#!/usr/bin/env python3
"""Research intake and asset collection helpers for CloverSec CTF workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

import cloversec_ctf_data as data


EVIDENCE_FIELDS = [
    "source_url",
    "source_type",
    "title",
    "accessed_at",
    "summary",
    "confidence",
    "status",
]

SOURCE_TYPES = {
    "public_web",
    "user_provided",
    "local_file",
    "github",
    "github_code",
    "github_release",
    "github_tree",
    "ctftime",
    "writeup",
    "agent_web_search",
    "browser_visible",
    "direct_url",
    "unknown",
}
EVIDENCE_STATUS = {"found", "missing", "inaccessible", "unverified", "previewed", "downloaded", "needs_review"}
COLLECTION_REQUIRED_METADATA = ["名称", "分类"]
COLLECTION_HUMAN_FIELDS = [
    "时间年份",
    "赛事名称",
    "赛事类型",
    "题目分类",
    "题目名称",
    "已知材料情况",
    "Wp 地址",
    "附件/源码地址",
    "收集人",
    "收集情况",
]
COLLECTION_HUMAN_STYLE = {
    "font_name": "等线",
    "font_size": 12,
    "row_height": 18.05,
    "column_widths": {
        "时间年份": 26.9326923076923,
        "赛事名称": 27.5961538461538,
        "赛事类型": 26.9326923076923,
        "题目分类": 24.7692307692308,
        "题目名称": 25.6057692307692,
        "已知材料情况": 29.7596153846154,
        "Wp 地址": 65.6923076923077,
        "附件/源码地址": 42.75,
        "收集人": 19.9519230769231,
        "收集情况": 13.0,
    },
}

ASSET_EXTENSIONS = {
    ".zip": "attachment",
    ".7z": "attachment",
    ".rar": "attachment",
    ".tar": "image_or_archive",
    ".gz": "image_or_archive",
    ".tgz": "image_or_archive",
    ".md": "writeup",
    ".txt": "note",
    ".pdf": "writeup",
    ".png": "screenshot",
    ".jpg": "screenshot",
    ".jpeg": "screenshot",
    ".webp": "screenshot",
    ".dockerfile": "source",
    ".yml": "config",
    ".yaml": "config",
    ".json": "config",
}


def legacy_row_to_case(row: dict[str, Any], row_number: int) -> dict[str, Any]:
    source = _first_text(row, "赛事来源", "题目来源")
    flag_value = _string(row.get("Flag"))
    metadata = {field: "" for field in data.XLSX_FIELDS}
    for field in data.XLSX_FIELDS:
        metadata[field] = _string(row.get(field, ""))

    metadata["赛事来源"] = _string(row.get("赛事来源") or source)
    metadata["题目来源"] = _string(row.get("题目来源") or source)
    metadata["名称"] = _string(row.get("名称") or row.get("题目名称"))
    metadata["分类"] = _string(row.get("分类"))
    metadata["题目类型"] = _string(row.get("题目类型") or "未知")
    metadata["Flag类型"] = _string(row.get("Flag类型") or ("未知" if not flag_value else "unknown"))
    metadata["Flag"] = flag_value
    metadata["材料状态"] = data.normalize_material_status(row.get("材料状态"))
    metadata["构建状态"] = _string(row.get("构建状态") or "未开始")
    metadata["手册状态"] = _string(row.get("手册状态") or "未开始")
    metadata["验证状态"] = _string(row.get("验证状态") or "未验证")

    return {
        "case_id": f"legacy-{row_number:06d}",
        "source_files": [],
        "research": {"legacy_row_number": row_number},
        "asset_collection": {},
        "metadata": metadata,
        "flag": {"value": flag_value, "type": metadata["Flag类型"], "sensitive": True},
        "environment": {},
        "docker_artifacts": {},
        "attachments": [],
        "writeup": {},
        "hub_fields": {},
        "review": {},
        "archive": {},
        "evidence": _legacy_evidence(row),
        "confidence": "low",
    }


def collection_human_row(case: dict[str, Any]) -> dict[str, str]:
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    research = case.get("research") if isinstance(case.get("research"), dict) else {}
    assets = case.get("asset_collection") if isinstance(case.get("asset_collection"), dict) else {}
    collection_status = _string(metadata.get("收集情况")) or collection_status_from_gate(research or assets)
    return {
        "时间年份": _string(metadata.get("时间年份") or metadata.get("年份") or research.get("year")),
        "赛事名称": _string(metadata.get("赛事名称") or metadata.get("赛事来源") or metadata.get("题目来源")),
        "赛事类型": _string(metadata.get("赛事类型")),
        "题目分类": _string(metadata.get("分类")),
        "题目名称": _string(metadata.get("名称") or metadata.get("题目名称") or research.get("source_title")),
        "已知材料情况": data.normalize_material_status(
            metadata.get("材料状态") or research.get("material_status") or assets.get("material_status")
        ),
        "Wp 地址": first_url_from_candidates(assets.get("writeup_candidates")) or first_evidence_url(case, want_writeup=True),
        "附件/源码地址": first_url_from_candidates(assets.get("attachment_candidates")) or first_evidence_url(case, want_asset=True),
        "收集人": _string(metadata.get("收集人")),
        "收集情况": collection_status,
    }


def collection_human_rows(cases: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [collection_human_row(case) for case in cases]


def write_collection_human_xlsx(cases: list[dict[str, Any]], path: str | Path) -> None:
    data.write_styled_xlsx(
        collection_human_rows(cases),
        path,
        fields=COLLECTION_HUMAN_FIELDS,
        sheet_name="Sheet1",
        style=COLLECTION_HUMAN_STYLE,
    )


def write_collection_machine_jsonl(cases: list[dict[str, Any]], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for case in cases:
        row = data.case_to_xlsx_row(case)
        lines.append(
            json.dumps(
                {
                    "case_id": _string(case.get("case_id")),
                    "xlsx_fields": row,
                    "research": case.get("research") if isinstance(case.get("research"), dict) else {},
                    "asset_collection": case.get("asset_collection") if isinstance(case.get("asset_collection"), dict) else {},
                    "evidence": case.get("evidence") if isinstance(case.get("evidence"), list) else [],
                    "confidence": _string(case.get("confidence")),
                },
                ensure_ascii=False,
            )
            + "\n"
        )
    output.write_text("".join(lines), encoding="utf-8")


def collection_status_from_gate(payload: dict[str, Any]) -> str:
    gate = _string(payload.get("gate"))
    if gate == "can_continue":
        return "可继续制作"
    if gate == "needs_human_download":
        return "待人工下载"
    if gate == "cannot_continue":
        return "不可制作"
    return ""


def first_url_from_candidates(value: Any) -> str:
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, dict):
                continue
            for key in ["source_url", "url", "href"]:
                text = _string(item.get(key)).strip()
                if text:
                    return text
    return ""


def first_evidence_url(case: dict[str, Any], *, want_writeup: bool = False, want_asset: bool = False) -> str:
    evidence = case.get("evidence") if isinstance(case.get("evidence"), list) else []
    for item in evidence:
        if not isinstance(item, dict):
            continue
        source_url = _string(item.get("source_url") or item.get("url")).strip()
        if not source_url:
            continue
        source_type = _string(item.get("source_type")).lower()
        text = " ".join(_string(item.get(key)) for key in ["title", "summary", "snippet", "source_url", "url"]).lower()
        if want_writeup and ("writeup" in source_type or "wp" in source_type or any(token in text for token in ["writeup", "wp", "题解"])):
            return source_url
        if want_asset and (
            any(token in source_type for token in ["github", "direct_url", "release", "asset", "attachment", "source"])
            or any(token in text for token in ["attachment", "source", "源码", "附件", "release", "download"])
        ):
            return source_url
    return ""


def validate_collection_case(case: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    for field in COLLECTION_REQUIRED_METADATA:
        if not _text(metadata.get(field)):
            issues.append(f"{case.get('case_id', '<unknown>')}: 缺少 {field}")

    evidence = case.get("evidence")
    if evidence is None:
        issues.append(f"{case.get('case_id', '<unknown>')}: 缺少 evidence 字段")
        return issues
    if not isinstance(evidence, list):
        issues.append(f"{case.get('case_id', '<unknown>')}: evidence 必须是数组，每条至少包含 source_url 或 local_path")
        return issues
    if not evidence:
        issues.append(f"{case.get('case_id', '<unknown>')}: evidence 为空；至少需要一条 source_url 或 local_path")
        return issues

    for index, item in enumerate(evidence):
        if not isinstance(item, dict):
            issues.append(f"{case.get('case_id', '<unknown>')}: evidence[{index}] must be an object")
            continue
        if not _text(item.get("source_url")) and not _text(item.get("local_path")):
            issues.append(f"{case.get('case_id', '<unknown>')}: evidence[{index}].source_url or local_path is required")
        source_type = item.get("source_type")
        if _text(source_type) and source_type not in SOURCE_TYPES:
            issues.append(f"{case.get('case_id', '<unknown>')}: evidence[{index}].source_type unsupported: {source_type}")
        status = item.get("status")
        if _text(status) and status not in EVIDENCE_STATUS:
            issues.append(f"{case.get('case_id', '<unknown>')}: evidence[{index}].status unsupported: {status}")
        confidence = item.get("confidence")
        if _text(confidence) and confidence not in data.CONFIDENCE_VALUES:
            issues.append(f"{case.get('case_id', '<unknown>')}: evidence[{index}].confidence unsupported: {confidence}")
    return issues


def build_asset_inventory(root: str | Path) -> dict[str, Any]:
    base = Path(root)
    assets: list[dict[str, Any]] = []
    for path in sorted(item for item in base.rglob("*") if item.is_file()):
        if _is_ignored(path):
            continue
        stat = path.stat()
        assets.append(
            {
                "name": path.name,
                "relative_path": path.relative_to(base).as_posix(),
                "asset_type": classify_asset(path),
                "size": stat.st_size,
                "sha256": sha256_file(path),
                "status": "found",
            }
        )

    counts = Counter(item["asset_type"] for item in assets)
    return {
        "root": base.as_posix(),
        "assets": assets,
        "summary": {
            "total_assets": len(assets),
            "by_asset_type": dict(counts),
        },
    }


def classify_asset(path: Path) -> str:
    lower_name = path.name.lower()
    if lower_name == "dockerfile":
        return "source"
    if "writeup" in lower_name or lower_name in {"wp.md", "writeup.md"}:
        return "writeup"
    suffixes = path.suffixes
    if len(suffixes) >= 2 and "".join(suffixes[-2:]).lower() in {".tar.gz"}:
        return "image_or_archive"
    return ASSET_EXTENSIONS.get(path.suffix.lower(), "source")


def render_research_report(cases: list[dict[str, Any]], title: str = "CloverSec CTF 赛题收集报告") -> str:
    lines = [
        f"# {title}",
        "",
        f"- 生成日期：{date.today().isoformat()}",
        f"- 题目数量：{len(cases)}",
        "",
        "## 赛题列表",
        "",
        "| case_id | 赛事来源 | 名称 | 分类 |",
        "|---|---|---|---|",
    ]
    for case in cases:
        metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
        lines.append(
            "| {case_id} | {source} | {name} | {category} |".format(
                case_id=_string(case.get("case_id")),
                source=_string(metadata.get("赛事来源")),
                name=_string(metadata.get("名称")),
                category=_string(metadata.get("分类")),
            )
        )

    issues = []
    for case in cases:
        issues.extend(validate_collection_case(case))

    lines.extend(["", "## 缺失项与风险", ""])
    if issues:
        lines.extend(f"- {issue}" for issue in issues)
    else:
        lines.append("- 暂未发现缺失项。")

    lines.extend(["", "## 来源证据", ""])
    for case in cases:
        evidence = case.get("evidence") if isinstance(case.get("evidence"), list) else []
        for item in evidence:
            if not isinstance(item, dict):
                continue
            lines.append(
                "- {case_id}: {summary} {source}".format(
                    case_id=_string(case.get("case_id")),
                    summary=_string(item.get("summary")),
                    source=_string(item.get("source_url") or item.get("local_path")),
                ).rstrip()
            )
    return "\n".join(lines) + "\n"


def migrate_xlsx_to_jsonl(source: str | Path, output: str | Path) -> None:
    rows = legacy_workbook_rows(source)
    cases = [legacy_row_to_case(row, index + 2) for index, row in enumerate(rows)]
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        "\n".join(json.dumps(case, ensure_ascii=False) for case in cases) + ("\n" if cases else ""),
        encoding="utf-8",
    )


def legacy_workbook_rows(source: str | Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for sheet_name, sheet_rows in data.read_xlsx_sheets(source).items():
        if "标准" in sheet_name or "说明" in sheet_name:
            continue
        for row in sheet_rows:
            if _legacy_row_has_case_data(row):
                rows.append(row)
    return rows


def load_cases(path: str | Path) -> list[dict[str, Any]]:
    return data.load_cases(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _legacy_evidence(row: dict[str, Any]) -> list[dict[str, str]]:
    source = _first_text(row, "赛事来源", "题目来源")
    if not source:
        return []
    return [
        {
            "source_url": "",
            "source_type": "user_provided",
            "title": source,
            "accessed_at": "",
            "summary": "legacy xlsx row",
            "confidence": "low",
            "status": "unverified",
        }
    ]


def _legacy_row_has_case_data(row: dict[str, Any]) -> bool:
    return _text(row.get("名称")) or _text(row.get("题目名称")) or _text(row.get("HUB编号"))


def _is_ignored(path: Path) -> bool:
    parts = set(path.parts)
    return "__pycache__" in parts or ".git" in parts or path.name == ".DS_Store"


def _first_text(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if _text(value):
            return _string(value)
    return ""


def _string(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _text(value: Any) -> bool:
    return bool(_string(value).strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF research and asset collection utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    migrate_parser = subparsers.add_parser("migrate-xlsx", help="convert a legacy xlsx table to ctf_cases.jsonl")
    migrate_parser.add_argument("input")
    migrate_parser.add_argument("output")

    inventory_parser = subparsers.add_parser("asset-inventory", help="scan a local directory and write asset inventory JSON")
    inventory_parser.add_argument("root")
    inventory_parser.add_argument("output")

    report_parser = subparsers.add_parser("research-report", help="render a research report from JSON/JSONL cases")
    report_parser.add_argument("input")
    report_parser.add_argument("output")
    report_parser.add_argument("--title", default="CloverSec CTF 赛题收集报告")

    validate_parser = subparsers.add_parser("validate-collection", help="validate collection evidence fields")
    validate_parser.add_argument("input")
    validate_parser.add_argument("--json", action="store_true", help="write a structured validation result to stdout")

    args = parser.parse_args(argv)

    if args.command == "migrate-xlsx":
        migrate_xlsx_to_jsonl(args.input, args.output)
        print(f"wrote {args.output}")
        return 0

    if args.command == "asset-inventory":
        manifest = build_asset_inventory(args.root)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {output}")
        return 0

    if args.command == "research-report":
        cases = load_cases(args.input)
        Path(args.output).write_text(render_research_report(cases, args.title), encoding="utf-8")
        print(f"wrote {args.output}")
        return 0

    if args.command == "validate-collection":
        cases = load_cases(args.input)
        issues = []
        for case in cases:
            issues.extend(validate_collection_case(case))
        if args.json:
            print(json.dumps({"valid": not issues, "case_count": len(cases), "issues": issues}, ensure_ascii=False, indent=2))
            return 0 if not issues else 1
        if issues:
            print("\n".join(issues), file=sys.stderr)
            return 1
        print(f"validated {len(cases)} case(s)")
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
