#!/usr/bin/env python3
"""Batch archive workflow runner for CloverSec CTF cases."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import cloversec_ctf_archive as archive
import cloversec_ctf_data as data
import cloversec_ctf_final as final


def run_archive_workflow(
    *,
    cases_path: str | Path,
    output_root: str | Path,
    output_cases: str | Path = "",
    final_output_dir: str | Path = "",
    copy_files: bool = True,
    copy_image_tars: bool = False,
) -> dict[str, Any]:
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)
    cases = data.load_cases(cases_path)
    archive_payload = archive.create_batch_archive(cases, root, copy_files=copy_files, copy_image_tars=copy_image_tars)
    archived_cases = archive_payload["updated_cases"]

    cache_dir = root / "_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    output_cases_path = Path(output_cases) if str(output_cases).strip() else cache_dir / "ctf_cases.archived.jsonl"
    archive.write_cases_jsonl(archived_cases, output_cases_path)

    final_dir = Path(final_output_dir) if str(final_output_dir).strip() else root / "_final"
    final_payload = final.create_final_outputs(archived_cases, final_dir, base_dir=Path.cwd())

    resource_index = build_resource_index(archive_payload["manifests"])
    missing_report = build_missing_report(archive_payload, final_payload)
    resource_index_path = cache_dir / "resource_index.json"
    missing_report_path = cache_dir / "missing_report.md"
    resource_index_path.write_text(json.dumps(resource_index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    missing_report_path.write_text(render_missing_report(missing_report), encoding="utf-8")

    summary = {
        "cases": len(cases),
        "archived": archive_payload.get("summary", {}).get("archived", 0),
        "with_issues": archive_payload.get("summary", {}).get("with_issues", 0),
        "resource_count": resource_index["summary"]["resource_count"],
        "missing_count": missing_report["summary"]["missing_count"],
        "remaining_actions": final_payload.get("summary", {}).get("remaining_actions", 0),
        "output_cases": output_cases_path.as_posix(),
        "resource_index": resource_index_path.as_posix(),
        "missing_report": missing_report_path.as_posix(),
        "final_xlsx": final_payload.get("summary", {}).get("xlsx_path", ""),
        "yuque_table": final_payload.get("summary", {}).get("yuque_table_path", ""),
        "final_report": final_payload.get("summary", {}).get("report_path", ""),
    }
    payload = {
        "schema_version": "cloversec.ctf.archive_workflow.v1",
        "summary": summary,
        "archive_summary": archive_payload.get("summary", {}),
        "final_summary": final_payload.get("summary", {}),
        "paths": {
            "output_root": root.as_posix(),
            "output_cases": output_cases_path.as_posix(),
            "resource_index": resource_index_path.as_posix(),
            "missing_report": missing_report_path.as_posix(),
            "final_dir": final_dir.as_posix(),
        },
    }
    workflow_path = cache_dir / "archive_workflow.json"
    workflow_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    payload["paths"]["workflow"] = workflow_path.as_posix()
    return payload


def build_resource_index(manifests: list[dict[str, Any]]) -> dict[str, Any]:
    resources = []
    for manifest in manifests:
        case_id = str(manifest.get("case_id") or "")
        for item in manifest.get("files", []):
            if not isinstance(item, dict):
                continue
            resources.append(
                {
                    "case_id": case_id,
                    "role": item.get("role", ""),
                    "relative_path": item.get("relative_path", ""),
                    "path": item.get("path", ""),
                    "size": item.get("size", 0),
                    "sha256": item.get("sha256", ""),
                }
            )
    by_role: dict[str, int] = {}
    for item in resources:
        role = str(item.get("role") or "unknown")
        by_role[role] = by_role.get(role, 0) + 1
    return {
        "schema_version": "cloversec.ctf.resource_index.v1",
        "summary": {"resource_count": len(resources), "by_role": by_role},
        "resources": resources,
    }


def build_missing_report(archive_payload: dict[str, Any], final_payload: dict[str, Any]) -> dict[str, Any]:
    items = []
    for manifest in archive_payload.get("manifests", []):
        for issue in manifest.get("issues", []):
            items.append({"case_id": manifest.get("case_id", ""), "source": "archive", "message": str(issue)})
    for issue in final_payload.get("remaining_actions", []):
        items.append({"case_id": "", "source": "final", "message": str(issue)})
    return {
        "schema_version": "cloversec.ctf.missing_report.v1",
        "summary": {"missing_count": len(items)},
        "items": items,
    }


def render_missing_report(report: dict[str, Any]) -> str:
    lines = [
        "# 缺失项报告",
        "",
        f"- 缺失/待处理数量：{report.get('summary', {}).get('missing_count', 0)}",
        "",
        "| 来源 | 题目 ID | 说明 |",
        "|---|---|---|",
    ]
    for item in report.get("items", []):
        lines.append(
            "| "
            + " | ".join(escape_table(value) for value in [item.get("source", ""), item.get("case_id", ""), item.get("message", "")])
            + " |"
        )
    return "\n".join(lines) + "\n"


def compact_archive_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "cloversec.ctf.archive_workflow.compact.v1",
        "summary": payload.get("summary", {}),
        "paths": payload.get("paths", {}),
        "response_note": "短 JSON 默认返回。完整归档、资源索引、缺失项报告、xlsx 和语雀表见 paths。",
    }


def escape_table(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF batch archive workflow")
    parser.add_argument("--cases", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--output-cases", default="")
    parser.add_argument("--final-output-dir", default="")
    parser.add_argument("--no-copy", action="store_true")
    parser.add_argument("--copy-image-tars", action="store_true")
    parser.add_argument("--compact-output")
    args = parser.parse_args(argv)
    payload = run_archive_workflow(
        cases_path=args.cases,
        output_root=args.output_root,
        output_cases=args.output_cases,
        final_output_dir=args.final_output_dir,
        copy_files=not args.no_copy,
        copy_image_tars=args.copy_image_tars,
    )
    if args.compact_output:
        output = Path(args.compact_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(compact_archive_payload(payload), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {payload['paths']['workflow']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
