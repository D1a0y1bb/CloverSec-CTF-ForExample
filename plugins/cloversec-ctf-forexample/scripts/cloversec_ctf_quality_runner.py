#!/usr/bin/env python3
"""Batch quality runner for CloverSec CTF cases."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import cloversec_ctf_data as data
import cloversec_ctf_review as review


def run_quality_batch(
    *,
    cases_path: str | Path,
    output_dir: str | Path,
    output_cases: str | Path = "",
    execute_docker: bool = False,
    archive_dir: str | Path = "",
    startup_wait: float = 2.0,
    command_timeout: int = 30,
    probe_timeout: float = 3.0,
    probe_urls: list[str] | None = None,
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    cases = data.load_cases(cases_path)
    updated_cases = []
    entries = []
    for index, case in enumerate(cases, start=1):
        case_id = str(case.get("case_id") or f"case-{index}")
        case_dir = output / safe_path_part(case_id)
        case_dir.mkdir(parents=True, exist_ok=True)
        case_archive_dir = resolve_archive_dir(case, archive_dir)
        docker_execution = None
        if execute_docker:
            docker_execution = review.execute_docker_review(
                case,
                case_dir,
                startup_wait=startup_wait,
                command_timeout=command_timeout,
                probe_timeout=probe_timeout,
                probe_urls=probe_urls or [],
            )
            (case_dir / "docker_execution.json").write_text(
                json.dumps(docker_execution, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        quality = review.create_quality_review(case, archive_dir=case_archive_dir, docker_execution=docker_execution)
        (case_dir / "quality_review.json").write_text(json.dumps(quality, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (case_dir / "quality_review_report.md").write_text(review.render_review_markdown(quality), encoding="utf-8")
        updated = review.apply_review_outputs(case, quality)
        updated_cases.append(updated)
        entries.append(
            {
                "case_id": case_id,
                "status": quality.get("summary", {}).get("status", ""),
                "pass": quality.get("summary", {}).get("pass", 0),
                "fail": quality.get("summary", {}).get("fail", 0),
                "skip": quality.get("summary", {}).get("skip", 0),
                "quality_review": (case_dir / "quality_review.json").as_posix(),
                "quality_report": (case_dir / "quality_review_report.md").as_posix(),
                "docker_evidence": (case_dir / "docker_execution.json").as_posix() if docker_execution else "",
                "issues": [
                    f"{item.get('id', '')}: {item.get('name', '')}: {item.get('message', '')}"
                    for item in quality.get("checks", [])
                    if item.get("status") != "pass"
                ],
            }
        )

    output_cases_path = Path(output_cases) if str(output_cases).strip() else output / "ctf_cases.reviewed.jsonl"
    output_cases_path.write_text("".join(json.dumps(case, ensure_ascii=False) + "\n" for case in updated_cases), encoding="utf-8")
    summary = build_summary(entries, output_cases_path)
    payload = {
        "schema_version": "cloversec.ctf.quality_batch.v1",
        "summary": summary,
        "entries": entries,
        "paths": {
            "output_dir": output.as_posix(),
            "output_cases": output_cases_path.as_posix(),
            "summary_json": (output / "quality_summary.json").as_posix(),
            "summary_report": (output / "quality_summary.md").as_posix(),
        },
    }
    (output / "quality_summary.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "quality_summary.md").write_text(render_quality_summary(payload), encoding="utf-8")
    return payload


def build_summary(entries: list[dict[str, Any]], output_cases_path: Path) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    for entry in entries:
        status = str(entry.get("status") or "unknown")
        by_status[status] = by_status.get(status, 0) + 1
    return {
        "total": len(entries),
        "by_status": by_status,
        "with_failures": sum(1 for item in entries if int(item.get("fail", 0)) > 0),
        "with_skips": sum(1 for item in entries if int(item.get("skip", 0)) > 0),
        "output_cases": output_cases_path.as_posix(),
    }


def render_quality_summary(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines = [
        "# 批量质量检查报告",
        "",
        f"- 题目数量：{summary.get('total', 0)}",
        f"- 有失败项：{summary.get('with_failures', 0)}",
        f"- 有未执行项：{summary.get('with_skips', 0)}",
        f"- 输出 cases：{summary.get('output_cases', '')}",
        "",
        "| 题目 ID | 状态 | 通过 | 失败 | 未执行 | 报告 |",
        "|---|---|---|---|---|---|",
    ]
    for entry in payload.get("entries", []):
        lines.append(
            "| "
            + " | ".join(
                escape_table(value)
                for value in [
                    entry.get("case_id", ""),
                    entry.get("status", ""),
                    entry.get("pass", 0),
                    entry.get("fail", 0),
                    entry.get("skip", 0),
                    entry.get("quality_report", ""),
                ]
            )
            + " |"
        )
    issues = [(entry.get("case_id", ""), issue) for entry in payload.get("entries", []) for issue in entry.get("issues", [])]
    if issues:
        lines.extend(["", "## 待处理/复核项", ""])
        for case_id, issue in issues:
            lines.append(f"- {case_id}: {issue}")
    return "\n".join(lines) + "\n"


def compact_quality_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "cloversec.ctf.quality_batch.compact.v1",
        "summary": payload.get("summary", {}),
        "paths": payload.get("paths", {}),
        "entries": [
            {
                "case_id": item.get("case_id", ""),
                "status": item.get("status", ""),
                "fail": item.get("fail", 0),
                "skip": item.get("skip", 0),
                "quality_report": item.get("quality_report", ""),
                "docker_evidence": item.get("docker_evidence", ""),
                "issues": item.get("issues", [])[:5],
            }
            for item in payload.get("entries", [])[:20]
        ],
        "response_note": "短 JSON 默认返回。完整质量证据见 paths.summary_json 和每题 quality_review。",
    }


def resolve_archive_dir(case: dict[str, Any], archive_dir: str | Path) -> str:
    if str(archive_dir).strip():
        return str(archive_dir)
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    if str(metadata.get("归档目录") or "").strip():
        return str(metadata["归档目录"])
    archive_info = case.get("archive") if isinstance(case.get("archive"), dict) else {}
    manifest = str(archive_info.get("manifest_path") or "")
    if manifest:
        return str(Path(manifest).parents[1]) if len(Path(manifest).parents) >= 2 else str(Path(manifest).parent)
    return ""


def safe_path_part(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in value).strip(".-")[:80] or "case"


def escape_table(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF batch quality runner")
    parser.add_argument("--cases", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--output-cases", default="")
    parser.add_argument("--execute-docker", action="store_true")
    parser.add_argument("--archive-dir", default="")
    parser.add_argument("--probe-url", action="append", default=[])
    parser.add_argument("--startup-wait", type=float, default=2.0)
    parser.add_argument("--command-timeout", type=int, default=30)
    parser.add_argument("--probe-timeout", type=float, default=3.0)
    parser.add_argument("--compact-output")
    args = parser.parse_args(argv)
    payload = run_quality_batch(
        cases_path=args.cases,
        output_dir=args.output_dir,
        output_cases=args.output_cases,
        execute_docker=args.execute_docker,
        archive_dir=args.archive_dir,
        startup_wait=args.startup_wait,
        command_timeout=args.command_timeout,
        probe_timeout=args.probe_timeout,
        probe_urls=args.probe_url,
    )
    if args.compact_output:
        output = Path(args.compact_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(compact_quality_payload(payload), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {payload['paths']['summary_json']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
