#!/usr/bin/env python3
"""Quality review helpers for CloverSec CTF workflows."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

import cloversec_ctf_data as data


TARGET_PLATFORM = "linux/amd64"


def create_quality_review(
    case: dict[str, Any],
    *,
    archive_dir: str | Path | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    flag = case.get("flag") if isinstance(case.get("flag"), dict) else {}
    docker_artifacts = case.get("docker_artifacts") if isinstance(case.get("docker_artifacts"), dict) else {}
    writeup = case.get("writeup") if isinstance(case.get("writeup"), dict) else {}

    validation_errors = data.validate_case(case)
    _add_check(
        checks,
        "data-model",
        "数据模型与 xlsx 必填字段",
        "pass" if not validation_errors else "fail",
        "字段完整" if not validation_errors else "; ".join(validation_errors),
    )

    _add_check(
        checks,
        "full-flag",
        "完整 Flag",
        "pass" if _text(flag.get("value")) else "fail",
        "Flag 已进入结构化字段" if _text(flag.get("value")) else "flag.value 为空",
    )

    manual_paths = _manual_paths(writeup)
    if manual_paths:
        _check_paths(checks, "manual-files", "手册文件", manual_paths, archive_dir=archive_dir)
    else:
        _add_check(checks, "manual-files", "手册文件", "skip", "writeup 中没有手册路径")

    attachments = [item.get("path") or item.get("local_path") for item in case.get("attachments", []) if isinstance(item, dict)]
    if attachments:
        _check_paths(checks, "attachment-files", "附件文件", attachments, archive_dir=archive_dir)
    else:
        _add_check(checks, "attachment-files", "附件文件", "skip", "attachments 为空")

    source_files = [item.get("path") or item.get("local_path") for item in case.get("source_files", []) if isinstance(item, dict)]
    if source_files:
        _check_paths(checks, "source-files", "源码文件", source_files, archive_dir=archive_dir)
    else:
        _add_check(checks, "source-files", "源码文件", "skip", "source_files 为空")

    tar_path = docker_artifacts.get("tar_path")
    if tar_path:
        _check_paths(checks, "image-tar", "镜像 tar", [tar_path], archive_dir=archive_dir)
    else:
        _add_check(checks, "image-tar", "镜像 tar", "skip", "docker_artifacts.tar_path 为空")

    platform = docker_artifacts.get("platform")
    if platform:
        _add_check(
            checks,
            "image-platform",
            "镜像平台",
            "pass" if platform == TARGET_PLATFORM else "fail",
            f"platform={platform}",
        )
    else:
        _add_check(checks, "image-platform", "镜像平台", "skip", "docker_artifacts.platform 为空")

    if docker_artifacts.get("run_verified") is True:
        _add_check(checks, "docker-run", "镜像启动验证", "pass", "docker_artifacts.run_verified=true")
    else:
        _add_check(checks, "docker-run", "镜像启动验证", "skip", "没有真实 Docker run 验证记录")

    if writeup.get("solve_verified") is True:
        _add_check(checks, "solve-proof", "手册解题验证", "pass", "writeup.solve_verified=true")
    else:
        _add_check(checks, "solve-proof", "手册解题验证", "skip", "没有按手册解出 Flag 的验证记录")

    if _text(metadata.get("名称")) and _text(writeup.get("title")) and metadata.get("名称") != writeup.get("title"):
        _add_check(checks, "title-consistency", "题名一致性", "fail", "metadata.名称 与 writeup.title 不一致")
    else:
        _add_check(checks, "title-consistency", "题名一致性", "pass", "未发现题名冲突")

    status = _overall_status(checks)
    issues = [f"{item['name']}: {item['message']}" for item in checks if item["status"] != "pass"]
    xlsx_fields = {
        "验证状态": status,
        "是否通过": "是" if status == "通过" else "否",
        "问题": "；".join(issues),
        "手册状态": _manual_status(manual_paths, writeup),
    }
    return {
        "case_id": str(case.get("case_id") or ""),
        "checks": checks,
        "summary": {
            "pass": sum(1 for item in checks if item["status"] == "pass"),
            "fail": sum(1 for item in checks if item["status"] == "fail"),
            "skip": sum(1 for item in checks if item["status"] == "skip"),
            "status": status,
        },
        "xlsx_fields": xlsx_fields,
    }


def apply_review_outputs(case: dict[str, Any], review: dict[str, Any]) -> dict[str, Any]:
    updated = copy.deepcopy(case)
    updated.setdefault("metadata", {})
    updated["review"] = copy.deepcopy(review)
    for key, value in review.get("xlsx_fields", {}).items():
        updated["metadata"][key] = value
    return updated


def render_review_markdown(review: dict[str, Any]) -> str:
    lines = [
        "# 质量检查报告",
        "",
        f"- 题目 ID：{review.get('case_id', '')}",
        f"- 验证状态：{review.get('summary', {}).get('status', '')}",
        f"- 通过：{review.get('summary', {}).get('pass', 0)}",
        f"- 失败：{review.get('summary', {}).get('fail', 0)}",
        f"- 未执行：{review.get('summary', {}).get('skip', 0)}",
        "",
        "| 检查项 | 状态 | 说明 |",
        "|---|---|---|",
    ]
    for item in review.get("checks", []):
        lines.append(f"| {item.get('name', '')} | {item.get('status', '')} | {_escape_table(item.get('message', ''))} |")
    lines.extend(["", "## xlsx 字段建议", ""])
    for key, value in review.get("xlsx_fields", {}).items():
        lines.append(f"- {key}：{value}")
    return "\n".join(lines) + "\n"


def _check_paths(
    checks: list[dict[str, str]],
    check_id: str,
    name: str,
    paths: list[Any],
    *,
    archive_dir: str | Path | None,
) -> None:
    missing = []
    for raw_path in paths:
        if not _path_exists(raw_path, archive_dir=archive_dir):
            missing.append(str(raw_path))
    _add_check(
        checks,
        check_id,
        name,
        "pass" if not missing else "fail",
        "文件存在" if not missing else "缺失文件：" + ", ".join(missing),
    )


def _path_exists(raw_path: Any, *, archive_dir: str | Path | None) -> bool:
    if not _text(raw_path):
        return False
    path = Path(str(raw_path))
    if path.exists():
        return True
    if archive_dir:
        archive_path = Path(archive_dir) / path
        if archive_path.exists():
            return True
    return False


def _manual_paths(writeup: dict[str, Any]) -> list[str]:
    paths = []
    for key in ["manual_path", "manual_filled_draft", "manual_template"]:
        if _text(writeup.get(key)):
            paths.append(str(writeup[key]))
    return paths


def _manual_status(manual_paths: list[str], writeup: dict[str, Any]) -> str:
    if not manual_paths:
        return "未开始"
    if writeup.get("solve_verified") is True:
        return "已校验"
    return "待人工完善"


def _overall_status(checks: list[dict[str, str]]) -> str:
    if any(item["status"] == "fail" for item in checks):
        return "失败"
    if any(item["status"] == "skip" for item in checks):
        return "部分通过"
    return "通过"


def _add_check(checks: list[dict[str, str]], check_id: str, name: str, status: str, message: str) -> None:
    checks.append({"id": check_id, "name": name, "status": status, "message": message})


def _escape_table(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _text(value: Any) -> bool:
    return bool(str(value or "").strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF quality review utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    review_parser = subparsers.add_parser("review", help="create quality review report")
    review_parser.add_argument("--case-json", required=True)
    review_parser.add_argument("--output-dir", required=True)
    review_parser.add_argument("--archive-dir")
    review_parser.add_argument("--output-case")

    args = parser.parse_args(argv)
    if args.command == "review":
        case = json.loads(Path(args.case_json).read_text(encoding="utf-8"))
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        review = create_quality_review(case, archive_dir=args.archive_dir)
        (output_dir / "quality_review.json").write_text(
            json.dumps(review, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        (output_dir / "quality_review_report.md").write_text(render_review_markdown(review), encoding="utf-8")
        if args.output_case:
            updated = apply_review_outputs(case, review)
            Path(args.output_case).write_text(json.dumps(updated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {output_dir / 'quality_review.json'}")
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
