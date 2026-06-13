#!/usr/bin/env python3
"""Hub submission package helpers for CloverSec CTF workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any


def default_screenshot_plan() -> list[dict[str, str]]:
    return [
        {"filename": "01-challenge-page.png", "description": "题目页面或题目信息截图"},
        {"filename": "02-container-running.png", "description": "容器运行或服务访问截图"},
        {"filename": "03-solve-proof.png", "description": "解题验证截图"},
    ]


def create_submission_package(
    case: dict[str, Any],
    hub_fields: dict[str, Any],
    manual_markdown: str,
    output_dir: str | Path,
) -> dict[str, Any]:
    root = Path(output_dir)
    fields_dir = root / "fields"
    manual_dir = root / "manual"
    attachments_dir = root / "attachments"
    images_dir = root / "images"
    screenshots_dir = root / "screenshots"
    manifests_dir = root / "manifests"
    for directory in [fields_dir, manual_dir, attachments_dir, images_dir, screenshots_dir, manifests_dir]:
        directory.mkdir(parents=True, exist_ok=True)

    (fields_dir / "hub_fields.json").write_text(json.dumps(hub_fields, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (fields_dir / "hub_fields_preview.json").write_text(json.dumps(hub_fields, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (manual_dir / "manual_filled_draft.md").write_text(manual_markdown, encoding="utf-8")

    upload_files: list[dict[str, Any]] = []
    issues: list[str] = []
    for item in case.get("attachments", []) if isinstance(case.get("attachments"), list) else []:
        source = Path(item.get("path", ""))
        copied = _copy_file(source, attachments_dir / (item.get("name") or source.name), issues)
        if copied:
            upload_files.append(_file_record(copied, "attachment"))

    docker_artifacts = case.get("docker_artifacts") if isinstance(case.get("docker_artifacts"), dict) else {}
    tar_path = docker_artifacts.get("tar_path")
    if tar_path:
        source = Path(tar_path)
        copied = _copy_file(source, images_dir / source.name, issues)
        if copied:
            upload_files.append(_file_record(copied, "image_tar"))

    screenshot_records = []
    screenshot_sources = []
    archive = case.get("archive") if isinstance(case.get("archive"), dict) else {}
    if isinstance(archive.get("screenshots"), list):
        screenshot_sources = [Path(item) for item in archive["screenshots"]]
    for index, plan in enumerate(default_screenshot_plan()):
        record = dict(plan)
        if index < len(screenshot_sources):
            copied = _copy_file(screenshot_sources[index], screenshots_dir / plan["filename"], issues)
            if copied:
                record.update(_file_record(copied, "screenshot"))
        screenshot_records.append(record)

    manifest = {
        "case_id": case.get("case_id", ""),
        "hub_fields": hub_fields,
        "upload_files": upload_files,
        "screenshots": screenshot_records,
        "issues": issues,
        "summary": {
            "total_upload_files": len(upload_files),
            "screenshot_slots": len(screenshot_records),
            "issues": len(issues),
        },
    }
    (manifests_dir / "upload_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (root / "hub_submission_checklist.md").write_text(render_checklist(manifest), encoding="utf-8")
    return manifest


def render_checklist(manifest: dict[str, Any]) -> str:
    fields = manifest.get("hub_fields", {})
    lines = [
        "# Hub 提交核对清单",
        "",
        "## 表单字段",
        "",
        f"- 题目标题：{fields.get('题目标题', '')}",
        f"- 题目分类：{fields.get('题目分类', '')}",
        f"- Flag类型：{fields.get('Flag类型', '')}",
        f"- 题目类型：{fields.get('题目类型', '')}",
        f"- 题目等级：{fields.get('题目等级', '')}",
        "",
        "## 上传文件",
        "",
    ]
    upload_files = manifest.get("upload_files", [])
    if upload_files:
        for item in upload_files:
            lines.append(f"- {item['role']}：{item['relative_path']}，SHA256 `{item['sha256']}`")
    else:
        lines.append("- 暂无上传文件。")
    lines.extend(["", "## 截图", ""])
    for item in manifest.get("screenshots", []):
        lines.append(f"- {item['filename']}：{item['description']}")
    if manifest.get("issues"):
        lines.extend(["", "## 待处理问题", ""])
        lines.extend(f"- {issue}" for issue in manifest["issues"])
    return "\n".join(lines) + "\n"


def _copy_file(source: Path, target: Path, issues: list[str]) -> Path | None:
    if not source.exists() or not source.is_file():
        issues.append(f"missing file: {source}")
        return None
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    return target


def _file_record(path: Path, role: str) -> dict[str, Any]:
    return {
        "role": role,
        "relative_path": path.parent.name + "/" + path.name,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF Hub submission package utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    package_parser = subparsers.add_parser("package", help="create Hub submission package")
    package_parser.add_argument("--case-json", required=True)
    package_parser.add_argument("--hub-fields", required=True)
    package_parser.add_argument("--manual", required=True)
    package_parser.add_argument("--output-dir", required=True)

    args = parser.parse_args(argv)
    if args.command == "package":
        case = json.loads(Path(args.case_json).read_text(encoding="utf-8"))
        fields = json.loads(Path(args.hub_fields).read_text(encoding="utf-8"))
        manual = Path(args.manual).read_text(encoding="utf-8")
        create_submission_package(case, fields, manual, args.output_dir)
        print(f"wrote {args.output_dir}")
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
