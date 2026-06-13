#!/usr/bin/env python3
"""Archive packaging helpers for CloverSec CTF workflows."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any


ARCHIVE_SUBDIRS = ["source", "attachments", "image", "writeup", "screenshots", "manifests"]


def create_archive_package(
    case: dict[str, Any],
    output_root: str | Path,
    *,
    copy_files: bool = True,
) -> dict[str, Any]:
    root = Path(output_root)
    archive_dir = root / archive_folder_name(case)
    for subdir in ARCHIVE_SUBDIRS:
        (archive_dir / subdir).mkdir(parents=True, exist_ok=True)

    issues: list[str] = []
    files: list[dict[str, Any]] = []

    for item in _iter_path_items(case.get("source_files"), default_role="source"):
        files.extend(_copy_or_record(item, archive_dir / "source", "source", copy_files, issues))

    for item in _iter_path_items(case.get("attachments"), default_role="attachment"):
        files.extend(_copy_or_record(item, archive_dir / "attachments", "attachment", copy_files, issues))

    docker_artifacts = case.get("docker_artifacts") if isinstance(case.get("docker_artifacts"), dict) else {}
    tar_path = docker_artifacts.get("tar_path")
    if tar_path:
        files.extend(_copy_or_record({"path": tar_path}, archive_dir / "image", "image_tar", copy_files, issues))

    writeup = case.get("writeup") if isinstance(case.get("writeup"), dict) else {}
    for key in ["manual_path", "manual_filled_draft", "manual_template"]:
        if writeup.get(key):
            files.extend(_copy_or_record({"path": writeup[key]}, archive_dir / "writeup", "writeup", copy_files, issues))

    archive = case.get("archive") if isinstance(case.get("archive"), dict) else {}
    for item in _iter_path_items(archive.get("screenshots"), default_role="screenshot"):
        files.extend(_copy_or_record(item, archive_dir / "screenshots", "screenshot", copy_files, issues))

    image_paths = [item["relative_path"] for item in files if item["role"] == "image_tar"]
    attachment_paths = [item["relative_path"] for item in files if item["role"] == "attachment"]
    manual_paths = [item["relative_path"] for item in files if item["role"] == "writeup"]

    manifest = {
        "case_id": str(case.get("case_id") or ""),
        "archive_dir": archive_dir.as_posix(),
        "files": files,
        "issues": issues,
        "summary": {
            "file_count": len(files),
            "issue_count": len(issues),
            "attachments": len(attachment_paths),
            "image_tars": len(image_paths),
            "writeups": len(manual_paths),
        },
        "xlsx_fields": {
            "是否归档": "是" if not issues else "否",
            "归档目录": archive_dir.as_posix(),
            "环境包/附件包路径": ";".join(image_paths or attachment_paths),
        },
    }
    manifest_path = archive_dir / "manifests" / "archive_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def apply_archive_outputs(case: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    updated = copy.deepcopy(case)
    updated.setdefault("metadata", {})
    updated.setdefault("archive", {})
    updated["archive"]["manifest_path"] = str(Path(manifest["archive_dir"]) / "manifests" / "archive_manifest.json")
    updated["archive"]["files"] = copy.deepcopy(manifest.get("files", []))
    updated["archive"]["issues"] = copy.deepcopy(manifest.get("issues", []))
    for key, value in manifest.get("xlsx_fields", {}).items():
        updated["metadata"][key] = value
    return updated


def archive_folder_name(case: dict[str, Any]) -> str:
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    case_id = str(case.get("case_id") or metadata.get("HUB编号") or "case").strip()
    title = str(metadata.get("名称") or metadata.get("题目标题") or "untitled").strip()
    return f"{_safe_name(case_id)}-{_safe_name(title)}".strip("-") or "case-untitled"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _iter_path_items(value: Any, *, default_role: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items = []
    for item in value:
        if isinstance(item, dict):
            path = item.get("path") or item.get("local_path")
            if path:
                normalized = dict(item)
                normalized.setdefault("role", default_role)
                items.append(normalized)
        elif str(item).strip():
            items.append({"path": str(item), "role": default_role})
    return items


def _copy_or_record(
    item: dict[str, Any],
    target_dir: Path,
    role: str,
    copy_files: bool,
    issues: list[str],
) -> list[dict[str, Any]]:
    source = Path(str(item.get("path") or ""))
    if not source.is_file():
        issues.append(f"missing {role}: {source}")
        return []
    target_name = _safe_filename(str(item.get("name") or source.name))
    target = target_dir / target_name
    if copy_files:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        record_path = target
    else:
        record_path = source
    return [_file_record(record_path, role, target_dir.parent)]


def _file_record(path: Path, role: str, archive_dir: Path) -> dict[str, Any]:
    try:
        relative = path.relative_to(archive_dir).as_posix()
    except ValueError:
        relative = path.as_posix()
    return {
        "role": role,
        "relative_path": relative,
        "path": path.as_posix(),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def _safe_name(value: str) -> str:
    text = re.sub(r"[^\w.-]+", "-", value.strip(), flags=re.UNICODE)
    text = re.sub(r"-+", "-", text).strip(".-")
    return text[:80] or "item"


def _safe_filename(value: str) -> str:
    name = Path(value).name
    return _safe_name(name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF archive packaging utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    package_parser = subparsers.add_parser("package", help="create archive package for one case")
    package_parser.add_argument("--case-json", required=True)
    package_parser.add_argument("--output-root", required=True)
    package_parser.add_argument("--output-case")
    package_parser.add_argument("--no-copy", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "package":
        case = json.loads(Path(args.case_json).read_text(encoding="utf-8"))
        manifest = create_archive_package(case, args.output_root, copy_files=not args.no_copy)
        if args.output_case:
            updated = apply_archive_outputs(case, manifest)
            Path(args.output_case).write_text(json.dumps(updated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {Path(manifest['archive_dir']) / 'manifests' / 'archive_manifest.json'}")
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
