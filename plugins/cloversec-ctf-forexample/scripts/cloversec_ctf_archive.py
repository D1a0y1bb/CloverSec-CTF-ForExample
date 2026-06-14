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

import cloversec_ctf_data as data


ARCHIVE_SUBDIRS = ["源码", "附件", "镜像", "手册", "截图", "清单"]
ROLE_DIRS = {
    "source": "源码",
    "attachment": "附件",
    "image_tar": "镜像",
    "writeup": "手册",
    "screenshot": "截图",
    "manifest": "清单",
}


def create_archive_package(
    case: dict[str, Any],
    output_root: str | Path,
    *,
    copy_files: bool = True,
    copy_image_tars: bool = False,
) -> dict[str, Any]:
    root = Path(output_root)
    archive_dir = root / archive_folder_name(case)
    for subdir in ARCHIVE_SUBDIRS:
        (archive_dir / subdir).mkdir(parents=True, exist_ok=True)

    issues: list[str] = []
    files: list[dict[str, Any]] = []

    for item in _iter_path_items(case.get("source_files"), default_role="source"):
        files.extend(_copy_or_record(item, archive_dir / ROLE_DIRS["source"], "source", copy_files, issues))

    for item in _iter_path_items(case.get("attachments"), default_role="attachment"):
        files.extend(_copy_or_record(item, archive_dir / ROLE_DIRS["attachment"], "attachment", copy_files, issues))

    docker_artifacts = case.get("docker_artifacts") if isinstance(case.get("docker_artifacts"), dict) else {}
    tar_path = docker_artifacts.get("tar_path")
    if tar_path:
        files.extend(
            _copy_or_record(
                {"path": tar_path},
                archive_dir / ROLE_DIRS["image_tar"],
                "image_tar",
                copy_files and copy_image_tars,
                issues,
                force_reference=not (copy_files and copy_image_tars),
            )
        )

    writeup = case.get("writeup") if isinstance(case.get("writeup"), dict) else {}
    manual_inputs: list[dict[str, Any]] = []
    for key in ["manual_path", "manual_filled_draft", "manual_template"]:
        if writeup.get(key):
            manual_inputs.append({"path": writeup[key]})
    if manual_inputs:
        for item in manual_inputs:
            files.extend(_copy_or_record(item, archive_dir / ROLE_DIRS["writeup"], "writeup", copy_files, issues))
    else:
        issues.append("missing writeup: writeup.manual_path/manual_filled_draft/manual_template 为空")

    archive = case.get("archive") if isinstance(case.get("archive"), dict) else {}
    screenshot_inputs = _iter_path_items(archive.get("screenshots"), default_role="screenshot")
    if screenshot_inputs:
        for item in screenshot_inputs:
            files.extend(_copy_or_record(item, archive_dir / ROLE_DIRS["screenshot"], "screenshot", copy_files, issues))
    else:
        issues.append("missing screenshot: archive.screenshots 为空")
    issues.extend(_verification_issues(case))

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
    manifest_path = archive_dir / ROLE_DIRS["manifest"] / "archive_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def apply_archive_outputs(case: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    updated = copy.deepcopy(case)
    updated.setdefault("metadata", {})
    updated.setdefault("archive", {})
    updated["archive"]["manifest_path"] = str(Path(manifest["archive_dir"]) / ROLE_DIRS["manifest"] / "archive_manifest.json")
    updated["archive"]["files"] = copy.deepcopy(manifest.get("files", []))
    updated["archive"]["issues"] = copy.deepcopy(manifest.get("issues", []))
    for key, value in manifest.get("xlsx_fields", {}).items():
        updated["metadata"][key] = value
    return updated


def _verification_issues(case: dict[str, Any]) -> list[str]:
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    issues: list[str] = []
    validation_status = str(metadata.get("验证状态") or "").strip()
    passed = str(metadata.get("是否通过") or "").strip()
    if validation_status != "通过":
        issues.append(f"validation not passed: 验证状态为{validation_status or '空'}")
    if passed != "是":
        issues.append(f"validation not passed: 是否通过为{passed or '空'}")
    return issues


def create_batch_archive(
    cases: list[dict[str, Any]],
    output_root: str | Path,
    *,
    copy_files: bool = True,
    copy_image_tars: bool = False,
) -> dict[str, Any]:
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)
    manifests = []
    updated_cases = []
    for case in cases:
        manifest = create_archive_package(case, root, copy_files=copy_files, copy_image_tars=copy_image_tars)
        manifests.append(manifest)
        updated_cases.append(apply_archive_outputs(case, manifest))

    summary = {
        "total": len(cases),
        "archived": sum(1 for item in manifests if not item.get("issues")),
        "with_issues": sum(1 for item in manifests if item.get("issues")),
        "file_count": sum(int(item.get("summary", {}).get("file_count", 0)) for item in manifests),
        "issue_count": sum(int(item.get("summary", {}).get("issue_count", 0)) for item in manifests),
    }
    payload = {
        "summary": summary,
        "manifests": manifests,
        "updated_cases": updated_cases,
    }
    batch_dir = root / "_batch"
    batch_dir.mkdir(parents=True, exist_ok=True)
    (batch_dir / "batch_archive_summary.json").write_text(
        json.dumps({"summary": summary, "manifests": manifests}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (batch_dir / "batch_archive_report.md").write_text(render_batch_archive_report(payload), encoding="utf-8")
    return payload


def write_cases_jsonl(cases: list[dict[str, Any]], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "".join(json.dumps(case, ensure_ascii=False) + "\n" for case in cases),
        encoding="utf-8",
    )


def render_batch_archive_report(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines = [
        "# 批量归档报告",
        "",
        f"- 题目数量：{summary.get('total', 0)}",
        f"- 成功归档：{summary.get('archived', 0)}",
        f"- 有问题：{summary.get('with_issues', 0)}",
        f"- 文件数：{summary.get('file_count', 0)}",
        f"- 问题数：{summary.get('issue_count', 0)}",
        "",
        "| 题目 ID | 归档目录 | 文件数 | 问题数 |",
        "|---|---|---|---|",
    ]
    for manifest in payload.get("manifests", []):
        lines.append(
            "| "
            + " | ".join(
                _escape_table(value)
                for value in [
                    manifest.get("case_id", ""),
                    manifest.get("archive_dir", ""),
                    manifest.get("summary", {}).get("file_count", 0),
                    manifest.get("summary", {}).get("issue_count", 0),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


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
    *,
    force_reference: bool = False,
) -> list[dict[str, Any]]:
    source = Path(str(item.get("path") or ""))
    if not source.is_file():
        issues.append(f"missing {role}: {source}")
        return []
    target_name = _safe_filename(str(item.get("name") or source.name))
    target = target_dir / target_name
    if copy_files and not force_reference:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        record_path = target
        status = "copied"
    else:
        record_path = source
        status = "referenced"
    return [_file_record(record_path, role, target_dir.parent, status=status)]


def _file_record(path: Path, role: str, archive_dir: Path, *, status: str = "present") -> dict[str, Any]:
    try:
        relative = path.relative_to(archive_dir).as_posix()
    except ValueError:
        relative = path.as_posix()
    return {
        "role": role,
        "status": status,
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


def _escape_table(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF archive packaging utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    package_parser = subparsers.add_parser("package", help="create archive package for one case")
    package_parser.add_argument("--case-json", required=True)
    package_parser.add_argument("--output-root", required=True)
    package_parser.add_argument("--output-case")
    package_parser.add_argument("--no-copy", action="store_true")
    package_parser.add_argument("--copy-image-tars", action="store_true")

    batch_parser = subparsers.add_parser("batch", help="create archive packages for ctf_cases.jsonl")
    batch_parser.add_argument("--cases", required=True)
    batch_parser.add_argument("--output-root", required=True)
    batch_parser.add_argument("--output-cases")
    batch_parser.add_argument("--final-output-dir")
    batch_parser.add_argument("--no-copy", action="store_true")
    batch_parser.add_argument("--copy-image-tars", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "package":
        case = json.loads(Path(args.case_json).read_text(encoding="utf-8"))
        manifest = create_archive_package(case, args.output_root, copy_files=not args.no_copy, copy_image_tars=args.copy_image_tars)
        if args.output_case:
            updated = apply_archive_outputs(case, manifest)
            Path(args.output_case).write_text(json.dumps(updated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {Path(manifest['archive_dir']) / 'manifests' / 'archive_manifest.json'}")
        return 0

    if args.command == "batch":
        cases = data.load_cases(args.cases)
        payload = create_batch_archive(cases, args.output_root, copy_files=not args.no_copy, copy_image_tars=args.copy_image_tars)
        if args.output_cases:
            write_cases_jsonl(payload["updated_cases"], args.output_cases)
        if args.final_output_dir:
            import cloversec_ctf_final as final

            final.create_final_outputs(payload["updated_cases"], args.final_output_dir)
        summary_path = Path(args.output_root) / "_batch" / "batch_archive_summary.json"
        print(f"wrote {summary_path}")
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
