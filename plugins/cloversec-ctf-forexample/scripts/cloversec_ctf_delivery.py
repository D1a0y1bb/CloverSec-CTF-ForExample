#!/usr/bin/env python3
"""Create a human-readable CloverSec CTF delivery folder."""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "cloversec.ctf.delivery.v1"
VERSION = "0.9.9-beta"
DEFAULT_COPY_LIMIT = 300 * 1024 * 1024

ROOT_FILES = ["最终归档表.xlsx", "语雀粘贴表.md", "交付说明.md"]
CHALLENGE_SUBDIRS = ["题目源码", "题目镜像", "题目手册", "题目附件"]
IMAGE_SUFFIXES = {".tar", ".gz", ".tgz"}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def create_delivery_package(
    *,
    workdir: str | Path,
    outputs_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
    copy_limit: int = DEFAULT_COPY_LIMIT,
    copy_image_tars: bool = True,
) -> dict[str, Any]:
    work = Path(workdir)
    if not work.exists():
        raise FileNotFoundError(work)
    outputs = Path(outputs_dir) if outputs_dir else guess_outputs_dir(work)
    if not outputs.exists():
        raise FileNotFoundError(outputs)
    delivery = Path(output_dir) if output_dir else outputs / f"交付包-{safe_display_name(work.name)}"
    delivery.mkdir(parents=True, exist_ok=True)

    selected = select_delivery_sources(work, outputs)
    files: list[dict[str, Any]] = []
    missing: list[dict[str, str]] = []

    add_record(copy_or_reference(selected.get("final_xlsx"), delivery / "最终归档表.xlsx", key="final_xlsx", copy_limit=copy_limit, force_reference=False), files, missing)
    add_record(copy_or_reference(selected.get("yuque_table"), delivery / "语雀粘贴表.md", key="yuque_table", copy_limit=copy_limit, force_reference=False), files, missing)

    challenge_records = copy_challenge_archives(
        archive_roots=selected.get("archive_roots", []),
        delivery=delivery,
        copy_limit=copy_limit,
        copy_image_tars=copy_image_tars,
    )
    files.extend(challenge_records["files"])
    missing.extend(challenge_records["missing"])

    cleanup_ds_store(delivery)
    summary = build_summary(work, outputs, delivery, files, missing, selected)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "version": VERSION,
        "generated_at": utc_now(),
        "summary": summary,
        "paths": {
            "workdir": work.as_posix(),
            "outputs_dir": outputs.as_posix(),
            "delivery_dir": delivery.as_posix(),
        },
        "files": files,
        "missing": missing,
        "package_issues": [],
        "selected_sources": {
            key: path.as_posix()
            for key, path in selected.items()
            if isinstance(path, Path)
        },
        "archive_roots": [path.as_posix() for path in selected.get("archive_roots", [])],
        "challenges": challenge_records["challenges"],
        "image_tars": challenge_records["image_tars"],
    }
    readme_path = delivery / "交付说明.md"
    manifest["paths"]["readme"] = readme_path.as_posix()
    readme_path.write_text(render_delivery_readme(manifest), encoding="utf-8")
    cleanup_ds_store(delivery)
    package_issues = scan_delivery_package(delivery)
    manifest["package_issues"] = package_issues
    manifest["summary"]["package_issues"] = len(package_issues)
    readme_path.write_text(render_delivery_readme(manifest), encoding="utf-8")
    return manifest


def guess_outputs_dir(workdir: Path) -> Path:
    candidates = [
        workdir.parent.parent / "outputs",
        workdir.parent / "outputs",
        workdir / "outputs",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def select_delivery_sources(workdir: Path, outputs_dir: Path) -> dict[str, Any]:
    selected: dict[str, Any] = {}
    selected["final_xlsx"] = first_existing(
        outputs_dir,
        [
            "*最终归档表.xlsx",
            "*completed_final_archive.xlsx",
            "*after_docker_final_archive.xlsx",
            "*final_archive.xlsx",
            "*archive.xlsx",
        ],
    )
    selected["yuque_table"] = first_existing(outputs_dir, ["*语雀粘贴表.md", "*completed_yuque_table.md", "*after_docker_yuque_table.md", "*yuque_table.md"])
    selected["archive_roots"] = find_archive_roots(workdir, outputs_dir)
    return {
        key: value
        for key, value in selected.items()
        if (is_real_path(value) if isinstance(value, Path) else bool(value))
    }


def find_archive_roots(workdir: Path, outputs_dir: Path) -> list[Path]:
    candidates = [
        outputs_dir / "archive",
        outputs_dir / "归档",
        workdir / "archive",
        workdir / "归档",
        workdir.parent / "archive",
        workdir.parent / "归档",
    ]
    roots = []
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate.exists() or not candidate.is_dir():
            continue
        key = candidate.resolve().as_posix()
        if key not in seen and find_challenge_dirs(candidate):
            roots.append(candidate)
            seen.add(key)
    return roots


def find_challenge_dirs(root: Path) -> list[Path]:
    if not root.exists():
        return []
    dirs = []
    for child in sorted(path for path in root.iterdir() if path.is_dir() and not path.name.startswith("_")):
        if any((child / subdir).exists() for subdir in CHALLENGE_SUBDIRS):
            dirs.append(child)
    return dirs


def copy_challenge_archives(
    *,
    archive_roots: list[Path],
    delivery: Path,
    copy_limit: int,
    copy_image_tars: bool,
) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    missing: list[dict[str, str]] = []
    challenges: list[dict[str, Any]] = []
    image_tars: list[dict[str, str]] = []
    seen: set[str] = set()
    for root in archive_roots:
        for case_dir in find_challenge_dirs(root):
            if case_dir.name in seen:
                continue
            seen.add(case_dir.name)
            target_case_dir = delivery / case_dir.name
            subdirs = []
            for subdir in CHALLENGE_SUBDIRS:
                source_subdir = case_dir / subdir
                if not source_subdir.exists() or not source_subdir.is_dir():
                    continue
                subdirs.append(subdir)
                target_subdir = target_case_dir / subdir
                for source in sorted(path for path in source_subdir.rglob("*") if path.is_file()):
                    relative = source.relative_to(source_subdir)
                    is_image_tar = subdir == "题目镜像" and source.suffix.lower() in IMAGE_SUFFIXES
                    target = target_subdir / relative
                    record = copy_or_reference(
                        source,
                        target,
                        key=f"challenge:{subdir}",
                        copy_limit=copy_limit,
                        force_reference=is_image_tar and not copy_image_tars,
                        extra={"challenge": case_dir.name, "subdir": subdir},
                    )
                    add_record(record, files, missing)
                    if is_image_tar:
                        image_tars.append(
                            {
                                "challenge": case_dir.name,
                                "image": source.name,
                                "status": record.get("status", ""),
                                "platform": "",
                                "sha256": "",
                                "tar": source.as_posix(),
                            }
                        )
            challenges.append({"name": case_dir.name, "source": case_dir.as_posix(), "subdirs": subdirs})
    return {"files": files, "missing": missing, "challenges": challenges, "image_tars": image_tars}


def first_existing(root: Path, patterns: list[str]) -> Path:
    for pattern in patterns:
        matches = sorted(path for path in root.glob(pattern) if path.is_file())
        if matches:
            return matches[-1]
    return Path()


def first_available(*paths: Path) -> Path:
    for path in paths:
        if is_real_path(path):
            return path
    return Path()


def is_real_path(path: Path) -> bool:
    return isinstance(path, Path) and path.as_posix() != "."


def first_existing_recursive(root: Path, patterns: list[str]) -> Path:
    if not root.exists():
        return Path()
    for pattern in patterns:
        matches = sorted(path for path in root.rglob(pattern) if path.is_file())
        if matches:
            return matches[-1]
    return Path()


def copy_or_reference(
    source: Path | None,
    target: Path,
    *,
    key: str,
    copy_limit: int,
    force_reference: bool,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    extra = extra or {}
    if source is None or not source.as_posix() or not source.is_file():
        return {"key": key, "status": "missing", "target": target.as_posix(), **extra}
    size = source.stat().st_size
    if force_reference or size > copy_limit:
        return {
            "key": key,
            "status": "referenced",
            "source": source.as_posix(),
            "target": "",
            "size": size,
            "reason": "large_or_reference_only" if size > copy_limit else "reference_only",
            **extra,
        }
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    return {
        "key": key,
        "status": "copied",
        "source": source.as_posix(),
        "target": target.as_posix(),
        "size": size,
        **extra,
    }


def add_record(record: dict[str, Any], files: list[dict[str, Any]], missing: list[dict[str, str]]) -> None:
    if record.get("status") == "missing":
        missing.append({"key": str(record.get("key") or ""), "target": str(record.get("target") or "")})
    else:
        files.append(record)


def collect_image_tar_records(json_path: Path | None, md_path: Path | None) -> list[dict[str, str]]:
    records = records_from_image_manifest_json(json_path) if json_path and json_path.is_file() else []
    if records:
        return records
    return records_from_image_manifest_md(md_path) if md_path and md_path.is_file() else []


def records_from_image_manifest_json(path: Path | None) -> list[dict[str, str]]:
    if not path or not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    candidates = []
    if isinstance(payload, dict):
        for key in ["items", "images", "tars", "records"]:
            value = payload.get(key)
            if isinstance(value, list):
                candidates = value
                break
    output = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        output.append(
            {
                "challenge": str(item.get("challenge") or item.get("case_id") or item.get("name") or ""),
                "image": str(item.get("image") or item.get("image_name") or ""),
                "status": str(item.get("status") or ""),
                "platform": str(item.get("platform") or ""),
                "sha256": str(item.get("sha256") or ""),
                "tar": str(item.get("tar") or item.get("tar_path") or item.get("path") or ""),
            }
        )
    return output


def records_from_image_manifest_md(path: Path | None) -> list[dict[str, str]]:
    if not path or not path.is_file():
        return []
    output = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| ") or "---" in line or "Challenge" in line:
            continue
        cells = [cell.strip().strip("`") for cell in line.strip("|").split("|")]
        if len(cells) < 7:
            continue
        output.append(
            {
                "challenge": cells[0],
                "image": cells[1],
                "status": cells[2],
                "platform": cells[3],
                "sha256": cells[5],
                "tar": cells[6],
            }
        )
    return output


def build_summary(
    workdir: Path,
    outputs_dir: Path,
    delivery: Path,
    files: list[dict[str, Any]],
    missing: list[dict[str, str]],
    selected: dict[str, Any],
) -> dict[str, Any]:
    copied = sum(1 for item in files if item.get("status") == "copied")
    referenced = sum(1 for item in files if item.get("status") == "referenced")
    return {
        "workdir": workdir.as_posix(),
        "outputs_dir": outputs_dir.as_posix(),
        "delivery_dir": delivery.as_posix(),
        "copied_files": copied,
        "referenced_files": referenced,
        "missing_files": len(missing),
        "has_final_xlsx": bool(selected.get("final_xlsx")),
        "has_yuque_table": bool(selected.get("yuque_table")),
        "challenge_count": sum(1 for root in selected.get("archive_roots", []) for _ in find_challenge_dirs(root)),
    }


def scan_delivery_package(delivery: Path) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    allowed_root_files = set(ROOT_FILES)
    blocked_keywords = ("draft", "草稿", "report", "summary", "quality", "质量检查", "最终表格", "过程证据", "机器数据")
    for path in delivery.rglob("*"):
        relative = path.relative_to(delivery).as_posix()
        parts = relative.split("/")
        if path.name == ".DS_Store":
            issues.append({"path": relative, "issue": "禁止 .DS_Store"})
            continue
        if path.is_file() and len(parts) == 1 and path.name not in allowed_root_files:
            issues.append({"path": relative, "issue": "交付根目录只能有最终归档表、语雀粘贴表和交付说明"})
        if path.is_file() and path.suffix.lower() in {".json", ".jsonl"}:
            issues.append({"path": relative, "issue": "禁止机器 JSON 进入交付目录"})
        if len(parts) == 2 and path.is_file():
            issues.append({"path": relative, "issue": "题目目录下只能放 题目源码/题目镜像/题目手册/题目附件 子目录"})
        if len(parts) >= 2 and parts[1] not in CHALLENGE_SUBDIRS:
            issues.append({"path": relative, "issue": "题目目录下只能有 题目源码/题目镜像/题目手册/题目附件"})
        if any(keyword in path.name for keyword in blocked_keywords):
            issues.append({"path": relative, "issue": "禁止过程报告、草稿或机器目录进入交付目录"})
    return issues


def render_delivery_readme(manifest: dict[str, Any]) -> str:
    summary = manifest.get("summary", {})
    lines = [
        "# CloverSec CTF 交付说明",
        "",
        "这个目录是给人接手查看的最终交付包。根目录只保留总表、语雀表和这份说明；每道题都放在自己的 `分类-题目名/` 目录里。",
        "",
        "## 根目录文件",
        "",
        "- `最终归档表.xlsx`：最终归档表，内部要求保留完整 Flag。",
        "- `语雀粘贴表.md`：可以粘贴到语雀的表格。",
        "- `交付说明.md`：当前文件，说明目录结构、缺失项和镜像 tar 引用。",
        "",
        "## 交付状态",
        "",
        f"- 已复制文件：{summary.get('copied_files', 0)}",
        f"- 仅引用文件：{summary.get('referenced_files', 0)}",
        f"- 缺失文件：{summary.get('missing_files', 0)}",
        f"- 题目目录数量：{len(manifest.get('challenges', []))}",
        f"- 交付包问题：{summary.get('package_issues', 0)}",
        f"- 工作目录：`{summary.get('workdir', '')}`",
        f"- 原始 outputs：`{summary.get('outputs_dir', '')}`",
        "",
        "## 题目目录",
        "",
        "| 题目目录 | 子目录 | 来源 |",
        "|---|---|---|",
    ]
    for item in manifest.get("challenges", []):
        lines.append("| " + " | ".join(escape_table(value) for value in [item.get("name", ""), "、".join(item.get("subdirs", [])), item.get("source", "")]) + " |")
    if manifest.get("missing"):
        lines.extend(["", "## 缺失文件", "", "| 类型 | 目标位置 |", "|---|---|"])
        for item in manifest["missing"]:
            lines.append("| " + " | ".join(escape_table(value) for value in [item.get("key", ""), item.get("target", "")]) + " |")
    if manifest.get("package_issues"):
        lines.extend(["", "## 交付包问题", "", "| 文件 | 问题 |", "|---|---|"])
        for item in manifest["package_issues"]:
            lines.append("| " + " | ".join(escape_table(value) for value in [item.get("path", ""), item.get("issue", "")]) + " |")
    referenced_tars = [item for item in manifest.get("image_tars", []) if item.get("status") == "referenced"]
    if referenced_tars:
        lines.extend(["", "## 镜像 tar 引用", "", "| 题目 | 镜像 | 原始路径 |", "|---|---|---|"])
        for item in referenced_tars:
            lines.append("| " + " | ".join(escape_table(value) for value in [item.get("challenge", ""), item.get("image", ""), item.get("tar", "")]) + " |")
    elif manifest.get("image_tars"):
        lines.extend(["", "## 镜像 tar", "", "| 题目 | 镜像 | 状态 | 路径 |", "|---|---|---|---|"])
        for item in manifest["image_tars"]:
            lines.append(
                "| "
                + " | ".join(
                    escape_table(value)
                    for value in [
                        item.get("challenge", ""),
                        item.get("image", ""),
                        item.get("status", ""),
                        item.get("tar", ""),
                    ]
                )
                + " |"
            )
    return "\n".join(lines) + "\n"


def cleanup_ds_store(root: Path) -> None:
    for path in root.rglob(".DS_Store"):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def safe_display_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in value.strip())
    return cleaned.strip(".-_")[:80] or "ctf"


def escape_table(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a human-readable CloverSec CTF delivery folder")
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--outputs-dir", default="")
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--copy-limit", type=int, default=DEFAULT_COPY_LIMIT)
    parser.add_argument("--copy-image-tars", dest="copy_image_tars", action="store_true", default=True)
    parser.add_argument("--no-copy-image-tars", dest="copy_image_tars", action="store_false")
    args = parser.parse_args(argv)
    manifest = create_delivery_package(
        workdir=args.workdir,
        outputs_dir=args.outputs_dir or None,
        output_dir=args.output_dir or None,
        copy_limit=args.copy_limit,
        copy_image_tars=args.copy_image_tars,
    )
    print(f"wrote {manifest['paths']['readme']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
