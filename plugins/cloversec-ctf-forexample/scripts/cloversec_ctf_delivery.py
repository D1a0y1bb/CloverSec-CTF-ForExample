#!/usr/bin/env python3
"""Create a human-readable CloverSec CTF delivery folder."""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import cloversec_ctf_naming as naming


SCHEMA_VERSION = "cloversec.ctf.delivery.v1"
VERSION = "1.0.1"
DEFAULT_COPY_LIMIT = 300 * 1024 * 1024

ROOT_FILES = ["最终归档表.xlsx", "语雀粘贴表.md", "交付说明.md"]
CHALLENGE_SUBDIRS = ["题目源码", "题目镜像", "题目手册", "题目附件"]
IMAGE_SUFFIXES = {".tar", ".gz", ".tgz"}
BLOCKED_PATH_PARTS = {".ctfbuild", ".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
BLOCKED_PROCESS_FILENAMES = {
    "docker_artifacts.json",
    "docker_artifacts.validated.json",
    "docker_artifacts.executed.json",
    "validate-summary.json",
    "image.inspect.json",
    "session.json",
    "proposal.json",
    "proposal.yaml",
}


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
    prepare_clean_delivery_dir(delivery)

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
    legacy_records = copy_legacy_single_challenges(
        legacy_challenges=selected.get("legacy_challenges", []),
        delivery=delivery,
        copy_limit=copy_limit,
        copy_image_tars=copy_image_tars,
    )
    files.extend(legacy_records["files"])
    missing.extend(legacy_records["missing"])

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
        "challenges": challenge_records["challenges"] + legacy_records["challenges"],
        "image_tars": challenge_records["image_tars"] + legacy_records["image_tars"],
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
    selected["legacy_challenges"] = [] if selected["archive_roots"] else find_legacy_single_challenges(workdir)
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


def prepare_clean_delivery_dir(delivery: Path) -> None:
    if delivery.exists():
        if not delivery.is_dir():
            raise NotADirectoryError(delivery)
        shutil.rmtree(delivery)
    delivery.mkdir(parents=True, exist_ok=True)


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
                    if not challenge_file_allowed(source, source_subdir, subdir):
                        continue
                    relative = source.relative_to(source_subdir)
                    is_image_tar = subdir == "题目镜像" and source.suffix.lower() in IMAGE_SUFFIXES
                    effective_copy_limit = source.stat().st_size if is_image_tar and copy_image_tars else copy_limit
                    target = target_subdir / relative
                    record = copy_or_reference(
                        source,
                        target,
                        key=f"challenge:{subdir}",
                        copy_limit=effective_copy_limit,
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


def find_legacy_single_challenges(workdir: Path) -> list[dict[str, Any]]:
    if not workdir.exists() or not workdir.is_dir():
        return []
    source_dir = first_existing_dir(workdir, ["dockerizer_work", "题目源码"])
    image_dir = first_existing_dir(workdir, ["题目镜像"])
    manual_dir = first_existing_dir(workdir, ["手册", "题目手册"])
    attachment_dir = first_existing_dir(workdir, ["题目附件", "附件"])
    if not any(is_existing_dir(path) for path in [source_dir, image_dir, manual_dir, attachment_dir]):
        return []
    case = load_case_metadata(workdir)
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    challenge_name = naming.challenge_dir_name(metadata)
    if not challenge_name or challenge_name == "Misc-未命名题目":
        challenge_name = safe_display_name(workdir.name)
    is_attachment = not is_existing_dir(source_dir) and not is_existing_dir(image_dir) and is_existing_dir(attachment_dir)
    return [
        {
            "name": challenge_name,
            "source": workdir.as_posix(),
            "type": "attachment" if is_attachment else "container",
            "source_dir": source_dir.as_posix() if is_existing_dir(source_dir) else "",
            "image_dir": image_dir.as_posix() if is_existing_dir(image_dir) else "",
            "manual_dir": manual_dir.as_posix() if is_existing_dir(manual_dir) else "",
            "attachment_dir": attachment_dir.as_posix() if is_existing_dir(attachment_dir) else "",
        }
    ]


def first_existing_dir(root: Path, names: list[str]) -> Path:
    for name in names:
        path = root / name
        if path.is_dir():
            return path
    return Path()


def load_case_metadata(workdir: Path) -> dict[str, Any]:
    case_json = workdir / "ctf_case.json"
    if case_json.is_file():
        try:
            payload = json.loads(case_json.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except json.JSONDecodeError:
            return {}
    cases_jsonl = workdir / "ctf_cases.jsonl"
    if cases_jsonl.is_file():
        for line in cases_jsonl.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            return payload if isinstance(payload, dict) else {}
    return {}


def copy_legacy_single_challenges(
    *,
    legacy_challenges: list[dict[str, Any]],
    delivery: Path,
    copy_limit: int,
    copy_image_tars: bool,
) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    missing: list[dict[str, str]] = []
    challenges: list[dict[str, Any]] = []
    image_tars: list[dict[str, str]] = []
    for item in legacy_challenges:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "未命名题目")
        target_case_dir = delivery / name
        subdirs: list[str] = []
        if item.get("type") == "attachment":
            subdirs.extend(copy_legacy_dir(Path(str(item.get("attachment_dir") or "")), target_case_dir / "题目附件", "题目附件", files, missing, copy_limit, challenge=name))
        else:
            subdirs.extend(copy_legacy_dir(Path(str(item.get("source_dir") or "")), target_case_dir / "题目源码", "题目源码", files, missing, copy_limit, challenge=name, source_filter=legacy_source_allowed))
            image_result = copy_legacy_dir(
                Path(str(item.get("image_dir") or "")),
                target_case_dir / "题目镜像",
                "题目镜像",
                files,
                missing,
                copy_limit,
                challenge=name,
                copy_image_tars=copy_image_tars,
            )
            subdirs.extend(image_result)
            for record in files:
                if record.get("challenge") == name and record.get("subdir") == "题目镜像" and str(record.get("target") or record.get("source") or "").lower().endswith((".tar", ".tar.gz", ".tgz")):
                    image_tars.append(
                        {
                            "challenge": name,
                            "image": Path(str(record.get("target") or record.get("source") or "")).name,
                            "status": str(record.get("status") or ""),
                            "platform": "",
                            "sha256": "",
                            "tar": str(record.get("source") or record.get("target") or ""),
                        }
                    )
        manual_copied = copy_legacy_manual(Path(str(item.get("manual_dir") or "")), target_case_dir / "题目手册", files, missing, challenge=name)
        if manual_copied:
            subdirs.append("题目手册")
        challenges.append({"name": name, "source": str(item.get("source") or ""), "subdirs": dedupe_strings(subdirs)})
    return {"files": files, "missing": missing, "challenges": challenges, "image_tars": image_tars}


def copy_legacy_dir(
    source_dir: Path,
    target_dir: Path,
    subdir: str,
    files: list[dict[str, Any]],
    missing: list[dict[str, str]],
    copy_limit: int,
    *,
    challenge: str,
    source_filter: Any | None = None,
    copy_image_tars: bool = True,
) -> list[str]:
    if source_dir.as_posix() in {"", "."}:
        missing.append({"key": f"legacy:{subdir}", "target": target_dir.as_posix()})
        return []
    if not source_dir.is_dir():
        missing.append({"key": f"legacy:{subdir}", "target": target_dir.as_posix()})
        return []
    copied = False
    for source in sorted(path for path in source_dir.rglob("*") if path.is_file()):
        if source_filter and not source_filter(source, source_dir):
            continue
        relative = source.relative_to(source_dir)
        target = target_dir / relative
        is_image_tar = subdir == "题目镜像" and source.suffix.lower() in IMAGE_SUFFIXES
        effective_copy_limit = source.stat().st_size if is_image_tar and copy_image_tars else copy_limit
        record = copy_or_reference(
            source,
            target,
            key=f"legacy:{subdir}",
            copy_limit=effective_copy_limit,
            force_reference=is_image_tar and not copy_image_tars,
            extra={"challenge": challenge, "subdir": subdir},
        )
        add_record(record, files, missing)
        copied = copied or record.get("status") == "copied"
    return [subdir] if copied else []


def legacy_source_allowed(path: Path, root: Path) -> bool:
    return challenge_file_allowed(path, root, "题目源码")


def challenge_file_allowed(path: Path, root: Path, subdir: str) -> bool:
    rel_parts = path.relative_to(root).parts
    if any(part in BLOCKED_PATH_PARTS or part == "verification" for part in rel_parts):
        return False
    if path.name in BLOCKED_PROCESS_FILENAMES:
        return False
    if path.suffix in {".pyc", ".pyo"} or path.name == ".DS_Store":
        return False
    if subdir == "题目手册" and manual_name_blocked(path.name):
        return False
    if subdir in {"题目手册", "题目镜像"} and path.suffix.lower() in {".json", ".jsonl"}:
        return False
    return True


def copy_legacy_manual(source_dir: Path, target_dir: Path, files: list[dict[str, Any]], missing: list[dict[str, str]], *, challenge: str) -> bool:
    if source_dir.as_posix() in {"", "."}:
        missing.append({"key": "legacy:题目手册", "target": target_dir.as_posix()})
        return False
    if not source_dir.is_dir():
        missing.append({"key": "legacy:题目手册", "target": target_dir.as_posix()})
        return False
    candidates = [source_dir / "题目解题手册.md"]
    candidates.extend(path for path in sorted(source_dir.glob("*.md")) if not manual_name_blocked(path.name))
    source = next((path for path in candidates if path.is_file()), Path())
    if not source.as_posix():
        missing.append({"key": "legacy:题目手册", "target": (target_dir / "题目解题手册.md").as_posix()})
        return False
    record = copy_or_reference(
        source,
        target_dir / "题目解题手册.md",
        key="legacy:题目手册",
        copy_limit=DEFAULT_COPY_LIMIT,
        force_reference=False,
        extra={"challenge": challenge, "subdir": "题目手册"},
    )
    add_record(record, files, missing)
    return record.get("status") == "copied"


def manual_name_blocked(name: str) -> bool:
    lower = name.lower()
    return any(token in lower for token in ["draft", "template", "proposal", "manual_filled_draft", "manual_template"])


def dedupe_strings(values: list[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        if value and value not in output:
            output.append(value)
    return output


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


def is_existing_dir(path: Path) -> bool:
    return is_real_path(path) and path.is_dir()


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
    archive_challenges = sum(1 for root in selected.get("archive_roots", []) for _ in find_challenge_dirs(root))
    legacy_challenges = len(selected.get("legacy_challenges", []))
    return {
        "workdir": workdir.as_posix(),
        "outputs_dir": outputs_dir.as_posix(),
        "delivery_dir": delivery.as_posix(),
        "copied_files": copied,
        "referenced_files": referenced,
        "missing_files": len(missing),
        "has_final_xlsx": bool(selected.get("final_xlsx")),
        "has_yuque_table": bool(selected.get("yuque_table")),
        "challenge_count": archive_challenges + legacy_challenges,
    }


def scan_delivery_package(delivery: Path) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    allowed_root_files = set(ROOT_FILES)
    allowed_subdirs = set(CHALLENGE_SUBDIRS)
    blocked_root_names = {"_cache", "过程证据", "机器数据", "reports", "logs", "evidence", "snapshots", "Hub准备", "质量检查"}
    blocked_manual_tokens = ("draft", "草稿", "template", "manual_filled_draft", "manual_template")

    for child in sorted(delivery.iterdir()) if delivery.exists() else []:
        if child.name == ".DS_Store":
            issues.append({"path": child.name, "issue": "禁止 .DS_Store"})
            continue
        if child.is_file():
            if child.name not in allowed_root_files:
                issues.append({"path": child.name, "issue": "交付根目录只能有最终归档表、语雀粘贴表和交付说明"})
            if child.suffix.lower() in {".json", ".jsonl"}:
                issues.append({"path": child.name, "issue": "交付根目录禁止机器 JSON"})
            continue
        if not child.is_dir():
            continue
        if child.name in blocked_root_names:
            issues.append({"path": child.name, "issue": "交付根目录不能出现过程目录"})
            continue
        present_subdirs = {item.name for item in child.iterdir() if item.is_dir() and item.name in allowed_subdirs}
        unknown_subdirs = [item.name for item in child.iterdir() if item.is_dir() and item.name not in allowed_subdirs and item.name != ".DS_Store"]
        direct_files = [item.name for item in child.iterdir() if item.is_file() and item.name != ".DS_Store"]
        if direct_files:
            issues.append({"path": child.name, "issue": "题目目录下只能放 题目源码/题目镜像/题目手册/题目附件 子目录"})
        for name in unknown_subdirs:
            issues.append({"path": f"{child.name}/{name}", "issue": "题目目录下只能有 题目源码/题目镜像/题目手册/题目附件"})
        if "题目附件" in present_subdirs:
            for forbidden in ["题目源码", "题目镜像"]:
                if forbidden in present_subdirs:
                    issues.append({"path": f"{child.name}/{forbidden}", "issue": "附件题交付目录不应包含源码或镜像目录"})
            if "题目手册" not in present_subdirs:
                issues.append({"path": child.name, "issue": "附件题缺少题目手册目录"})
        elif present_subdirs:
            for required in ["题目源码", "题目镜像", "题目手册"]:
                if required not in present_subdirs:
                    issues.append({"path": child.name, "issue": f"容器题缺少{required}目录"})
        else:
            issues.append({"path": child.name, "issue": "题目目录缺少有效中文子目录"})

    for path in delivery.rglob("*"):
        relative = path.relative_to(delivery).as_posix()
        parts = relative.split("/")
        if path.name == ".DS_Store":
            issues.append({"path": relative, "issue": "禁止 .DS_Store"})
            continue
        if any(part in BLOCKED_PATH_PARTS for part in parts):
            issues.append({"path": relative, "issue": "禁止过程目录进入交付包"})
            continue
        if path.is_file() and path.name in BLOCKED_PROCESS_FILENAMES:
            issues.append({"path": relative, "issue": "禁止过程文件进入交付包"})
            continue
        if len(parts) >= 2 and parts[1] not in CHALLENGE_SUBDIRS:
            continue
        if path.is_file() and len(parts) >= 3 and parts[1] in {"题目手册", "题目镜像"} and path.suffix.lower() in {".json", ".jsonl"}:
            issues.append({"path": relative, "issue": "手册和镜像目录禁止机器 JSON"})
        if path.is_file() and len(parts) >= 3 and parts[1] == "题目手册" and any(keyword in path.name for keyword in blocked_manual_tokens):
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
