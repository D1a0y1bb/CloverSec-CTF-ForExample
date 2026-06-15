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
VERSION = "0.5.3"
DEFAULT_COPY_LIMIT = 300 * 1024 * 1024

DELIVERY_DIRS = {
    "tables": "最终表格",
    "yuque": "语雀归档表",
    "archive": "题目归档包",
    "images": "镜像包清单",
    "quality": "质量检查报告",
    "hub": "Hub提交材料",
    "evidence": "过程证据",
    "machine": "过程证据/机器数据",
    "issues": "待处理问题",
    "manual": "手册",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def create_delivery_package(
    *,
    workdir: str | Path,
    outputs_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
    copy_limit: int = DEFAULT_COPY_LIMIT,
    copy_image_tars: bool = False,
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

    required_keys = {
        "final_xlsx",
        "yuque_table",
        "final_report_md",
        "archive_package",
        "formal_manual",
        "missing_report",
    }
    copy_spec = [
        ("final_xlsx", DELIVERY_DIRS["tables"], "最终归档表.xlsx"),
        ("reviewed_xlsx", DELIVERY_DIRS["tables"], "阶段归档表-质检后.xlsx"),
        ("after_docker_xlsx", DELIVERY_DIRS["tables"], "阶段归档表-Docker验证后.xlsx"),
        ("yuque_table", DELIVERY_DIRS["yuque"], "语雀粘贴表.md"),
        ("final_report_md", DELIVERY_DIRS["quality"], "最终报告.md"),
        ("final_report_json", DELIVERY_DIRS["machine"], "最终报告.json"),
        ("quality_summary_md", DELIVERY_DIRS["quality"], "质量检查汇总.md"),
        ("quality_summary_json", DELIVERY_DIRS["machine"], "质量检查汇总.json"),
        ("docker_summary_md", DELIVERY_DIRS["quality"], "Docker执行汇总.md"),
        ("docker_summary_json", DELIVERY_DIRS["machine"], "Docker执行汇总.json"),
        ("completion_report_md", DELIVERY_DIRS["quality"], "完成报告.md"),
        ("completion_report_json", DELIVERY_DIRS["machine"], "完成报告.json"),
        ("solver_summary_md", DELIVERY_DIRS["quality"], "solver验证汇总.md"),
        ("solver_summary_json", DELIVERY_DIRS["machine"], "solver验证汇总.json"),
        ("archive_package", DELIVERY_DIRS["archive"], "题目归档包.zip"),
        ("manuals_zip", DELIVERY_DIRS["archive"], "手册与字段包.zip"),
        ("formal_manual", DELIVERY_DIRS["manual"], "题目解题手册.md"),
        ("missing_report", DELIVERY_DIRS["issues"], "缺失项报告.md"),
        ("image_manifest_md", DELIVERY_DIRS["images"], "镜像包清单.md"),
        ("image_manifest_json", DELIVERY_DIRS["machine"], "镜像包清单.json"),
        ("cases_jsonl", DELIVERY_DIRS["machine"], "最终题目数据.jsonl"),
        ("research_report", DELIVERY_DIRS["evidence"], "题目收集报告.md"),
    ]
    for key, folder, target_name in copy_spec:
        if key not in selected and key not in required_keys:
            continue
        record = copy_or_reference(
            selected.get(key),
            delivery / folder / target_name,
            key=key,
            copy_limit=copy_limit,
            force_reference=False,
        )
        add_record(record, files, missing)

    image_tar_records = collect_image_tar_records(selected.get("image_manifest_json"), selected.get("image_manifest_md"))
    for record in image_tar_records:
        source = Path(str(record.get("tar") or ""))
        target = delivery / DELIVERY_DIRS["images"] / source.name
        copied = copy_image_tars and source.is_file()
        add_record(
            copy_or_reference(
                source if source.as_posix() else None,
                target,
                key="image_tar",
                copy_limit=copy_limit,
                force_reference=not copied,
                extra={"challenge": str(record.get("challenge") or ""), "image": str(record.get("image") or "")},
            ),
            files,
            missing,
        )

    package_issues = scan_delivery_package(delivery)
    summary = build_summary(work, outputs, delivery, files, missing, selected)
    summary["package_issues"] = len(package_issues)
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
        "package_issues": package_issues,
        "selected_sources": {key: path.as_posix() for key, path in selected.items() if isinstance(path, Path)},
        "image_tars": image_tar_records,
    }
    manifest_path = delivery / "交付清单.json"
    readme_path = delivery / "交付说明.md"
    manifest["paths"]["manifest"] = manifest_path.as_posix()
    manifest["paths"]["readme"] = readme_path.as_posix()
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
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


def select_delivery_sources(workdir: Path, outputs_dir: Path) -> dict[str, Path]:
    selected: dict[str, Path] = {}
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
    selected["reviewed_xlsx"] = first_existing(outputs_dir, ["*reviewed_archive.xlsx"])
    selected["after_docker_xlsx"] = first_existing(outputs_dir, ["*after_docker.xlsx"])
    selected["yuque_table"] = first_existing(outputs_dir, ["*语雀粘贴表.md", "*completed_yuque_table.md", "*after_docker_yuque_table.md", "*yuque_table.md"])
    selected["final_report_md"] = first_existing(outputs_dir, ["*最终报告.md", "*completed_final_report.md", "*after_docker_final_report.md", "*final_report.md"])
    selected["final_report_json"] = first_existing(outputs_dir, ["*最终报告.json", "*completed_final_report.json", "*after_docker_final_report.json", "*final_report.json"])
    selected["quality_summary_md"] = first_existing(outputs_dir, ["*quality_summary.md"])
    selected["quality_summary_json"] = first_existing(outputs_dir, ["*quality_summary.json"])
    selected["docker_summary_md"] = first_existing(outputs_dir, ["*docker_execution_summary.md"])
    selected["docker_summary_json"] = first_existing(outputs_dir, ["*docker_execution_summary.json"])
    selected["completion_report_md"] = first_existing(outputs_dir, ["*completion_report.md"])
    selected["completion_report_json"] = first_existing(outputs_dir, ["*completion_report.json"])
    selected["solver_summary_md"] = first_existing(outputs_dir, ["*solver_verification_summary.md"])
    selected["solver_summary_json"] = first_existing(outputs_dir, ["*solver_verification_summary.json"])
    selected["archive_package"] = first_existing(outputs_dir, ["*completed_archive_package_no_tars.zip", "*after_docker_archive_package.zip", "*archive_package.zip"])
    selected["manuals_zip"] = first_existing(outputs_dir, ["*manuals.zip"])
    selected["formal_manual"] = first_available(
        first_existing(outputs_dir, ["*题目解题手册.md", "题目解题手册.md"]),
        first_existing(workdir / "writeup", ["*题目解题手册.md", "题目解题手册.md"]),
        first_existing(workdir / "hub" / "manual", ["*题目解题手册.md", "题目解题手册.md"]),
        first_existing_recursive(workdir / "archive", ["题目解题手册.md"]),
    )
    selected["missing_report"] = first_existing(outputs_dir, ["*completed_missing_report.md", "*after_docker_missing_report.md", "*missing_report.md"])
    selected["cases_jsonl"] = first_existing(outputs_dir, ["*completed_archived_cases.jsonl", "*after_docker_archived_cases.jsonl", "*archived_cases.jsonl", "*cases.jsonl"])
    selected["research_report"] = first_existing(outputs_dir, ["*research_report.md"])
    selected["image_manifest_md"] = first_existing(workdir, ["image_tars_manifest.md"])
    selected["image_manifest_json"] = first_existing(workdir, ["image_tars_manifest.json"])
    return {key: value for key, value in selected.items() if is_real_path(value)}


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
    selected: dict[str, Path],
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
        "has_archive_package": bool(selected.get("archive_package")),
        "has_image_manifest": bool(selected.get("image_manifest_md") or selected.get("image_manifest_json")),
    }


def scan_delivery_package(delivery: Path) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    human_dirs = {value for key, value in DELIVERY_DIRS.items() if key != "machine"}
    blocked_names = {
        ".DS_Store",
        "archive.xlsx",
        "yuque_table.md",
        "final_report.md",
        "final_report.json",
        "quality_summary.json",
        "docker_execution_summary.json",
        "completion_report.json",
        "solver_verification_summary.json",
    }
    for path in delivery.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(delivery).as_posix()
        if path.name in blocked_names:
            issues.append({"path": relative, "issue": "人看的交付目录里出现无效或英文重复文件"})
        top = relative.split("/", 1)[0]
        if top in human_dirs and path.suffix.lower() == ".json" and not relative.startswith(DELIVERY_DIRS["machine"] + "/"):
            issues.append({"path": relative, "issue": "JSON 应放到 过程证据/机器数据"})
    return issues


def render_delivery_readme(manifest: dict[str, Any]) -> str:
    summary = manifest.get("summary", {})
    lines = [
        "# CloverSec CTF 交付说明",
        "",
        "这个目录是给人接手查看的交付包。内部 `work/` 目录保留完整过程数据、缓存、工具和大文件，不建议直接作为最终交付目录使用。",
        "",
        "## 先看这些",
        "",
        "- `最终表格/最终归档表.xlsx`：最终归档表，内部要求保留完整 Flag。",
        "- `语雀归档表/语雀粘贴表.md`：粘贴到语雀的表格。",
        "- `题目归档包/题目归档包.zip`：题目归档包。",
        "- `镜像包清单/镜像包清单.md`：镜像 tar 的位置、大小、平台和 hash。",
        "- `质量检查报告/最终报告.md`：本批次状态和待处理事项。",
        "- `待处理问题/缺失项报告.md`：缺失文件、未验证或待人工处理内容。",
        "",
        "## 交付状态",
        "",
        f"- 已复制文件：{summary.get('copied_files', 0)}",
        f"- 仅引用文件：{summary.get('referenced_files', 0)}",
        f"- 缺失文件：{summary.get('missing_files', 0)}",
        f"- 交付包问题：{summary.get('package_issues', 0)}",
        f"- 工作目录：`{summary.get('workdir', '')}`",
        f"- 原始 outputs：`{summary.get('outputs_dir', '')}`",
        "",
        "## 文件清单",
        "",
        "| 状态 | 类型 | 文件 | 来源 |",
        "|---|---|---|---|",
    ]
    for item in manifest.get("files", []):
        lines.append(
            "| "
            + " | ".join(
                escape_table(value)
                for value in [
                    item.get("status", ""),
                    item.get("key", ""),
                    item.get("target") or item.get("source", ""),
                    item.get("source", ""),
                ]
            )
            + " |"
        )
    if manifest.get("missing"):
        lines.extend(["", "## 缺失文件", "", "| 类型 | 目标位置 |", "|---|---|"])
        for item in manifest["missing"]:
            lines.append("| " + " | ".join(escape_table(value) for value in [item.get("key", ""), item.get("target", "")]) + " |")
    if manifest.get("package_issues"):
        lines.extend(["", "## 交付包问题", "", "| 文件 | 问题 |", "|---|---|"])
        for item in manifest["package_issues"]:
            lines.append("| " + " | ".join(escape_table(value) for value in [item.get("path", ""), item.get("issue", "")]) + " |")
    if manifest.get("image_tars"):
        lines.extend(["", "## 镜像 tar 位置", "", "| 题目 | 镜像 | 状态 | 平台 | tar |", "|---|---|---|---|---|"])
        for item in manifest["image_tars"]:
            lines.append(
                "| "
                + " | ".join(
                    escape_table(value)
                    for value in [
                        item.get("challenge", ""),
                        item.get("image", ""),
                        item.get("status", ""),
                        item.get("platform", ""),
                        item.get("tar", ""),
                    ]
                )
                + " |"
            )
    return "\n".join(lines) + "\n"


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
    parser.add_argument("--copy-image-tars", action="store_true")
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
