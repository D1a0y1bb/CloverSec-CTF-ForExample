#!/usr/bin/env python3
"""Chinese handoff tables for CTF collection and resource processing."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import cloversec_ctf_data as data
import cloversec_ctf_collect as collect
import cloversec_ctf_search as search


COLLECTION_FIELDS = collect.COLLECTION_HUMAN_FIELDS

RESOURCE_FIELDS = [
    "记录ID",
    "题目",
    "资源类型",
    "本地路径",
    "来源URL",
    "hash",
    "下载状态",
    "解压状态",
    "风险",
    "缺失项",
    "下一步动作",
    "推荐Skill",
]

DOCKERIZER_FIELDS = [
    "记录ID",
    "题目",
    "源码目录",
    "Dockerfile",
    "compose",
    "端口线索",
    "启动命令",
    "Flag路径",
    "缺失项",
    "自动动作",
    "下一步动作",
]


def write_collection_handoff(cases: list[dict[str, Any]], output_dir: str | Path) -> dict[str, Any]:
    base = Path(output_dir)
    base.mkdir(parents=True, exist_ok=True)
    rows = collection_rows_from_cases(cases)
    xlsx_path = base / "赛事题目信息收集表.xlsx"
    jsonl_path = base / "collection_machine.jsonl"
    schema_path = base / "赛事题目信息收集表.schema.json"
    collect.write_collection_human_xlsx(cases, xlsx_path)
    collect.write_collection_machine_jsonl(cases, jsonl_path)
    write_json(
        schema_path,
        {
            "schema_version": "cloversec.ctf.collection_human_table.v1",
            "title": "赛事题目信息收集表",
            "description": "前期收集阶段的人看表。机器字段在 collection_machine.jsonl。",
            "fields": [{"name": field, "type": "string", "required": field in {"时间年份", "赛事名称", "题目分类", "题目名称"}} for field in COLLECTION_FIELDS],
            "material_status_values": search.COLLECTION_MATERIAL_STATUSES,
            "row_count": len(rows),
        },
    )
    return {
        "table_name": "赛事题目信息收集表",
        "rows": len(rows),
        "xlsx": xlsx_path.as_posix(),
        "jsonl": jsonl_path.as_posix(),
        "schema": schema_path.as_posix(),
    }


def write_resource_handoff(classification: dict[str, Any], output_dir: str | Path) -> dict[str, Any]:
    rows = resource_rows_from_classification(classification)
    resource_payload = write_handoff_group(
        output_dir,
        table_name="资源整理与处理建议表",
        fields=RESOURCE_FIELDS,
        rows=rows,
        description="资源整理阶段的人和 Agent 共用工作表。",
    )
    docker_rows = dockerizer_rows_from_classification(classification)
    docker_payload = write_handoff_group(
        output_dir,
        table_name="Dockerizer交接表",
        fields=DOCKERIZER_FIELDS,
        rows=docker_rows,
        description="需要进入 CloverSec Dockerizer 的容器题交接表。",
    )
    return {"resource": resource_payload, "dockerizer": docker_payload}


def write_search_handoff(manifest: dict[str, Any], output_dir: str | Path) -> dict[str, Any]:
    cases = search.results_to_cases(manifest)
    payload = write_collection_handoff(cases, output_dir)
    cases_path = Path(output_dir) / "ctf_cases.jsonl"
    write_jsonl(cases_path, cases)
    payload["cases_jsonl"] = cases_path.as_posix()
    return payload


def collection_rows_from_cases(cases: list[dict[str, Any]]) -> list[dict[str, str]]:
    return collect.collection_human_rows(cases)


def resource_rows_from_classification(classification: dict[str, Any]) -> list[dict[str, str]]:
    resources = classification.get("resources") if isinstance(classification.get("resources"), list) else []
    root = str(classification.get("root") or "")
    rows: list[dict[str, str]] = []
    for index, item in enumerate(resources, start=1):
        if not isinstance(item, dict):
            continue
        archive_preview = item.get("archive_preview") if isinstance(item.get("archive_preview"), dict) else {}
        issue_count = int(archive_preview.get("issues") or 0)
        rows.append(
            {
                "记录ID": f"resource-{index:04d}",
                "题目": Path(root).name if root else "",
                "资源类型": str(item.get("resource_type") or ""),
                "本地路径": join_path(root, str(item.get("relative_path") or "")),
                "来源URL": str(item.get("source_url") or ""),
                "hash": str(item.get("sha256") or ""),
                "下载状态": "本地已存在",
                "解压状态": archive_status(archive_preview),
                "风险": "有风险" if issue_count else "",
                "缺失项": resource_missing_item(item),
                "下一步动作": resource_next_action(item),
                "推荐Skill": str(item.get("recommended_next_skill") or ""),
            }
        )
    return rows


def dockerizer_rows_from_classification(classification: dict[str, Any]) -> list[dict[str, str]]:
    platform_delivery = classification.get("platform_delivery") if isinstance(classification.get("platform_delivery"), dict) else {}
    root_classification = classification.get("root_classification") if isinstance(classification.get("root_classification"), dict) else {}
    if not platform_delivery.get("must_use_dockerizer") and not root_classification.get("platform_delivery", {}).get("must_use_dockerizer"):
        return []
    resources = classification.get("resources") if isinstance(classification.get("resources"), list) else []
    root = str(classification.get("root") or "")
    dockerfiles = [str(item.get("relative_path") or "") for item in resources if item.get("resource_type") == "dockerfile"]
    compose_files = [str(item.get("relative_path") or "") for item in resources if item.get("resource_type") == "compose_file"]
    flag_files = [str(item.get("relative_path") or "") for item in resources if item.get("resource_type") == "flag_file"]
    source_like = [
        str(item.get("relative_path") or "")
        for item in resources
        if item.get("resource_type") in {"source_file", "source_manifest", "source_archive", "docker_image_tar"}
    ]
    port_hints, command_hints = dockerizer_runtime_hints(root, dockerfiles, compose_files)
    missing = []
    if not dockerfiles and not compose_files and not source_like:
        missing.append("缺少源码、Dockerfile、compose 或镜像 tar")
    if not flag_files:
        missing.append("未发现 Flag 文件路径")
    row = {
        "记录ID": "dockerizer-0001",
        "题目": Path(root).name if root else "",
        "源码目录": root,
        "Dockerfile": ";".join(dockerfiles),
        "compose": ";".join(compose_files),
        "端口线索": port_hints,
        "启动命令": command_hints,
        "Flag路径": ";".join(flag_files),
        "缺失项": ";".join(missing),
        "自动动作": "auto_action=auto-render",
        "下一步动作": f"交给 cloversec-ctf-build-dockerizer 自动生成 CloverSec 平台交付件并做静态校验；在 Dockerizer skill 的 scripts 目录执行 workflow.py auto-render --project-dir {root}",
    }
    return [row]


def dockerizer_runtime_hints(root: str, dockerfiles: list[str], compose_files: list[str]) -> tuple[str, str]:
    if not root:
        return "", ""
    ports: list[str] = []
    commands: list[str] = []
    base = Path(root)
    for relative in dockerfiles:
        text = read_text_if_small(base / relative)
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.upper().startswith("EXPOSE "):
                for token in stripped.split()[1:]:
                    port = token.split("/", 1)[0]
                    if re.fullmatch(r"\d{2,5}", port):
                        append_unique(ports, port)
            if stripped.upper().startswith(("CMD ", "ENTRYPOINT ")):
                append_unique(commands, f"{relative}: {stripped}")
    for relative in compose_files:
        text = read_text_if_small(base / relative)
        for match in re.finditer(r"['\"]?(\d{2,5})\s*:\s*(\d{2,5})(?:/[A-Za-z]+)?['\"]?", text):
            append_unique(ports, f"{match.group(1)}:{match.group(2)}")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("command:"):
                append_unique(commands, f"{relative}: {stripped}")
    return ";".join(ports), ";".join(commands)


def read_text_if_small(path: Path, *, max_bytes: int = 65536) -> str:
    try:
        if not path.is_file() or path.stat().st_size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def append_unique(values: list[str], value: str) -> None:
    if value and value not in values:
        values.append(value)


def write_handoff_group(
    output_dir: str | Path,
    *,
    table_name: str,
    fields: list[str],
    rows: list[dict[str, str]],
    description: str,
) -> dict[str, Any]:
    base = Path(output_dir)
    base.mkdir(parents=True, exist_ok=True)
    jsonl_path = base / f"{table_name}.jsonl"
    xlsx_path = base / f"{table_name}.xlsx"
    schema_path = base / f"{table_name}.schema.json"
    normalized_rows = [{field: str(row.get(field, "")) for field in fields} for row in rows]
    write_jsonl(jsonl_path, normalized_rows)
    data.write_table_xlsx(normalized_rows, xlsx_path, fields=fields, sheet_name=table_name[:31])
    schema = {
        "schema_version": "cloversec.ctf.handoff_table.v1",
        "title": table_name,
        "description": description,
        "fields": [{"name": field, "type": "string", "required": field == "记录ID"} for field in fields],
        "row_count": len(normalized_rows),
    }
    write_json(schema_path, schema)
    return {
        "table_name": table_name,
        "rows": len(normalized_rows),
        "xlsx": xlsx_path.as_posix(),
        "jsonl": jsonl_path.as_posix(),
        "schema": schema_path.as_posix(),
    }


def processing_grade_for_case(case: dict[str, Any]) -> str:
    research = case.get("research") if isinstance(case.get("research"), dict) else {}
    material_level = str(research.get("material_level") or "")
    reproducibility = str(research.get("reproducibility_status") or "")
    if material_level == "official_challenge_metadata":
        return "可处理：官方配置/附件候选"
    if material_level == "attachment_candidate":
        return "可处理：附件候选"
    if reproducibility in {"solver_or_writeup_only", "writeup_only"}:
        return "不可交付：缺源码/附件"
    if reproducibility in {"lead_only", "search_gap"}:
        return "线索：待人工确认"
    if case.get("requires_user_confirmation"):
        return "待确认：需要人工判断"
    return "待材料识别"


def writeup_status_for_case(case: dict[str, Any]) -> str:
    assets = case.get("asset_collection") if isinstance(case.get("asset_collection"), dict) else {}
    candidates = assets.get("writeup_candidates") if isinstance(assets.get("writeup_candidates"), list) else []
    if candidates:
        return "已发现 WP 线索"
    research = case.get("research") if isinstance(case.get("research"), dict) else {}
    if str(research.get("reproducibility_status") or "") in {"writeup_only", "solver_or_writeup_only"}:
        return "只有 WP/solver 线索"
    return "未确认"


def dockerizer_flag_for_case(case: dict[str, Any]) -> str:
    challenge_metadata = case.get("challenge_metadata") if isinstance(case.get("challenge_metadata"), dict) else {}
    question_type = str(challenge_metadata.get("question_type") or case.get("metadata", {}).get("题目类型") or "")
    if any(token in question_type.lower() for token in ["env", "docker", "container"]) or "环境" in question_type:
        return "需要 Dockerizer"
    return ""


def first_candidate_url(value: Any) -> str:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and str(item.get("source_url") or "").strip():
                return str(item.get("source_url"))
            if isinstance(item, dict) and str(item.get("url") or "").strip():
                return str(item.get("url"))
            if isinstance(item, dict) and str(item.get("href") or "").strip():
                return str(item.get("href"))
    return ""


def first_evidence_url(value: Any) -> str:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and str(item.get("source_url") or "").strip():
                return str(item.get("source_url"))
            if isinstance(item, dict) and str(item.get("url") or "").strip():
                return str(item.get("url"))
    return ""


def next_action_for_case(case: dict[str, Any]) -> str:
    grade = processing_grade_for_case(case)
    if grade.startswith("可处理"):
        return "进入资源下载预览和资源识别。"
    if "缺源码/附件" in grade:
        return "继续搜索官方题包、源码、附件或让用户补入口。"
    return "需要人工确认来源和材料。"


def archive_status(preview: dict[str, Any]) -> str:
    if not preview:
        return ""
    if int(preview.get("issues") or 0):
        return "可预览但有风险"
    if int(preview.get("entries") or 0):
        return "可预览"
    return ""


def resource_missing_item(item: dict[str, Any]) -> str:
    if item.get("confidence") == "low":
        return "资源类型低置信度"
    if item.get("resource_type") == "unknown":
        return "无法识别资源类型"
    return ""


def resource_next_action(item: dict[str, Any]) -> str:
    skill = str(item.get("recommended_next_skill") or "")
    if skill == "cloversec-ctf-build-dockerizer":
        return "进入 Dockerizer 交接，不直接把现有 Dockerfile 当平台交付。"
    if skill == "cloversec-ctf-attachment-packager":
        return "检查附件 hash、解压和路径风险。"
    if skill == "cloversec-ctf-writeup-scaffold":
        return "进入中文手册生成或手册质量检查。"
    return "人工确认。"


def join_path(root: str, relative: str) -> str:
    if not root:
        return relative
    if not relative:
        return root
    return (Path(root) / relative).as_posix()


def write_json(path: str | Path, payload: Any) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: str | Path, rows: list[dict[str, Any]]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create Chinese handoff tables for CloverSec CTF workflows")
    subparsers = parser.add_subparsers(dest="command", required=True)

    collection_parser = subparsers.add_parser("collection", help="write collection handoff tables from ctf_cases.jsonl")
    collection_parser.add_argument("--cases", required=True)
    collection_parser.add_argument("--output-dir", required=True)

    search_parser = subparsers.add_parser("search", help="write collection handoff tables from search result manifest")
    search_parser.add_argument("--manifest", required=True)
    search_parser.add_argument("--output-dir", required=True)

    resource_parser = subparsers.add_parser("resource", help="write resource and Dockerizer handoff tables")
    resource_parser.add_argument("--classification", required=True)
    resource_parser.add_argument("--output-dir", required=True)

    args = parser.parse_args(argv)
    if args.command == "collection":
        payload = write_collection_handoff(data.load_cases(args.cases), args.output_dir)
    elif args.command == "search":
        payload = write_search_handoff(load_json(args.manifest), args.output_dir)
    elif args.command == "resource":
        payload = write_resource_handoff(load_json(args.classification), args.output_dir)
    else:
        parser.error("unknown command")
        return 2
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
