#!/usr/bin/env python3
"""Audit artifacts for CloverSec CTF production-style workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import cloversec_ctf_archive as archive
import cloversec_ctf_data as data


VERSION = "0.7.1"
CONFIRMATION_SCHEMA = "cloversec.ctf.confirmation_request.v1"
LOCK_SCHEMA = "cloversec.ctf.manifest_lock.v1"
PREVIEW_SCHEMA = "cloversec.ctf.archive_preview.v1"
BATCH_REPORT_SCHEMA = "cloversec.ctf.batch_status_report.v1"
FAILURE_SCHEMA = "cloversec.ctf.failure_case.v1"
NOTIFICATION_SCHEMA = "cloversec.ctf.stage_notification.v1"
WARNING_SCHEMA = "cloversec.ctf.codex_warning_report.v1"

CONFIRMATION_ACTIONS = {"download", "extract", "dockerizer", "docker", "hub", "retag", "archive", "final"}
ARCHIVE_ROLES = {
    "source": "源码",
    "attachment": "附件",
    "image_tar": "镜像",
    "writeup": "手册",
    "screenshot": "截图",
}
BATCH_REPORT_FIELDS = [
    "赛事来源",
    "年份",
    "分类",
    "题目 ID",
    "名称",
    "材料状态",
    "构建状态",
    "手册状态",
    "验证状态",
    "是否归档",
    "待人工确认",
    "缺失资源",
    "可归档",
    "已归档",
    "归档目录",
    "问题",
]
EXTERNAL_WARNING_MARKERS = [
    "openai-curated",
    "openai-bundled",
    "external plugin",
    "Auth required",
    "icon/defaultPrompt",
    "defaultPrompt warning",
]
CLOVERSEC_MARKERS = [
    "cloversec-ctf",
    "CloverSec CTF",
    "CloverSec-CTF",
    "cloversec_ctf",
]


def create_confirmation_request(
    *,
    action: str,
    output_dir: str | Path,
    case: dict[str, Any] | None = None,
    case_json: str | Path = "",
    inputs: list[str] | None = None,
    planned_outputs: list[str] | None = None,
    risks: list[str] | None = None,
    checks: list[str] | None = None,
    risk_level: str = "medium",
) -> dict[str, Any]:
    if case is None and str(case_json).strip():
        case = load_json(case_json)
    case = case or {}
    if action not in CONFIRMATION_ACTIONS:
        raise ValueError(f"unsupported confirmation action: {action}")
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": CONFIRMATION_SCHEMA,
        "version": VERSION,
        "request_id": f"{action}-{safe_id(case_id(case) or utc_compact())}",
        "case_id": case_id(case),
        "case_title": case_title(case),
        "action": action,
        "risk_level": risk_level,
        "requires_user_confirmation": True,
        "status": "pending",
        "created_at": utc_now(),
        "inputs": inputs or infer_action_inputs(action, case),
        "planned_outputs": planned_outputs or infer_action_outputs(action, case),
        "risks": risks or default_risks(action),
        "checks": checks or default_checks(action),
        "allowed_actions": allowed_actions(action),
        "forbidden_actions": forbidden_actions(action),
        "user_confirmation": {
            "accepted": False,
            "accepted_by": "",
            "accepted_at": "",
            "note": "",
        },
    }
    write_json(output / "confirmation_request.json", payload)
    write_text(output / "confirmation_request.md", render_confirmation_request(payload))
    return payload


def create_manifest_lock(
    case: dict[str, Any],
    output_dir: str | Path,
    *,
    archive_manifest: dict[str, Any] | None = None,
    archive_manifest_path: str | Path = "",
    extra_files: list[str] | None = None,
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    if archive_manifest is None and str(archive_manifest_path).strip():
        archive_manifest = load_json(archive_manifest_path)
    files = collect_case_file_records(case)
    for item in (archive_manifest or {}).get("files", []):
        if isinstance(item, dict):
            files.append(normalize_existing_record(item))
    for item in extra_files or []:
        path = Path(item)
        files.append(file_record(path, "extra", base=path.parent if path.parent != Path("") else Path(".")))
    deduped = dedupe_file_records(files)
    flag = case.get("flag") if isinstance(case.get("flag"), dict) else {}
    flag_value = str(flag.get("value") or data.case_to_xlsx_row(case).get("Flag") or "")
    xlsx_fields = data.case_to_xlsx_row(case)
    payload = {
        "schema_version": LOCK_SCHEMA,
        "version": VERSION,
        "case_id": case_id(case),
        "case_title": case_title(case),
        "created_at": utc_now(),
        "archive_manifest_path": str(archive_manifest_path or ""),
        "files": deduped,
        "summary": {
            "file_count": len(deduped),
            "missing_file_count": sum(1 for item in deduped if item.get("status") == "missing"),
            "total_size": sum(int(item.get("size") or 0) for item in deduped),
            "flag_present": bool(flag_value),
            "hub_id": xlsx_fields.get("HUB编号", ""),
            "archive_dir": xlsx_fields.get("归档目录", ""),
        },
        "flag": {
            "value": flag_value,
            "sha256": sha256_text(flag_value) if flag_value else "",
            "type": str(flag.get("type") or xlsx_fields.get("Flag类型") or ""),
            "sensitive": True,
        },
        "xlsx_fields": xlsx_fields,
        "issues": [f"missing file: {item.get('path', '')}" for item in deduped if item.get("status") == "missing"],
    }
    write_json(output / "manifest.lock.json", payload)
    write_text(output / "manifest.lock.md", render_manifest_lock(payload))
    return payload


def create_archive_preview(
    case: dict[str, Any],
    output_dir: str | Path,
    *,
    archive_root: str | Path = "",
    max_file_size: int = 500 * 1024 * 1024,
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    root = Path(archive_root) if str(archive_root).strip() else output / "archive"
    archive_dir = root / archive.archive_folder_name(case)
    files = expected_archive_records(case, archive_dir)
    duplicates = duplicate_target_names(files)
    oversized = [
        {"path": item["source_path"], "size": item.get("size", 0), "limit": max_file_size}
        for item in files
        if item.get("exists") and int(item.get("size") or 0) > max_file_size
    ]
    invalid_names = [
        {"source_path": item["source_path"], "target_path": item["target_path"]}
        for item in files
        if item.get("invalid_name")
    ]
    missing = [item for item in files if not item.get("exists")]
    would_create = [{"path": (archive_dir / subdir).as_posix(), "type": "dir"} for subdir in archive.ARCHIVE_SUBDIRS]
    would_create.extend({"path": item["target_path"], "type": "file", "role": item["role"]} for item in files)
    payload = {
        "schema_version": PREVIEW_SCHEMA,
        "version": VERSION,
        "case_id": case_id(case),
        "case_title": case_title(case),
        "created_at": utc_now(),
        "archive_root": root.as_posix(),
        "archive_dir": archive_dir.as_posix(),
        "would_create": would_create,
        "expected_files": files,
        "missing_items": missing,
        "duplicate_targets": duplicates,
        "oversized_files": oversized,
        "invalid_names": invalid_names,
        "summary": {
            "expected_files": len(files),
            "missing_items": len(missing),
            "duplicate_targets": len(duplicates),
            "oversized_files": len(oversized),
            "invalid_names": len(invalid_names),
            "ready_to_write": not (missing or duplicates or oversized or invalid_names),
        },
    }
    write_json(output / "archive_preview.json", payload)
    write_text(output / "archive_preview.md", render_archive_preview(payload))
    return payload


def create_batch_status_report(
    cases: list[dict[str, Any]],
    output_dir: str | Path,
    *,
    workflow_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    rows = [batch_row(case, workflow_state=workflow_state) for case in cases]
    summary = summarize_batch_rows(rows)
    payload = {
        "schema_version": BATCH_REPORT_SCHEMA,
        "version": VERSION,
        "created_at": utc_now(),
        "summary": summary,
        "rows": rows,
        "paths": {
            "json": (output / "batch_status_report.json").as_posix(),
            "markdown": (output / "batch_status_report.md").as_posix(),
            "xlsx": (output / "batch_status_report.xlsx").as_posix(),
        },
    }
    write_json(output / "batch_status_report.json", payload)
    write_text(output / "batch_status_report.md", render_batch_status_report(payload))
    data.write_table_xlsx(rows, output / "batch_status_report.xlsx", fields=BATCH_REPORT_FIELDS, sheet_name="批量状态")
    return payload


def create_failure_library(
    cases: list[dict[str, Any]],
    output_path: str | Path,
    *,
    extra_failures: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    failures = []
    for case in cases:
        failures.extend(extract_failures_from_case(case))
    for item in extra_failures or []:
        if isinstance(item, dict):
            failures.append(normalize_failure_case(item))
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in failures), encoding="utf-8")
    summary = {
        "total": len(failures),
        "by_stage": dict(Counter(item.get("stage", "unknown") for item in failures)),
        "retryable": sum(1 for item in failures if item.get("retryable") is True),
        "path": output.as_posix(),
    }
    return {"schema_version": "cloversec.ctf.failure_library.v1", "version": VERSION, "summary": summary, "failures": failures}


def create_stage_notification(
    *,
    stage: str,
    output_dir: str | Path,
    completed: list[str] | None = None,
    failed: list[str] | None = None,
    pending_user: list[str] | None = None,
    next_inputs: list[str] | None = None,
    artifacts: list[str] | None = None,
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": NOTIFICATION_SCHEMA,
        "version": VERSION,
        "stage": stage,
        "created_at": utc_now(),
        "completed": completed or [],
        "failed": failed or [],
        "pending_user": pending_user or [],
        "next_inputs": next_inputs or [],
        "artifacts": artifacts or [],
        "summary": {
            "completed": len(completed or []),
            "failed": len(failed or []),
            "pending_user": len(pending_user or []),
            "artifacts": len(artifacts or []),
        },
    }
    write_json(output / "stage_notification.json", payload)
    write_text(output / "stage_notification.md", render_stage_notification(payload))
    return payload


def classify_codex_warnings(log_text: str) -> dict[str, Any]:
    warnings = []
    for line in log_text.splitlines():
        lowered = line.lower()
        if "warning" not in lowered and "warn" not in lowered and "auth required" not in lowered:
            continue
        source = "external_plugin"
        severity = "warning"
        if any(marker.lower() in lowered for marker in CLOVERSEC_MARKERS):
            source = "cloversec"
            severity = "blocker" if any(term in lowered for term in ["error", "failed", "missing"]) else "warning"
        elif any(marker.lower() in lowered for marker in EXTERNAL_WARNING_MARKERS):
            source = "external_plugin"
        warnings.append({"source": source, "severity": severity, "line": line})
    return {
        "schema_version": WARNING_SCHEMA,
        "version": VERSION,
        "created_at": utc_now(),
        "summary": {
            "total": len(warnings),
            "cloversec_blockers": sum(1 for item in warnings if item["source"] == "cloversec" and item["severity"] == "blocker"),
            "cloversec_warnings": sum(1 for item in warnings if item["source"] == "cloversec" and item["severity"] == "warning"),
            "external_warnings": sum(1 for item in warnings if item["source"] == "external_plugin"),
        },
        "warnings": warnings,
    }


def batch_row(case: dict[str, Any], *, workflow_state: dict[str, Any] | None = None) -> dict[str, str]:
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    evidence = case.get("evidence") if isinstance(case.get("evidence"), list) else []
    missing = missing_resources(case)
    pending = pending_confirmations(case, workflow_state=workflow_state)
    problems = case_problem_messages(case)
    ready = not missing and not pending and not problems and str(metadata.get("验证状态") or "") == "通过"
    archived = str(metadata.get("是否归档") or "") == "是"
    return {
        "赛事来源": str(metadata.get("赛事来源") or metadata.get("题目来源") or ""),
        "年份": extract_year(str(metadata.get("赛事来源") or metadata.get("题目来源") or "")),
        "分类": str(metadata.get("分类") or ""),
        "题目 ID": case_id(case),
        "名称": case_title(case),
        "材料状态": str(metadata.get("材料状态") or ""),
        "构建状态": str(metadata.get("构建状态") or ""),
        "手册状态": str(metadata.get("手册状态") or ""),
        "验证状态": str(metadata.get("验证状态") or ""),
        "是否归档": str(metadata.get("是否归档") or ""),
        "待人工确认": ";".join(pending),
        "缺失资源": ";".join(missing),
        "可归档": "是" if ready else "否",
        "已归档": "是" if archived else "否",
        "归档目录": str(metadata.get("归档目录") or ""),
        "问题": ";".join(problems),
    }


def summarize_batch_rows(rows: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "total": len(rows),
        "by_event": dict(Counter(row["赛事来源"] or "未填写" for row in rows)),
        "by_year": dict(Counter(row["年份"] or "未填写" for row in rows)),
        "by_category": dict(Counter(row["分类"] or "未填写" for row in rows)),
        "by_validation_status": dict(Counter(row["验证状态"] or "未填写" for row in rows)),
        "missing_resources": sum(1 for row in rows if row["缺失资源"]),
        "pending_user": sum(1 for row in rows if row["待人工确认"]),
        "can_archive": sum(1 for row in rows if row["可归档"] == "是"),
        "archived": sum(1 for row in rows if row["已归档"] == "是"),
    }


def collect_case_file_records(case: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    for item in iter_case_paths(case):
        path = Path(item["path"])
        records.append(file_record(path, item["role"], base=path.parent))
    return records


def expected_archive_records(case: dict[str, Any], archive_dir: Path) -> list[dict[str, Any]]:
    records = []
    for item in iter_case_paths(case):
        source = Path(item["path"])
        role = item["role"]
        subdir = ARCHIVE_ROLES.get(role, "manifests")
        target_name = safe_name(str(item.get("name") or source.name))
        target = archive_dir / subdir / target_name
        invalid_name = bool(re.search(r"[\\/]|^\.+$", target_name)) or not target_name
        records.append(
            {
                "role": role,
                "source_path": source.as_posix(),
                "target_path": target.as_posix(),
                "exists": source.is_file(),
                "size": source.stat().st_size if source.is_file() else 0,
                "sha256": sha256_file(source) if source.is_file() else "",
                "invalid_name": invalid_name,
            }
        )
    return records


def iter_case_paths(case: dict[str, Any]) -> list[dict[str, str]]:
    items = []
    for source in list_value(case.get("source_files")):
        path = source.get("path") or source.get("local_path")
        if path:
            items.append({"role": "source", "path": str(path), "name": str(source.get("name") or Path(str(path)).name)})
    for source in list_value(case.get("attachments")):
        path = source.get("path") or source.get("local_path")
        if path:
            items.append({"role": "attachment", "path": str(path), "name": str(source.get("name") or Path(str(path)).name)})
    docker_artifacts = case.get("docker_artifacts") if isinstance(case.get("docker_artifacts"), dict) else {}
    if docker_artifacts.get("tar_path"):
        path = str(docker_artifacts["tar_path"])
        items.append({"role": "image_tar", "path": path, "name": Path(path).name})
    writeup = case.get("writeup") if isinstance(case.get("writeup"), dict) else {}
    for key in ["manual_path", "manual_filled_draft", "manual_template"]:
        if writeup.get(key):
            path = str(writeup[key])
            items.append({"role": "writeup", "path": path, "name": Path(path).name})
    archive_info = case.get("archive") if isinstance(case.get("archive"), dict) else {}
    screenshots = archive_info.get("screenshots") if isinstance(archive_info.get("screenshots"), list) else []
    for item in screenshots:
        if isinstance(item, dict):
            path = str(item.get("path") or item.get("local_path") or "")
            name = str(item.get("name") or Path(path).name)
        else:
            path = str(item)
            name = Path(path).name
        if path:
            items.append({"role": "screenshot", "path": path, "name": name})
    return items


def missing_resources(case: dict[str, Any]) -> list[str]:
    missing = []
    for item in iter_case_paths(case):
        if not Path(item["path"]).is_file():
            missing.append(f"{item['role']}:{item['path']}")
    if not _manual_paths(case):
        missing.append("手册文件")
    if not _screenshot_paths(case):
        missing.append("截图文件")
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    if not str(data.case_to_xlsx_row(case).get("Flag") or "").strip():
        missing.append("Flag")
    if not str(metadata.get("名称") or "").strip():
        missing.append("名称")
    if not str(metadata.get("分类") or "").strip():
        missing.append("分类")
    return missing


def case_problem_messages(case: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    if str(metadata.get("问题") or "").strip():
        problems.append(str(metadata["问题"]))
    validation_status = str(metadata.get("验证状态") or "").strip()
    if validation_status and validation_status != "通过":
        problems.append(f"验证状态为{validation_status}")
    if str(metadata.get("是否通过") or "").strip() == "否":
        problems.append("是否通过为否")

    archive_info = case.get("archive") if isinstance(case.get("archive"), dict) else {}
    for item in archive_info.get("issues", []) if isinstance(archive_info.get("issues"), list) else []:
        problems.append(str(item))

    review_info = case.get("review") if isinstance(case.get("review"), dict) else {}
    checks = review_info.get("checks") if isinstance(review_info.get("checks"), list) else []
    for item in checks:
        if not isinstance(item, dict):
            continue
        if item.get("status") != "pass":
            problems.append(f"{item.get('name', item.get('id', '检查项'))}: {item.get('message', '')}")

    evidence = case.get("evidence") if isinstance(case.get("evidence"), list) else []
    for item in evidence:
        if not isinstance(item, dict):
            continue
        if item.get("status") in {"missing", "inaccessible", "failed", "broken"}:
            message = str(item.get("summary") or item.get("message") or item.get("error") or "").strip()
            if message:
                problems.append(message)
    gate = dockerizer_conversion_gate(case)
    if gate["required"] and not gate["satisfied"]:
        problems.append(gate["message"])
    return dedupe_strings(problems)


def pending_confirmations(case: dict[str, Any], *, workflow_state: dict[str, Any] | None = None) -> list[str]:
    pending = []
    gate = dockerizer_conversion_gate(case)
    if gate["required"] and not gate["satisfied"]:
        pending.append("Dockerizer 改造待确认")
    if str(case.get("confidence") or "").lower() == "low":
        pending.append("低置信度题目信息")
    for evidence in case.get("evidence", []) if isinstance(case.get("evidence"), list) else []:
        if isinstance(evidence, dict) and evidence.get("requires_user_confirmation"):
            pending.append(str(evidence.get("title") or evidence.get("source_url") or "来源证据"))
    if workflow_state:
        for row in workflow_state.get("cases", []) if isinstance(workflow_state.get("cases"), list) else []:
            if isinstance(row, dict) and str(row.get("case_id") or "") == case_id(case):
                for stage, status in (row.get("stages") or {}).items():
                    if status == "pending_user":
                        pending.append(str(stage))
    if case_problem_messages(case):
        pending.append("问题待人工复核")
    return pending


def extract_failures_from_case(case: dict[str, Any]) -> list[dict[str, Any]]:
    failures = []
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    if str(metadata.get("问题") or "").strip():
        failures.append(
            normalize_failure_case(
                {
                    "case_id": case_id(case),
                    "stage": "metadata",
                    "category": "case_issue",
                    "message": metadata["问题"],
                    "retryable": False,
                    "suggested_action": "人工复核题目信息和归档字段",
                }
            )
        )
    for item in case.get("evidence", []) if isinstance(case.get("evidence"), list) else []:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "")
        if status not in {"missing", "inaccessible", "failed", "broken"}:
            continue
        failures.append(
            normalize_failure_case(
                {
                    "case_id": case_id(case),
                    "stage": str(item.get("stage") or item.get("source_type") or "evidence"),
                    "category": status,
                    "message": str(item.get("summary") or item.get("message") or item.get("error") or ""),
                    "source_url": str(item.get("source_url") or ""),
                    "evidence_path": str(item.get("local_path") or ""),
                    "retryable": status in {"inaccessible", "failed"},
                    "suggested_action": suggestion_for_failure(status),
                }
            )
        )
    for missing in missing_resources(case):
        failures.append(
            normalize_failure_case(
                {
                    "case_id": case_id(case),
                    "stage": "resource",
                    "category": "missing_resource",
                    "message": missing,
                    "retryable": True,
                    "suggested_action": "补齐资源后重新执行预览和质量检查",
                }
            )
        )
    gate = dockerizer_conversion_gate(case)
    for problem in case_problem_messages(case):
        if gate["required"] and not gate["satisfied"] and problem == gate["message"]:
            continue
        failures.append(
            normalize_failure_case(
                {
                    "case_id": case_id(case),
                    "stage": "review",
                    "category": "case_problem",
                    "message": problem,
                    "retryable": False,
                    "suggested_action": "复核问题后重新执行质量检查和最终报告",
                }
            )
        )
    if gate["required"] and not gate["satisfied"]:
        failures.append(
            normalize_failure_case(
                {
                    "case_id": case_id(case),
                    "stage": "dockerizer",
                    "category": "platform_conversion_required",
                    "message": gate["message"],
                    "retryable": True,
                    "suggested_action": "先用 cloversec-ctf-build-dockerizer 生成平台改造方案，把风险和确认项交给用户确认；确认后再生成 Docker 交付件并重新验证。",
                }
            )
        )
    return failures


def dockerizer_conversion_gate(case: dict[str, Any]) -> dict[str, Any]:
    reasons = dockerizer_required_reasons(case)
    satisfied, evidence = dockerizer_conversion_satisfied(case)
    required = bool(reasons)
    return {
        "required": required,
        "satisfied": satisfied if required else True,
        "status": "passed" if (not required or satisfied) else "needs_user_confirmation",
        "action": "dockerizer",
        "skill": "cloversec-ctf-build-dockerizer",
        "reasons": reasons,
        "evidence": evidence,
        "message": "容器题或源码题必须先经 cloversec-ctf-build-dockerizer 改造成 CloverSec 平台契约，并由用户确认方案" if required and not satisfied else "",
    }


def dockerizer_required_reasons(case: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    source_items = list_value(case.get("source_files"))
    docker_artifacts = case.get("docker_artifacts") if isinstance(case.get("docker_artifacts"), dict) else {}
    environment = case.get("environment") if isinstance(case.get("environment"), dict) else {}

    for key in ["platform_delivery", "resource_classification", "container_inference"]:
        value = case.get(key) if isinstance(case.get(key), dict) else {}
        if value.get("must_use_dockerizer") is True:
            reasons.append(f"{key}.must_use_dockerizer=true")
        delivery = value.get("platform_delivery") if isinstance(value.get("platform_delivery"), dict) else {}
        if delivery.get("must_use_dockerizer") is True:
            reasons.append(f"{key}.platform_delivery.must_use_dockerizer=true")

    for item in source_items:
        name = str(item.get("name") or item.get("path") or item.get("local_path") or "").lower()
        if name.endswith("dockerfile") or "docker-compose" in name or name.endswith("compose.yml") or name.endswith("compose.yaml"):
            reasons.append("source_files contains Dockerfile/compose")

    if any(str(docker_artifacts.get(key) or "").strip() for key in ["project_dir", "build_context", "dockerfile", "compose_file"]):
        reasons.append("docker_artifacts contains build context or Dockerfile")

    challenge_type = str(metadata.get("题目类型") or "")
    has_port = bool(str(metadata.get("开放端口") or "").strip() or environment.get("port_mappings"))
    if ("环境" in challenge_type or "容器" in challenge_type or str(metadata.get("离线/在线解题") or "") == "在线") and (source_items or has_port):
        reasons.append("metadata indicates online/container challenge with source or port")

    return dedupe_strings(reasons)


def dockerizer_conversion_satisfied(case: dict[str, Any]) -> tuple[bool, list[str]]:
    evidence: list[str] = []
    dockerizer = case.get("dockerizer") if isinstance(case.get("dockerizer"), dict) else {}
    status = str(dockerizer.get("status") or "").lower()
    if status in {"accepted", "rendered", "validated", "passed", "complete", "completed"}:
        evidence.append(f"dockerizer.status={status}")
        return True, evidence
    if dockerizer.get("user_confirmed") is True or dockerizer.get("conversion_confirmed") is True:
        evidence.append("dockerizer confirmation flag")
        return True, evidence

    platform_delivery = case.get("platform_delivery") if isinstance(case.get("platform_delivery"), dict) else {}
    if platform_delivery.get("dockerizer_conversion_accepted") is True:
        evidence.append("platform_delivery.dockerizer_conversion_accepted=true")
        return True, evidence

    docker_artifacts = case.get("docker_artifacts") if isinstance(case.get("docker_artifacts"), dict) else {}
    if docker_artifacts.get("platform_contract_verified") is True:
        evidence.append("docker_artifacts.platform_contract_verified=true")
        return True, evidence
    if str(docker_artifacts.get("contract") or "").lower() in {"cloversec", "cloversec_verified", "platform_verified"}:
        evidence.append(f"docker_artifacts.contract={docker_artifacts.get('contract')}")
        return True, evidence
    return False, evidence


def normalize_failure_case(item: dict[str, Any]) -> dict[str, Any]:
    case = {
        "schema_version": FAILURE_SCHEMA,
        "version": VERSION,
        "failure_id": str(item.get("failure_id") or f"failure-{sha256_text(json.dumps(item, ensure_ascii=False))[:12]}"),
        "captured_at": str(item.get("captured_at") or utc_now()),
        "case_id": str(item.get("case_id") or ""),
        "stage": str(item.get("stage") or "unknown"),
        "category": str(item.get("category") or "unknown"),
        "message": str(item.get("message") or ""),
        "source_url": str(item.get("source_url") or ""),
        "evidence_path": str(item.get("evidence_path") or ""),
        "retryable": bool(item.get("retryable", False)),
        "suggested_action": str(item.get("suggested_action") or suggestion_for_failure(str(item.get("category") or ""))),
    }
    return case


def duplicate_target_names(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in files:
        grouped[item["target_path"]].append(item)
    return [
        {"target_path": target, "sources": [item["source_path"] for item in items]}
        for target, items in grouped.items()
        if len(items) > 1
    ]


def dedupe_file_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for item in records:
        key = (item.get("role", ""), item.get("path", ""), item.get("sha256", ""))
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def normalize_existing_record(item: dict[str, Any]) -> dict[str, Any]:
    path = Path(str(item.get("path") or item.get("relative_path") or ""))
    return {
        "role": str(item.get("role") or ""),
        "path": path.as_posix(),
        "relative_path": str(item.get("relative_path") or path.name),
        "status": "present" if path.is_file() or item.get("sha256") else "missing",
        "size": int(item.get("size") or (path.stat().st_size if path.is_file() else 0)),
        "sha256": str(item.get("sha256") or (sha256_file(path) if path.is_file() else "")),
    }


def file_record(path: Path, role: str, *, base: Path) -> dict[str, Any]:
    exists = path.is_file()
    try:
        relative = path.relative_to(base).as_posix()
    except ValueError:
        relative = path.name
    return {
        "role": role,
        "path": path.as_posix(),
        "relative_path": relative,
        "status": "present" if exists else "missing",
        "size": path.stat().st_size if exists else 0,
        "sha256": sha256_file(path) if exists else "",
    }


def render_confirmation_request(payload: dict[str, Any]) -> str:
    lines = [
        "# 人工确认请求",
        "",
        f"- 动作：{payload.get('action', '')}",
        f"- 题目：{payload.get('case_title', '') or payload.get('case_id', '')}",
        f"- 风险级别：{payload.get('risk_level', '')}",
        f"- 状态：{payload.get('status', '')}",
        "",
        "## 输入",
        "",
    ]
    lines.extend(f"- {item}" for item in payload.get("inputs", []))
    lines.extend(["", "## 计划输出", ""])
    lines.extend(f"- {item}" for item in payload.get("planned_outputs", []))
    lines.extend(["", "## 风险", ""])
    lines.extend(f"- {item}" for item in payload.get("risks", []))
    lines.extend(["", "## 确认项", ""])
    lines.extend(f"- {item}" for item in payload.get("checks", []))
    lines.extend(["", "## 禁止动作", ""])
    lines.extend(f"- {item}" for item in payload.get("forbidden_actions", []))
    return "\n".join(lines) + "\n"


def render_manifest_lock(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines = [
        "# 归档一致性锁定",
        "",
        f"- 题目：{payload.get('case_title', '') or payload.get('case_id', '')}",
        f"- 文件数：{summary.get('file_count', 0)}",
        f"- 缺失文件：{summary.get('missing_file_count', 0)}",
        f"- HUB 编号：{summary.get('hub_id', '')}",
        f"- Flag SHA256：{payload.get('flag', {}).get('sha256', '')}",
        "",
        "| 角色 | 路径 | 状态 | SHA256 |",
        "|---|---|---|---|",
    ]
    for item in payload.get("files", []):
        lines.append(f"| {escape_table(item.get('role', ''))} | {escape_table(item.get('path', ''))} | {item.get('status', '')} | `{item.get('sha256', '')}` |")
    if payload.get("issues"):
        lines.extend(["", "## 问题", ""])
        lines.extend(f"- {issue}" for issue in payload["issues"])
    return "\n".join(lines) + "\n"


def render_archive_preview(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines = [
        "# 归档目录预览",
        "",
        f"- 归档目录：{payload.get('archive_dir', '')}",
        f"- 预期文件：{summary.get('expected_files', 0)}",
        f"- 缺失项：{summary.get('missing_items', 0)}",
        f"- 重复目标：{summary.get('duplicate_targets', 0)}",
        f"- 过大文件：{summary.get('oversized_files', 0)}",
        f"- 命名异常：{summary.get('invalid_names', 0)}",
        f"- 可以写入：{'是' if summary.get('ready_to_write') else '否'}",
        "",
        "## 将生成",
        "",
    ]
    for item in payload.get("would_create", [])[:200]:
        lines.append(f"- {item.get('type', '')}: {item.get('path', '')}")
    if payload.get("missing_items"):
        lines.extend(["", "## 缺失项", ""])
        for item in payload["missing_items"]:
            lines.append(f"- {item.get('role', '')}: {item.get('source_path', '')}")
    if payload.get("duplicate_targets"):
        lines.extend(["", "## 重复目标", ""])
        for item in payload["duplicate_targets"]:
            lines.append(f"- {item.get('target_path', '')}: {', '.join(item.get('sources', []))}")
    return "\n".join(lines) + "\n"


def render_batch_status_report(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines = [
        "# 批量状态报告",
        "",
        f"- 题目数量：{summary.get('total', 0)}",
        f"- 缺失资源题目：{summary.get('missing_resources', 0)}",
        f"- 待人工确认：{summary.get('pending_user', 0)}",
        f"- 可归档：{summary.get('can_archive', 0)}",
        f"- 已归档：{summary.get('archived', 0)}",
        "",
        "| 赛事 | 年份 | 分类 | 题目 ID | 名称 | 验证状态 | 缺失资源 | 待人工确认 | 问题 | 可归档 | 已归档 |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in payload.get("rows", []):
        lines.append(
            "| "
            + " | ".join(
                escape_table(row.get(field, ""))
                for field in ["赛事来源", "年份", "分类", "题目 ID", "名称", "验证状态", "缺失资源", "待人工确认", "问题", "可归档", "已归档"]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def _manual_paths(case: dict[str, Any]) -> list[str]:
    writeup = case.get("writeup") if isinstance(case.get("writeup"), dict) else {}
    paths = []
    for key in ["manual_path", "manual_filled_draft", "manual_template"]:
        value = str(writeup.get(key) or "").strip()
        if value:
            paths.append(value)
    return paths


def _screenshot_paths(case: dict[str, Any]) -> list[str]:
    archive_info = case.get("archive") if isinstance(case.get("archive"), dict) else {}
    output = []
    for item in archive_info.get("screenshots", []) if isinstance(archive_info.get("screenshots"), list) else []:
        if isinstance(item, dict):
            path = str(item.get("path") or item.get("local_path") or "").strip()
        else:
            path = str(item).strip()
        if path:
            output.append(path)
    return output


def dedupe_strings(values: list[str]) -> list[str]:
    output = []
    seen = set()
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


def render_stage_notification(payload: dict[str, Any]) -> str:
    lines = [
        "# 阶段通知",
        "",
        f"- 阶段：{payload.get('stage', '')}",
        f"- 时间：{payload.get('created_at', '')}",
        "",
        "## 已完成",
        "",
    ]
    append_list_or_none(lines, payload.get("completed", []))
    lines.extend(["", "## 失败", ""])
    append_list_or_none(lines, payload.get("failed", []))
    lines.extend(["", "## 待人工处理", ""])
    append_list_or_none(lines, payload.get("pending_user", []))
    lines.extend(["", "## 下一阶段输入", ""])
    append_list_or_none(lines, payload.get("next_inputs", []))
    lines.extend(["", "## 产物", ""])
    append_list_or_none(lines, payload.get("artifacts", []))
    return "\n".join(lines) + "\n"


def render_codex_warning_report(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines = [
        "# Codex Warning 分类报告",
        "",
        f"- 总数：{summary.get('total', 0)}",
        f"- CloverSec 阻断项：{summary.get('cloversec_blockers', 0)}",
        f"- CloverSec 警告：{summary.get('cloversec_warnings', 0)}",
        f"- 外部插件 warning：{summary.get('external_warnings', 0)}",
        "",
        "| 来源 | 等级 | 内容 |",
        "|---|---|---|",
    ]
    for item in payload.get("warnings", []):
        lines.append(
            "| "
            + " | ".join(escape_table(item.get(field, "")) for field in ["source", "severity", "line"])
            + " |"
        )
    if not payload.get("warnings"):
        lines.append("| none | none | 未发现 warning |")
    return "\n".join(lines) + "\n"


def append_list_or_none(lines: list[str], values: Any) -> None:
    items = [str(item) for item in values] if isinstance(values, list) else []
    if not items:
        lines.append("- 无")
        return
    lines.extend(f"- {item}" for item in items)


def infer_action_inputs(action: str, case: dict[str, Any]) -> list[str]:
    if action in {"archive", "final"}:
        return [case_id(case), *[item["path"] for item in iter_case_paths(case)]]
    if action == "hub":
        return [case_id(case), "hub_fields.json", "manual markdown", "upload manifest"]
    if action == "dockerizer":
        return [case_id(case), "source directory", "resource_classification.json", "container_inference.json", "upstream Dockerfile/compose if present"]
    if action == "docker":
        docker_artifacts = case.get("docker_artifacts") if isinstance(case.get("docker_artifacts"), dict) else {}
        return [str(docker_artifacts.get("image_name") or ""), str(docker_artifacts.get("tar_path") or "")]
    return [case_id(case)]


def infer_action_outputs(action: str, case: dict[str, Any]) -> list[str]:
    mapping = {
        "download": ["downloads_sandbox/", "download_preview.json", "download_safety_report.md"],
        "extract": ["extraction preview", "resource_classification.json"],
        "dockerizer": ["CONFIG PROPOSAL", "Dockerfile", "start.sh", "changeflag.sh", "flag", "environment.json", "docker_artifacts.json", "xlsx_fields.json"],
        "docker": ["docker_evidence.json", "docker_logs.txt"],
        "hub": ["hub_draft.json", "hub_upload_manifest.json", "hub_diff_report.md"],
        "retag": ["retag_plan.json", "image tar"],
        "archive": ["archive_manifest.json", "manifest.lock.json"],
        "final": ["最终归档表.xlsx", "语雀粘贴表.md", "最终报告.md"],
    }
    return mapping.get(action, [case_id(case)])


def default_risks(action: str) -> list[str]:
    return {
        "download": ["外部 URL 可能失效、过大、重定向到登录页或不是题目附件"],
        "extract": ["压缩包可能包含路径穿越、过多文件或非题目资源"],
        "dockerizer": ["上游 Dockerfile/compose 只能作为迁移输入；未确认 CONFIG PROPOSAL 前不得生成最终平台交付件", "需要 privileged、eBPF/tc、KVM、jail 或多服务时必须把平台差异列给用户确认"],
        "docker": ["镜像或容器可能执行未知服务；只在明确授权后执行"],
        "hub": ["未登录时填写会丢失表单内容；最终提交必须人工判断"],
        "retag": ["HUB 编号错误会导致镜像 tag 和归档字段错误"],
        "archive": ["归档写入会复制文件并固定路径/hash/Flag/xlsx 字段"],
        "final": ["最终 xlsx 会写入完整 Flag，适合内部归档，不适合作为公开材料"],
    }[action]


def default_checks(action: str) -> list[str]:
    return {
        "download": ["URL 属于预期来源", "文件大小和协议符合限制", "失败原因已记录"],
        "extract": ["预览无路径穿越", "文件数量和体积可接受", "资源类型已识别"],
        "dockerizer": ["已列出源码、上游 Dockerfile/compose、端口、启动命令和高风险依赖", "已明确生成 CloverSec 平台契约文件，不直接沿用上游 Dockerfile", "用户已确认 CONFIG PROPOSAL 后再写入 Dockerfile/start.sh/changeflag.sh/flag"],
        "docker": ["只执行受信样例或用户授权题目", "目标平台为 linux/amd64", "日志和端口探测会保存"],
        "hub": ["用户已在浏览器登录 Hub", "分类 ID 已确认", "停止在最终提交前"],
        "retag": ["HUB 编号来自审核结果", "源镜像存在", "输出 tar 路径正确"],
        "archive": ["手册、附件、镜像 tar、截图都存在", "manifest.lock.json 会记录完整 Flag"],
        "final": ["所有题目已完成质量检查", "xlsx 保留完整 Flag", "未处理问题已列出"],
    }[action]


def allowed_actions(action: str) -> list[str]:
    base = ["read_local_files", "write_json_reports", "write_markdown_reports"]
    if action == "dockerizer":
        base.extend(["write_platform_delivery_after_user_confirmation", "run_static_validate"])
    if action in {"archive", "final", "hub"}:
        base.append("copy_declared_files")
    if action == "docker":
        base.append("run_docker_only_after_user_approval")
    return base


def forbidden_actions(action: str) -> list[str]:
    items = ["hide_failed_checks", "invent_missing_ids", "discard_full_flag_from_xlsx"]
    if action == "hub":
        items.extend(["read_browser_secrets", "click_final_submit", "fill_form_before_login"])
    if action == "dockerizer":
        items.extend(["treat_upstream_dockerfile_as_final_delivery", "write_delivery_files_before_config_proposal_acceptance"])
    if action == "docker":
        items.append("run_unknown_image_without_user_approval")
    return items


def suggestion_for_failure(status: str) -> str:
    if status == "inaccessible":
        return "使用 Agent 联网搜索或浏览器可见内容导入后重试"
    if status == "failed":
        return "查看失败证据，确认是否换来源或人工提供材料"
    if status == "missing":
        return "补充缺失文件或把字段标记为待人工确认"
    if status == "broken":
        return "替换损坏附件或记录不可复现原因"
    return "人工复核后选择重试或记录为不可用"


def case_id(case: dict[str, Any]) -> str:
    return str(case.get("case_id") or "").strip()


def case_title(case: dict[str, Any]) -> str:
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    return str(metadata.get("名称") or metadata.get("题目标题") or case.get("title") or "").strip()


def list_value(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def extract_year(text: str) -> str:
    match = re.search(r"(?<!\d)(20\d{2})(?!\d)", text)
    return match.group(1) if match else ""


def safe_id(value: str) -> str:
    return safe_name(value).lower()


def safe_name(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.\-\u4e00-\u9fff]+", "-", value.strip())
    text = re.sub(r"-+", "-", text).strip(".-")
    return text[:96] or "item"


def escape_table(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def utc_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, payload: Any) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_text(path: str | Path, text: str) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF audit artifact utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    confirmation = subparsers.add_parser("confirmation", help="write confirmation_request.json/md")
    confirmation.add_argument("--action", required=True, choices=sorted(CONFIRMATION_ACTIONS))
    confirmation.add_argument("--case-json")
    confirmation.add_argument("--output-dir", required=True)
    confirmation.add_argument("--input", action="append", default=[])
    confirmation.add_argument("--planned-output", action="append", default=[])
    confirmation.add_argument("--risk", action="append", default=[])
    confirmation.add_argument("--check", action="append", default=[])
    confirmation.add_argument("--risk-level", default="medium")

    lock = subparsers.add_parser("lock", help="write manifest.lock.json/md")
    lock.add_argument("--case-json", required=True)
    lock.add_argument("--output-dir", required=True)
    lock.add_argument("--archive-manifest")
    lock.add_argument("--extra-file", action="append", default=[])

    preview = subparsers.add_parser("archive-preview", help="write archive_preview.json/md")
    preview.add_argument("--case-json", required=True)
    preview.add_argument("--output-dir", required=True)
    preview.add_argument("--archive-root", default="")
    preview.add_argument("--max-file-size", type=int, default=500 * 1024 * 1024)

    batch = subparsers.add_parser("batch-report", help="write batch_status_report.json/md/xlsx")
    batch.add_argument("--cases", required=True)
    batch.add_argument("--output-dir", required=True)
    batch.add_argument("--workflow-state")

    failures = subparsers.add_parser("failure-library", help="write failure_cases.jsonl")
    failures.add_argument("--cases", required=True)
    failures.add_argument("--output", required=True)
    failures.add_argument("--extra-failures")

    notify = subparsers.add_parser("notify", help="write stage_notification.json/md")
    notify.add_argument("--stage", required=True)
    notify.add_argument("--output-dir", required=True)
    notify.add_argument("--completed", action="append", default=[])
    notify.add_argument("--failed", action="append", default=[])
    notify.add_argument("--pending-user", action="append", default=[])
    notify.add_argument("--next-input", action="append", default=[])
    notify.add_argument("--artifact", action="append", default=[])

    warnings = subparsers.add_parser("warning-report", help="classify codex exec warnings")
    warnings.add_argument("--log", required=True)
    warnings.add_argument("--output", required=True)

    args = parser.parse_args(argv)
    if args.command == "confirmation":
        create_confirmation_request(
            action=args.action,
            case_json=args.case_json or "",
            output_dir=args.output_dir,
            inputs=args.input or None,
            planned_outputs=args.planned_output or None,
            risks=args.risk or None,
            checks=args.check or None,
            risk_level=args.risk_level,
        )
        print(f"wrote {Path(args.output_dir) / 'confirmation_request.json'}")
        return 0
    if args.command == "lock":
        case = load_json(args.case_json)
        manifest = load_json(args.archive_manifest) if args.archive_manifest else None
        create_manifest_lock(case, args.output_dir, archive_manifest=manifest, archive_manifest_path=args.archive_manifest or "", extra_files=args.extra_file)
        print(f"wrote {Path(args.output_dir) / 'manifest.lock.json'}")
        return 0
    if args.command == "archive-preview":
        create_archive_preview(load_json(args.case_json), args.output_dir, archive_root=args.archive_root, max_file_size=args.max_file_size)
        print(f"wrote {Path(args.output_dir) / 'archive_preview.json'}")
        return 0
    if args.command == "batch-report":
        state = load_json(args.workflow_state) if args.workflow_state else None
        create_batch_status_report(data.load_cases(args.cases), args.output_dir, workflow_state=state)
        print(f"wrote {Path(args.output_dir) / 'batch_status_report.json'}")
        return 0
    if args.command == "failure-library":
        extra = load_json(args.extra_failures) if args.extra_failures else []
        if isinstance(extra, dict):
            extra = extra.get("failures", [extra])
        create_failure_library(data.load_cases(args.cases), args.output, extra_failures=extra)
        print(f"wrote {args.output}")
        return 0
    if args.command == "notify":
        create_stage_notification(
            stage=args.stage,
            output_dir=args.output_dir,
            completed=args.completed,
            failed=args.failed,
            pending_user=args.pending_user,
            next_inputs=args.next_input,
            artifacts=args.artifact,
        )
        print(f"wrote {Path(args.output_dir) / 'stage_notification.json'}")
        return 0
    if args.command == "warning-report":
        payload = classify_codex_warnings(Path(args.log).read_text(encoding="utf-8"))
        write_json(args.output, payload)
        output_path = Path(args.output)
        write_text(output_path.with_suffix(".md"), render_codex_warning_report(payload))
        print(f"wrote {args.output}")
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
