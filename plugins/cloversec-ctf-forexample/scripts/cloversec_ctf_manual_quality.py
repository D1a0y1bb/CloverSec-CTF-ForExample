#!/usr/bin/env python3
"""Manual and Hub field quality checks for CloverSec CTF cases."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import cloversec_ctf_data as data


VERSION = "1.0.1"
SCHEMA_VERSION = "cloversec.ctf.manual_quality.v1"
REQUIRED_METADATA_FIELDS = ["名称", "分类", "题目类型", "Flag类型"]
REQUIRED_HUB_FIELDS = ["题目标题", "题目内容", "题目来源", "题目分类", "题目分值", "题目等级", "题目类型", "资源等级", "添加关键字"]
REQUIRED_TOP_SECTIONS = ["## 1 题目设计部署信息", "## 2 HUB上传部分&题解信息"]
REQUIRED_DESIGN_SUBSECTIONS = [f"### 1.{index} " for index in range(1, 9)]
REQUIRED_HUB_SUBSECTIONS = [f"### 2.{index} " for index in range(1, 13)]
REQUIRED_SOLVE_SUBSECTIONS = [
    "#### 题目描述",
    "#### 前置知识",
    "#### 考察知识点",
    "#### 解题工具",
    "#### 题目目标",
    "#### 解题步骤",
    "#### Flag",
]
LEGACY_HEADINGS = ["## 题目说明", "## 环境说明", "## 命令输出", "## 截图说明", "## 复现说明"]


def check_manual_quality(
    *,
    case: dict[str, Any],
    manual_markdown: str,
    hub_fields: dict[str, Any] | None = None,
    archive_manifest: dict[str, Any] | None = None,
    resource_manifest: dict[str, Any] | None = None,
    output_dir: str | Path = "",
) -> dict[str, Any]:
    if hub_fields is None:
        hub_fields = case.get("hub_fields") if isinstance(case.get("hub_fields"), dict) else {}
    else:
        hub_fields = hub_fields or {}
    checks = []
    checks.extend(check_case_fields(case))
    checks.extend(check_manual_sections(manual_markdown, attachment_case=is_attachment_case(case)))
    checks.extend(check_manual_references(case, manual_markdown, archive_manifest=archive_manifest, resource_manifest=resource_manifest))
    checks.extend(check_hub_consistency(case, hub_fields, manual_markdown))
    xlsx_patch = build_xlsx_fields_patch(case, checks)
    summary = summarize_checks(checks)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "version": VERSION,
        "created_at": utc_now(),
        "case_id": str(case.get("case_id") or ""),
        "case_title": data.case_to_xlsx_row(case).get("名称", ""),
        "summary": summary,
        "checks": checks,
        "hub_fields_checked": bool(hub_fields),
        "xlsx_fields_patch": xlsx_patch,
        "notes": [
            "manual_quality_report.md 不展示完整 Flag；xlsx_fields_patch.json 保留完整 Flag，用于内部归档。",
            "Hub 最终提交仍需要人工确认，不由本脚本点击提交。",
        ],
    }
    if str(output_dir).strip():
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        (output / "manual_quality.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (output / "manual_quality_report.md").write_text(render_manual_quality_report(payload), encoding="utf-8")
        (output / "xlsx_fields_patch.json").write_text(json.dumps(xlsx_patch, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def check_case_fields(case: dict[str, Any]) -> list[dict[str, Any]]:
    checks = []
    row = data.case_to_xlsx_row(case)
    for field in REQUIRED_METADATA_FIELDS:
        value = row.get(field, "")
        checks.append(check("case-field-" + safe_id(field), f"字段 {field}", "pass" if value.strip() else "fail", "已填写" if value.strip() else "缺少字段"))
    flag_value = row.get("Flag", "")
    checks.append(
        check(
            "case-field-flag",
            "完整 Flag",
            "pass" if flag_value.strip() else "fail",
            "结构化字段中存在完整 Flag" if flag_value.strip() else "结构化字段缺少完整 Flag",
            evidence={"flag_sha256": sha256_text(flag_value) if flag_value else "", "full_flag_kept_in_xlsx_patch": bool(flag_value)},
        )
    )
    return checks


def check_manual_sections(manual: str, *, attachment_case: bool = False) -> list[dict[str, Any]]:
    checks = []
    text_len = len(re.sub(r"\s+", "", manual))
    checks.append(
        check(
            "manual-min-length",
            "手册正文长度",
            "pass" if text_len >= 500 else "fail",
            f"正文有效字符数 {text_len}",
            evidence={"text_length": text_len},
        )
    )
    placeholder_count = sum(manual.count(item) for item in ["（待填写", "（待补充", "请输入", "TODO", "TBD", "xxx", "【", "（请输入", "（待"])
    checks.append(
        check(
            "manual-placeholders",
            "草稿占位内容",
            "pass" if placeholder_count == 0 else "fail",
            "未发现草稿占位" if placeholder_count == 0 else f"发现 {placeholder_count} 处草稿占位",
            evidence={"placeholder_count": placeholder_count},
        )
    )
    has_top = all(section in manual for section in REQUIRED_TOP_SECTIONS)
    checks.append(
        check(
            "manual-structure-two-part",
            "两段式手册结构",
            "pass" if has_top or attachment_case else "fail",
            "已包含两段式主章节" if has_top else ("附件题允许简化结构" if attachment_case else "缺少两段式主章节"),
        )
    )
    required = list(REQUIRED_DESIGN_SUBSECTIONS) + list(REQUIRED_HUB_SUBSECTIONS) + list(REQUIRED_SOLVE_SUBSECTIONS)
    missing = [item for item in required if item not in manual]
    status = "pass" if not missing else ("warn" if attachment_case and all(item.startswith("### 1.7") for item in missing) else "fail")
    checks.append(
        check(
            "manual-required-subsections",
            "必需章节",
            status,
            "必需章节齐全" if not missing else "缺少章节：" + "、".join(missing[:12]),
            evidence={"missing": missing},
        )
    )
    headings = re.findall(r"^#{2,4}\s+(.+?)\s*$", manual, flags=re.M)
    duplicates = sorted({item for item in headings if headings.count(item) > 1})
    checks.append(
        check(
            "manual-duplicate-headings",
            "重复章节标题",
            "pass" if not duplicates else "fail",
            "未发现重复章节" if not duplicates else "重复章节：" + "、".join(duplicates[:10]),
            evidence={"duplicates": duplicates},
        )
    )
    legacy = [item for item in LEGACY_HEADINGS if re.search(rf"^{re.escape(item)}\s*$", manual, flags=re.M)]
    checks.append(
        check(
            "manual-legacy-residue",
            "旧版扁平标题残留",
            "pass" if not legacy else "fail",
            "未发现旧版标题" if not legacy else "仍存在旧版标题：" + "、".join(legacy),
            evidence={"legacy_headings": legacy},
        )
    )
    flag_consistency = manual_flag_consistency(manual)
    checks.append(
        check(
            "manual-flag-consistency",
            "Flag 一致性",
            "pass" if flag_consistency["consistent"] else "fail",
            "三处 Flag 一致" if flag_consistency["consistent"] else "手册内 Flag 不一致",
            evidence=flag_consistency,
        )
    )
    deploy_consistency = manual_deploy_consistency(manual)
    deploy_status = "pass" if deploy_consistency["consistent"] or attachment_case else "fail"
    checks.append(
        check(
            "manual-deploy-consistency",
            "部署命令一致性",
            deploy_status,
            "部署命令一致" if deploy_consistency["consistent"] else ("附件题不要求镜像部署命令" if attachment_case else "1.7.1 与 1.7.2 部署信息不一致"),
            evidence=deploy_consistency,
        )
    )
    step_substance = manual_step_substance(manual)
    checks.append(
        check(
            "manual-step-substance",
            "解题步骤有效性",
            "pass" if step_substance["has_evidence"] else "fail",
            "解题步骤包含命令、路径、URL 或代码证据" if step_substance["has_evidence"] else "解题步骤缺少可复核证据",
            evidence=step_substance,
        )
    )
    step_density = manual_step_density(manual)
    checks.append(
        check(
            "manual-step-density",
            "解题步骤密度",
            "pass" if step_density >= 3 else "fail",
            f"检测到 {step_density} 个步骤/命令线索",
            evidence={"step_density": step_density},
        )
    )
    return checks


def check_manual_references(
    case: dict[str, Any],
    manual: str,
    *,
    archive_manifest: dict[str, Any] | None = None,
    resource_manifest: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    checks = []
    attachment_paths = declared_paths(case.get("attachments"))
    screenshot_paths = []
    archive_info = case.get("archive") if isinstance(case.get("archive"), dict) else {}
    for item in archive_info.get("screenshots", []) if isinstance(archive_info.get("screenshots"), list) else []:
        screenshot_paths.append(str(item.get("path") if isinstance(item, dict) else item))
    for label, paths, required in [("附件", attachment_paths, bool(attachment_paths)), ("截图", screenshot_paths, True)]:
        missing = [path for path in paths if path and not Path(path).is_file()]
        mentioned = any(Path(path).name in manual for path in paths if path)
        if missing:
            status = "fail"
            message = f"{label}路径不存在：{len(missing)} 个"
        elif paths and not mentioned:
            status = "fail"
            message = f"{label}存在，但手册未引用文件名"
        elif paths:
            status = "pass"
            message = f"{label}存在并可检查"
        else:
            status = "pass" if not required else "fail"
            message = f"未声明{label}"
        label_id = {"附件": "attachments", "截图": "screenshots"}.get(label, safe_id(label))
        checks.append(check(f"manual-reference-{label_id}", f"{label}引用", status, message, evidence={"declared": paths, "missing": missing}))
    manifest_issues = []
    if archive_manifest:
        manifest_issues.extend(str(item) for item in archive_manifest.get("issues", []))
    if resource_manifest:
        manifest_issues.extend(str(item) for item in resource_manifest.get("warnings", []))
    checks.append(
        check(
            "resource-manifest-issues",
            "资源 manifest 问题",
            "pass" if not manifest_issues else "warn",
            "资源 manifest 未记录问题" if not manifest_issues else f"资源 manifest 有 {len(manifest_issues)} 个问题",
            evidence={"issues": manifest_issues[:20]},
        )
    )
    return checks


def check_hub_consistency(case: dict[str, Any], hub_fields: dict[str, Any], manual: str) -> list[dict[str, Any]]:
    checks = []
    row = data.case_to_xlsx_row(case)
    if not hub_fields:
        return [check("hub-fields-present", "Hub 字段", "warn", "未提供 Hub 字段，仅检查手册和 case")]
    for field in REQUIRED_HUB_FIELDS:
        value = str(hub_fields.get(field) or "").strip()
        checks.append(check(f"hub-field-{safe_id(field)}", f"Hub 字段 {field}", "pass" if value else "fail", "已填写" if value else "缺少 Hub 字段"))
    comparisons = [
        ("题目标题", row.get("名称", "")),
        ("题目分类", row.get("分类", "")),
        ("题目类型", row.get("题目类型", "")),
        ("Flag类型", row.get("Flag类型", "")),
    ]
    for hub_key, expected in comparisons:
        current = str(hub_fields.get(hub_key) or "").strip()
        if not current or not expected:
            status = "warn"
            message = "无法比较，字段不完整"
        elif normalize_hub_compare(hub_key, current) == normalize_hub_compare(hub_key, expected):
            status = "pass"
            message = "与 case 字段一致"
        else:
            status = "fail"
            message = f"Hub 字段与 case 不一致：Hub={current}，case={expected}"
        checks.append(check(f"hub-consistency-{safe_id(hub_key)}", f"Hub 一致性 {hub_key}", status, message))
    answer = str(hub_fields.get("题目解答") or hub_fields.get("manual_markdown") or "")
    if answer and normalize_text(answer[:100]) in normalize_text(manual):
        checks.append(check("hub-answer-manual", "Hub 解答与手册", "pass", "Hub 解答来自手册内容"))
    elif answer:
        checks.append(check("hub-answer-manual", "Hub 解答与手册", "warn", "Hub 解答与当前手册文本不完全一致"))
    else:
        checks.append(check("hub-answer-manual", "Hub 解答与手册", "fail", "Hub 字段缺少题目解答"))
    return checks


def build_xlsx_fields_patch(case: dict[str, Any], checks: list[dict[str, Any]]) -> dict[str, str]:
    row = data.case_to_xlsx_row(case)
    fail_count = sum(1 for item in checks if item["status"] == "fail")
    warn_count = sum(1 for item in checks if item["status"] == "warn")
    solve_verified = case_solve_verified(case)
    current_validation = str(row.get("验证状态") or "").strip()
    row["手册状态"] = "已校验" if fail_count == 0 else "待人工完善"
    if fail_count:
        row["验证状态"] = "失败"
        row["是否通过"] = "否"
    elif solve_verified:
        row["验证状态"] = "通过" if not warn_count else "部分通过"
        row["是否通过"] = "是" if not warn_count else "否"
    else:
        row["验证状态"] = current_validation if current_validation in {"未验证", "部分通过", "失败"} else "部分通过"
        row["是否通过"] = "否"
    row["问题"] = ";".join(item["message"] for item in checks if item["status"] in {"fail", "warn"})[:1000]
    return row


def case_solve_verified(case: dict[str, Any]) -> bool:
    review = case.get("review") if isinstance(case.get("review"), dict) else {}
    writeup = case.get("writeup") if isinstance(case.get("writeup"), dict) else {}
    docker_artifacts = case.get("docker_artifacts") if isinstance(case.get("docker_artifacts"), dict) else {}
    return any(
        value is True
        for value in [
            review.get("solve_verified"),
            review.get("flag_verified"),
            writeup.get("solve_verified"),
            docker_artifacts.get("solve_verified"),
        ]
    )


def summarize_checks(checks: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {status: sum(1 for item in checks if item["status"] == status) for status in ["pass", "warn", "fail"]}
    if counts["fail"]:
        status = "fail"
    elif counts["warn"]:
        status = "needs_review"
    else:
        status = "pass"
    return {"status": status, **counts, "total": len(checks)}


def render_manual_quality_report(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines = [
        "# 手册质量检查报告",
        "",
        f"- 题目：{payload.get('case_title', '') or payload.get('case_id', '')}",
        f"- 状态：{summary.get('status', '')}",
        f"- 通过：{summary.get('pass', 0)}",
        f"- 警告：{summary.get('warn', 0)}",
        f"- 失败：{summary.get('fail', 0)}",
        "",
        "| 检查项 | 状态 | 说明 |",
        "|---|---|---|",
    ]
    for item in payload.get("checks", []):
        lines.append(f"| {escape_table(item.get('name', ''))} | {item.get('status', '')} | {escape_table(item.get('message', ''))} |")
    lines.extend(["", "## xlsx 字段更新", ""])
    patch = payload.get("xlsx_fields_patch", {})
    for key in ["名称", "分类", "题目类型", "Flag类型", "手册状态", "验证状态", "是否通过", "问题"]:
        lines.append(f"- {key}：{patch.get(key, '')}")
    if patch.get("Flag"):
        lines.append(f"- Flag：已保留完整值，SHA256 `{sha256_text(str(patch.get('Flag')))}`")
    return "\n".join(lines) + "\n"


def check(check_id: str, name: str, status: str, message: str, *, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "id": check_id,
        "name": name,
        "status": status,
        "message": message,
        "evidence": evidence or {},
    }


def declared_paths(value: Any) -> list[str]:
    paths = []
    if not isinstance(value, list):
        return paths
    for item in value:
        if isinstance(item, dict):
            path = str(item.get("path") or item.get("local_path") or "")
        else:
            path = str(item)
        if path:
            paths.append(path)
    return paths


def manual_step_density(manual: str) -> int:
    count = 0
    count += len(re.findall(r"^\s*(?:\d+[\).、]|[-*]\s+)", manual, flags=re.M))
    count += len(re.findall(r"`[^`]{4,}`", manual))
    count += len(re.findall(r"```", manual)) // 2
    return count


def is_attachment_case(case: dict[str, Any]) -> bool:
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    question_type = str(metadata.get("题目类型") or "")
    return "附件" in question_type


FLAG_PATTERN = re.compile(r"\b(?:flag|[A-Za-z0-9_]*CTF)\{[^}\n]+\}", flags=re.I)


def manual_flag_consistency(manual: str) -> dict[str, Any]:
    flags = FLAG_PATTERN.findall(manual)
    unique = sorted({item for item in flags})
    return {
        "flag_count": len(flags),
        "unique_count": len(unique),
        "consistent": bool(flags) and len(unique) == 1,
        "flag_sha256": sha256_text(unique[0]) if len(unique) == 1 else "",
    }


def manual_deploy_consistency(manual: str) -> dict[str, Any]:
    dockerfile_section = section_between(manual, "#### 1.7.1 Dockerfile 构建启动", ["#### 1.7.2 Tar 镜像包导入启动"])
    tar_section = section_between(manual, "#### 1.7.2 Tar 镜像包导入启动", ["### 1.8 非预期测试"])
    if "附件题不需要" in dockerfile_section and "附件题不需要" in tar_section:
        return {"consistent": True, "reason": "attachment"}
    docker_runs = docker_run_facts(dockerfile_section)
    tar_runs = docker_run_facts(tar_section)
    if not docker_runs or not tar_runs:
        return {"consistent": False, "dockerfile": docker_runs, "tar": tar_runs}
    image_match = bool(set(docker_runs["images"]) & set(tar_runs["images"]))
    port_match = not docker_runs["ports"] or not tar_runs["ports"] or bool(set(docker_runs["ports"]) & set(tar_runs["ports"]))
    return {
        "consistent": image_match and port_match,
        "dockerfile": docker_runs,
        "tar": tar_runs,
        "image_match": image_match,
        "port_match": port_match,
    }


def docker_run_facts(section: str) -> dict[str, list[str]]:
    images = []
    ports = []
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("docker run"):
            continue
        port_match = re.findall(r"(?:^|\s)-p\s+([^\s]+)", stripped)
        ports.extend(port_match)
        tokens = stripped.split()
        if tokens:
            images.append(tokens[-1])
    return {"images": images, "ports": ports}


def manual_step_substance(manual: str) -> dict[str, Any]:
    section = section_between(manual, "#### 解题步骤", ["#### Flag", "#### 命令输出", "## "])
    evidence_patterns = [
        r"```",
        r"`[^`]{4,}`",
        r"\b(?:python|curl|nc|docker|burp|sqlmap|dirsearch|gdb|strings|socket)\b",
        r"https?://",
        r"/[A-Za-z0-9_.\-/]+",
        r"flag\{[^}\n]+\}",
    ]
    matches = [pattern for pattern in evidence_patterns if re.search(pattern, section, flags=re.I)]
    has_placeholder = "待人工确认" in section or "不能编造步骤" in section
    return {
        "has_evidence": bool(matches) and not has_placeholder,
        "matched_patterns": matches,
        "has_placeholder": has_placeholder,
        "section_length": len(section.strip()),
    }


def section_between(manual: str, start: str, end_markers: list[str]) -> str:
    start_index = manual.find(start)
    if start_index == -1:
        return ""
    content_start = start_index + len(start)
    end_indexes = [manual.find(marker, content_start) for marker in end_markers]
    end_indexes = [index for index in end_indexes if index != -1]
    content_end = min(end_indexes) if end_indexes else len(manual)
    return manual[content_start:content_end]


def normalize_text(value: str) -> str:
    return re.sub(r"\s+", "", value.strip().lower())


def normalize_hub_compare(field: str, value: str) -> str:
    if field == "Flag类型":
        return normalize_text(data.normalize_flag_type_for_display(value))
    return normalize_text(value)


def safe_id(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    return text.strip("-").lower() or "field"


def escape_table(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_optional_json(path: str | Path | None) -> Any:
    if path is None or not str(path).strip():
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF manual quality checks")
    parser.add_argument("--case-json", required=True)
    parser.add_argument("--manual", required=True)
    parser.add_argument("--hub-fields")
    parser.add_argument("--archive-manifest")
    parser.add_argument("--resource-manifest")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)

    case = json.loads(Path(args.case_json).read_text(encoding="utf-8"))
    manual = Path(args.manual).read_text(encoding="utf-8")
    check_manual_quality(
        case=case,
        manual_markdown=manual,
        hub_fields=load_optional_json(args.hub_fields),
        archive_manifest=load_optional_json(args.archive_manifest),
        resource_manifest=load_optional_json(args.resource_manifest),
        output_dir=args.output_dir,
    )
    print(f"wrote {Path(args.output_dir) / 'manual_quality.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
