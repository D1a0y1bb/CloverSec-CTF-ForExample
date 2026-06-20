#!/usr/bin/env python3
"""Hub review retag planning helpers for CloverSec CTF workflows."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TARGET_PLATFORM = "linux/amd64"
AGENT_DECISION_BOOL_FIELDS = ["can_execute", "requires_user_confirmation", "execute_docker"]
FORMAL_HUB_ID_RE = re.compile(r"^CTF-\d{6,}$", re.I)


def hub_id_gate(hub_id: str, *, user_confirmed: bool = False) -> dict[str, Any]:
    candidate = str(hub_id or "").strip()
    if not candidate or not FORMAL_HUB_ID_RE.match(candidate):
        return {
            "status": "needs_hub_id",
            "hub_id": "",
            "candidate_hub_id": candidate,
            "user_confirmed": bool(user_confirmed),
            "can_backfill_tag": False,
            "can_backfill_xlsx": False,
            "reason": "缺少正式 Hub 编号，不能生成镜像 tag 或 xlsx 回填字段。",
        }
    if not user_confirmed:
        return {
            "status": "needs_user_confirm",
            "hub_id": "",
            "candidate_hub_id": candidate,
            "user_confirmed": False,
            "can_backfill_tag": False,
            "can_backfill_xlsx": False,
            "reason": "已提供疑似正式 Hub 编号，但需要用户确认后才能 retag。",
        }
    return {
        "status": "ready_to_backfill",
        "hub_id": candidate,
        "candidate_hub_id": candidate,
        "user_confirmed": True,
        "can_backfill_tag": True,
        "can_backfill_xlsx": True,
        "reason": "Hub 编号已确认，可以用于 retag 和 xlsx。",
    }


def create_image_naming_plan(
    case: dict[str, Any],
    hub_id: str,
    output_dir: str | Path,
    *,
    registry_prefix: str = "",
    tag_template: str = "{hub_id}",
    hub_id_confirmed: bool = False,
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    docker_artifacts = case.get("docker_artifacts") if isinstance(case.get("docker_artifacts"), dict) else {}
    safe_hub_id = _safe_tag_part(hub_id)
    case_part = _safe_tag_part(str(case.get("case_id") or ""))
    name_part = _safe_tag_part(str(metadata.get("名称") or ""))
    category_part = _safe_tag_part(str(metadata.get("分类") or "ctf"))
    gate = hub_id_gate(hub_id, user_confirmed=hub_id_confirmed)
    if gate["can_backfill_tag"]:
        tag_body = tag_template.format(hub_id=safe_hub_id, case_id=case_part, name=name_part, category=category_part).strip(":/")
        image_tag = f"{registry_prefix.rstrip('/')}/{tag_body}" if registry_prefix else tag_body
        tar_name = f"{safe_hub_id}.tar"
        status = "ready"
        issues: list[str] = []
    else:
        image_tag = ""
        tar_name = ""
        status = gate["status"]
        issues = [gate["reason"]]
    tar_path = (output / tar_name).as_posix() if tar_name else ""
    plan = {
        "schema_version": "cloversec.ctf.image_naming_plan.v1",
        "version": "1.0.11",
        "case_id": str(case.get("case_id") or ""),
        "case_title": str(metadata.get("名称") or ""),
        "hub_id": hub_id,
        "hub_id_gate": gate,
        "status": status,
        "source_image": str(docker_artifacts.get("image_name") or ""),
        "image_tag": image_tag,
        "tar_name": tar_name,
        "tar_path": tar_path,
        "target_platform": TARGET_PLATFORM,
        "issues": issues,
        "xlsx_fields": {
            "HUB编号": hub_id if gate["can_backfill_xlsx"] else "",
            "环境包/附件包路径": tar_path,
        },
        "retag_inputs": {
            "case_json_required": True,
            "hub_id": hub_id,
            "output_dir": output.as_posix(),
            "registry_prefix": registry_prefix,
            "tag_template": tag_template,
            "execute": False,
        },
    }
    (output / "image_naming_plan.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "retag_inputs.json").write_text(json.dumps(plan["retag_inputs"], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "image_naming_plan.md").write_text(render_image_naming_plan(plan), encoding="utf-8")
    return plan


def create_retag_plan(
    case: dict[str, Any],
    hub_id: str,
    output_dir: str | Path,
    *,
    registry_prefix: str = "",
    tag_template: str = "{hub_id}",
    hub_id_confirmed: bool = False,
) -> dict[str, Any]:
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    docker_artifacts = case.get("docker_artifacts") if isinstance(case.get("docker_artifacts"), dict) else {}
    source_image = str(docker_artifacts.get("image_name") or "")
    safe_hub_id = _safe_tag_part(hub_id)
    gate = hub_id_gate(hub_id, user_confirmed=hub_id_confirmed)
    tag_body = tag_template.format(
        hub_id=safe_hub_id,
        case_id=_safe_tag_part(str(case.get("case_id") or "")),
        name=_safe_tag_part(str(metadata.get("名称") or "")),
    ).strip(":/")
    new_image = f"{registry_prefix.rstrip('/')}/{tag_body}" if registry_prefix else tag_body
    tar_path = Path(output_dir) / f"{safe_hub_id or 'hub-image'}.tar"
    if not gate["can_backfill_tag"]:
        new_image = ""
        tar_path = Path(output_dir) / "hub-image.pending.tar"

    commands = {}
    if gate["can_backfill_tag"]:
        commands = {
            "tag": f"docker tag {shlex.quote(source_image)} {shlex.quote(new_image)}",
            "export": f"docker save {shlex.quote(new_image)} -o {shlex.quote(tar_path.as_posix())}",
            "import": f"docker load -i {shlex.quote(tar_path.as_posix())}",
            "inspect": f"docker image inspect {shlex.quote(new_image)}",
        }
    issues = []
    if not gate["can_backfill_tag"]:
        issues.append(gate["reason"])
    if not source_image:
        issues.append("docker_artifacts.image_name 为空")
    if docker_artifacts.get("platform") and docker_artifacts.get("platform") != TARGET_PLATFORM:
        issues.append(f"镜像平台不是 {TARGET_PLATFORM}")
    if not new_image:
        issues.append("无法生成新镜像 tag")

    plan = {
        "case_id": str(case.get("case_id") or ""),
        "hub_id": hub_id if gate["can_backfill_tag"] else "",
        "hub_id_gate": gate,
        "source_image": source_image,
        "new_image": new_image,
        "target_platform": TARGET_PLATFORM,
        "tar_path": tar_path.as_posix(),
        "commands": commands,
        "issues": issues,
        "xlsx_fields": {
            "HUB编号": hub_id if gate["can_backfill_xlsx"] else "",
            "环境包/附件包路径": tar_path.as_posix(),
        },
    }
    return plan


def render_image_naming_plan(plan: dict[str, Any]) -> str:
    lines = [
        "# 镜像命名计划",
        "",
        f"- 状态：{plan.get('status', '')}",
        f"- 题目 ID：{plan.get('case_id', '')}",
        f"- HUB 编号：{plan.get('hub_id', '')}",
        f"- 源镜像：{plan.get('source_image', '')}",
        f"- 新镜像 tag：{plan.get('image_tag', '')}",
        f"- tar 文件名：{plan.get('tar_name', '')}",
        f"- tar 路径：{plan.get('tar_path', '')}",
        f"- 目标平台：{plan.get('target_platform', '')}",
        "",
        "## xlsx 字段",
        "",
    ]
    for key, value in plan.get("xlsx_fields", {}).items():
        lines.append(f"- {key}：{value}")
    if plan.get("issues"):
        lines.extend(["", "## 需要处理", ""])
        lines.extend(f"- {issue}" for issue in plan["issues"])
    return "\n".join(lines) + "\n"


def apply_retag_outputs(case: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    updated = copy.deepcopy(case)
    updated.setdefault("metadata", {})
    updated.setdefault("docker_artifacts", {})
    updated["docker_artifacts"]["image_name"] = plan.get("new_image", "")
    updated["docker_artifacts"]["tar_path"] = plan.get("tar_path", "")
    updated["docker_artifacts"]["platform"] = plan.get("target_platform", TARGET_PLATFORM)
    updated["docker_artifacts"]["retag_plan"] = copy.deepcopy(plan)
    if plan.get("execution"):
        updated["docker_artifacts"]["retag_execution"] = copy.deepcopy(plan["execution"])
        if plan["execution"].get("summary", {}).get("tar_sha256"):
            updated["docker_artifacts"]["sha256"] = plan["execution"]["summary"]["tar_sha256"]
        if plan["execution"].get("summary", {}).get("platform"):
            updated["docker_artifacts"]["platform"] = plan["execution"]["summary"]["platform"]
    for key, value in plan.get("xlsx_fields", {}).items():
        updated["metadata"][key] = value
    return updated


def execute_retag_plan(plan: dict[str, Any], *, command_timeout: int = 60) -> dict[str, Any]:
    tar_path = Path(str(plan.get("tar_path") or ""))
    tar_path.parent.mkdir(parents=True, exist_ok=True)
    source_image = str(plan.get("source_image") or "")
    new_image = str(plan.get("new_image") or "")
    execution: dict[str, Any] = {
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "source_image": source_image,
        "new_image": new_image,
        "tar_path": tar_path.as_posix(),
        "steps": [],
        "summary": {
            "status": "fail",
            "platform": "",
            "tar_sha256": "",
            "issues": [],
        },
    }
    issues = []
    if not source_image:
        issues.append("source_image 为空")
    if not new_image:
        issues.append("new_image 为空")
    if issues:
        execution["summary"]["issues"] = issues
        return execution

    steps = execution["steps"]
    steps.append(_run_command(["docker", "tag", source_image, new_image], timeout=command_timeout))
    steps.append(_run_command(["docker", "save", new_image, "-o", tar_path.as_posix()], timeout=command_timeout))
    if tar_path.is_file():
        execution["summary"]["tar_sha256"] = sha256_file(tar_path)
    else:
        issues.append(f"tar 未生成：{tar_path}")
    steps.append(_run_command(["docker", "load", "-i", tar_path.as_posix()], timeout=command_timeout))
    inspect = _run_command(["docker", "image", "inspect", new_image], timeout=command_timeout)
    steps.append(inspect)
    platform = _platform_from_inspect_output(inspect.get("stdout", ""))
    if platform:
        execution["summary"]["platform"] = platform
    if platform and platform != TARGET_PLATFORM:
        issues.append(f"镜像平台不是 {TARGET_PLATFORM}: {platform}")
    for step in steps:
        if step.get("status") == "fail":
            issues.append(f"{step.get('id')}: exit_code={step.get('exit_code')}")
    execution["summary"]["issues"] = issues
    execution["summary"]["status"] = "pass" if not issues else "fail"
    return execution


def render_retag_report(plan: dict[str, Any]) -> str:
    lines = [
        "# Hub 编号与镜像 tag 计划",
        "",
        f"- 题目 ID：{plan.get('case_id', '')}",
        f"- HUB 编号：{plan.get('hub_id', '')}",
        f"- 原镜像：{plan.get('source_image', '')}",
        f"- 新镜像：{plan.get('new_image', '')}",
        f"- 新 tar：{plan.get('tar_path', '')}",
        f"- 目标平台：{plan.get('target_platform', '')}",
        "",
        "## Docker 命令",
        "",
    ]
    for key, command in plan.get("commands", {}).items():
        lines.append(f"- {key}: `{command}`")
    if plan.get("issues"):
        lines.extend(["", "## 需要处理", ""])
        lines.extend(f"- {issue}" for issue in plan["issues"])
    else:
        lines.extend(["", "## 状态", "", "- 可按命令执行 retag、导出和 inspect。"])
    if plan.get("execution"):
        summary = plan["execution"].get("summary", {})
        lines.extend(["", "## 执行证据", ""])
        lines.append(f"- 状态：{summary.get('status', '')}")
        lines.append(f"- 平台：{summary.get('platform', '')}")
        lines.append(f"- tar SHA256：{summary.get('tar_sha256', '')}")
        if summary.get("issues"):
            lines.extend(f"- {issue}" for issue in summary["issues"])
    return "\n".join(lines) + "\n"


def validate_agent_decision(payload: dict[str, Any]) -> dict[str, Any]:
    issues = []
    for field in AGENT_DECISION_BOOL_FIELDS:
        if field not in payload:
            issues.append(f"{field} missing")
        elif not isinstance(payload.get(field), bool):
            issues.append(f"{field} must be boolean true/false")
    next_action = str(payload.get("next_action") or "")
    if next_action not in {"ask_user", "create_plan", "stop"}:
        issues.append("next_action must be ask_user, create_plan, or stop")
    if payload.get("can_execute") is True:
        if not str(payload.get("hub_id") or "").strip():
            issues.append("hub_id required when can_execute is true")
        if payload.get("requires_user_confirmation") is not False:
            issues.append("requires_user_confirmation must be false when execution is already authorized")
    if payload.get("can_execute") is False and payload.get("execute_docker") is True:
        issues.append("execute_docker cannot be true when can_execute is false")
    return {
        "status": "valid" if not issues else "invalid",
        "issues": issues,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_command(args: list[str], *, timeout: int) -> dict[str, Any]:
    started = time.time()
    command_id = _command_id(args)
    try:
        result = subprocess.run(args, check=False, capture_output=True, text=True, timeout=timeout)
        status = "pass" if result.returncode == 0 else "fail"
        return {
            "id": command_id,
            "status": status,
            "command": args,
            "exit_code": result.returncode,
            "stdout": _truncate(result.stdout),
            "stderr": _truncate(result.stderr),
            "duration_seconds": round(time.time() - started, 3),
            "message": "ok" if status == "pass" else _truncate(result.stderr or result.stdout),
        }
    except FileNotFoundError as exc:
        return {
            "id": command_id,
            "status": "fail",
            "command": args,
            "exit_code": 127,
            "stdout": "",
            "stderr": str(exc),
            "duration_seconds": round(time.time() - started, 3),
            "message": str(exc),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "id": command_id,
            "status": "fail",
            "command": args,
            "exit_code": 124,
            "stdout": _truncate(exc.stdout or ""),
            "stderr": _truncate(exc.stderr or ""),
            "duration_seconds": round(time.time() - started, 3),
            "message": f"timeout after {timeout}s",
        }


def _command_id(args: list[str]) -> str:
    if args[:2] == ["docker", "tag"]:
        return "docker-tag"
    if args[:2] == ["docker", "save"]:
        return "docker-save"
    if args[:2] == ["docker", "load"]:
        return "docker-load"
    if args[:3] == ["docker", "image", "inspect"]:
        return "docker-image-inspect"
    return "-".join(args[:3])


def _platform_from_inspect_output(output: str) -> str:
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return ""
    image = payload[0] if isinstance(payload, list) and payload else payload
    if not isinstance(image, dict):
        return ""
    os_name = image.get("Os") or image.get("OS") or ""
    arch = image.get("Architecture") or ""
    return f"{os_name}/{arch}" if os_name and arch else ""


def _truncate(value: Any, limit: int = 4000) -> str:
    text = value.decode() if isinstance(value, bytes) else str(value or "")
    return text if len(text) <= limit else text[-limit:]


def _safe_tag_part(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    text = re.sub(r"-+", "-", text).strip(".-")
    return text[:96].lower()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF Hub retag utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    naming_parser = subparsers.add_parser("image-naming", help="create image tag, tar name, xlsx fields, and retag inputs")
    naming_parser.add_argument("--case-json", required=True)
    naming_parser.add_argument("--hub-id", default="")
    naming_parser.add_argument("--output-dir", required=True)
    naming_parser.add_argument("--registry-prefix", default="")
    naming_parser.add_argument("--tag-template", default="{hub_id}")
    naming_parser.add_argument("--hub-id-confirmed", action="store_true")

    plan_parser = subparsers.add_parser("plan", help="create retag plan after Hub review")
    plan_parser.add_argument("--case-json", required=True)
    plan_parser.add_argument("--hub-id", required=True)
    plan_parser.add_argument("--output-dir", required=True)
    plan_parser.add_argument("--registry-prefix", default="")
    plan_parser.add_argument("--tag-template", default="{hub_id}")
    plan_parser.add_argument("--hub-id-confirmed", action="store_true")
    plan_parser.add_argument("--output", required=True)
    plan_parser.add_argument("--report")
    plan_parser.add_argument("--output-case")
    plan_parser.add_argument("--execute", action="store_true", help="run docker tag/save/load/inspect and record evidence")
    plan_parser.add_argument("--command-timeout", type=int, default=60)

    decision_parser = subparsers.add_parser("validate-agent-decision", help="validate strict JSON decision for retag Agent output")
    decision_parser.add_argument("--input", required=True)
    decision_parser.add_argument("--output", required=True)

    args = parser.parse_args(argv)
    if args.command == "image-naming":
        case = json.loads(Path(args.case_json).read_text(encoding="utf-8"))
        create_image_naming_plan(
            case,
            args.hub_id,
            args.output_dir,
            registry_prefix=args.registry_prefix,
            tag_template=args.tag_template,
            hub_id_confirmed=args.hub_id_confirmed,
        )
        print(f"wrote {Path(args.output_dir) / 'image_naming_plan.json'}")
        return 0
    if args.command == "plan":
        case = json.loads(Path(args.case_json).read_text(encoding="utf-8"))
        plan = create_retag_plan(
            case,
            args.hub_id,
            args.output_dir,
            registry_prefix=args.registry_prefix,
            tag_template=args.tag_template,
            hub_id_confirmed=args.hub_id_confirmed,
        )
        if args.execute:
            plan["execution"] = execute_retag_plan(plan, command_timeout=args.command_timeout)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        report_path = Path(args.report) if args.report else output.with_suffix(".md")
        report_path.write_text(render_retag_report(plan), encoding="utf-8")
        if args.output_case:
            updated = apply_retag_outputs(case, plan)
            Path(args.output_case).write_text(json.dumps(updated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {output}")
        return 0
    if args.command == "validate-agent-decision":
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
        result = validate_agent_decision(payload)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {output}")
        return 0 if result["status"] == "valid" else 1

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
