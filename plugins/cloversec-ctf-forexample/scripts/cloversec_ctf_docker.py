#!/usr/bin/env python3
"""Controlled Docker execution helpers for CloverSec CTF workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import cloversec_ctf_http as http
import cloversec_ctf_i18n as i18n


TARGET_PLATFORM = "linux/amd64"
DEFAULT_OPERATIONS = ["build", "load", "inspect", "run", "logs", "stop", "save"]
OPERATION_ALIASES = {
    "inspect_image": ["inspect"],
    "image_inspect": ["inspect"],
    "probe": ["run", "logs", "stop"],
    "probe_http": ["run", "logs", "stop"],
    "http_probe": ["run", "logs", "stop"],
    "probe_tcp": ["run", "logs", "stop"],
    "tcp_probe": ["run", "logs", "stop"],
    "run_probe": ["run", "logs", "stop"],
    "cleanup": ["stop"],
    "remove": ["stop"],
    "rm": ["stop"],
    "save_image": ["save"],
    "save_image_tar": ["save"],
}
VERSION = "1.1.4"
VALIDATION_LEVELS = ["static_only", "inspect_only", "build_only", "run_probe", "solve_verify"]
OPERATION_AUTH_ACTIONS = {
    "build": "docker_build",
    "load": "docker_load",
    "inspect": "docker_inspect",
    "run": "docker_run_probe",
    "logs": "docker_run_probe",
    "stop": "docker_run_probe",
    "save": "docker_save",
}


def create_docker_plan(
    *,
    case: dict[str, Any] | None = None,
    project_dir: str | Path = "",
    image_name: str = "",
    tar_path: str | Path = "",
    ports: list[str] | None = None,
    dockerfile: str | Path = "",
    container_command: str = "",
    operations: list[str] | None = None,
    validation_level: str = "",
    container_inference: dict[str, Any] | None = None,
) -> dict[str, Any]:
    case = case or {}
    container_inference = container_inference or {}
    docker_artifacts = case.get("docker_artifacts") if isinstance(case.get("docker_artifacts"), dict) else {}
    environment = case.get("environment") if isinstance(case.get("environment"), dict) else {}
    inferred_runtime = container_inference.get("runtime") if isinstance(container_inference.get("runtime"), dict) else {}
    selected_level = normalize_validation_level(validation_level or inferred_runtime.get("validation_level") or "")
    selected_ports = normalize_ports(ports or docker_artifacts.get("ports") or environment.get("port_mappings") or inferred_runtime.get("ports") or [])
    selected_image = str(image_name or docker_artifacts.get("image_name") or inferred_runtime.get("image_name") or "").strip()
    selected_tar = str(tar_path or docker_artifacts.get("tar_path") or "").strip()
    selected_project_dir_text = str(
        project_dir
        or docker_artifacts.get("project_dir")
        or environment.get("project_dir")
        or inferred_runtime.get("build_context")
        or ""
    ).strip()
    selected_project_dir = Path(selected_project_dir_text) if selected_project_dir_text else None
    selected_dockerfile = Path(str(dockerfile or inferred_runtime.get("dockerfile") or "Dockerfile"))
    dockerfile_for_command = resolve_dockerfile_path(selected_project_dir, selected_dockerfile)
    selected_command = str(container_command or environment.get("start_command") or inferred_runtime.get("container_command") or "").strip()
    selected_protocol = normalize_probe_protocol(
        inferred_runtime.get("probe_protocol")
        or inferred_runtime.get("service_protocol")
        or inferred_runtime.get("protocol")
        or ""
    )
    raw_operations = operations if operations is not None else operations_for_validation_level(selected_level, tar_path=selected_tar)
    selected_operations = [] if selected_level == "static_only" and raw_operations == [] else normalize_operations(raw_operations)
    case_id = infer_case_id(case=case, project_dir=selected_project_dir, image_name=selected_image)
    container_name = f"cloversec-docker-{safe_token(case_id)}-{int(time.time())}"

    commands: dict[str, list[str]] = {}
    if "build" in selected_operations:
        commands["build"] = [
            "docker",
            "build",
            "--platform",
            TARGET_PLATFORM,
            "-t",
            selected_image,
            "-f",
            dockerfile_for_command.as_posix(),
            selected_project_dir.as_posix() if selected_project_dir else "",
        ]
    if "load" in selected_operations and selected_tar:
        commands["load"] = ["docker", "load", "-i", selected_tar]
    if "inspect" in selected_operations:
        commands["inspect"] = ["docker", "image", "inspect", selected_image]
    if "run" in selected_operations:
        run_args = ["docker", "run", "-d", "--name", container_name]
        for mapping in selected_ports:
            run_args.extend(["-p", mapping])
        run_args.append(selected_image)
        if selected_command:
            run_args.extend(shlex.split(selected_command))
        commands["run"] = run_args
    if "logs" in selected_operations:
        commands["logs"] = ["docker", "logs", container_name]
    if "stop" in selected_operations:
        commands["stop"] = ["docker", "stop", container_name]
        commands["rm"] = ["docker", "rm", container_name]
    if "save" in selected_operations and selected_tar:
        commands["save"] = ["docker", "save", selected_image, "-o", selected_tar]

    issues = []
    if selected_level == "static_only" and selected_operations:
        issues.append("static_only validation must not execute Docker operations")
    if raw_operations is not None and raw_operations and not selected_operations:
        issues.append("no recognized docker operations: " + ", ".join(str(item) for item in raw_operations))
    if selected_operations and not selected_image:
        issues.append("image_name is required")
    if "build" in selected_operations and not selected_project_dir_text:
        issues.append("project_dir is required for docker build")
    if "save" in selected_operations and not selected_tar:
        issues.append("tar_path is required for docker save")

    return {
        "schema_version": "cloversec.ctf.docker_plan.v1",
        "version": VERSION,
        "case_id": case_id,
        "validation_level": selected_level,
        "target_platform": TARGET_PLATFORM,
        "image_name": selected_image,
        "tar_path": selected_tar,
        "project_dir": selected_project_dir.as_posix() if selected_project_dir else "",
        "dockerfile": dockerfile_for_command.as_posix(),
        "ports": selected_ports,
        "probe_protocol": selected_protocol,
        "probe_urls": [] if selected_protocol == "tcp" else probe_urls_from_ports(selected_ports),
        "tcp_probes": tcp_probes_from_ports(selected_ports) if selected_protocol == "tcp" else [],
        "operations": selected_operations,
        "container_name": container_name,
        "commands": commands,
        "issues": issues,
        "safety": [
            "Only run Docker operations explicitly requested by the Agent/user.",
            "validation_level=static_only creates evidence without running Docker.",
            "validation_level=solve_verify records the intent; it does not execute unknown solver scripts.",
            "Record command output, exit code, platform, probes, logs, tar hash, and failure evidence.",
            "Stop and remove the test container after run/logs when stop is requested.",
        ],
    }


def create_docker_validation_plan(
    *,
    case: dict[str, Any] | None = None,
    project_dir: str | Path = "",
    image_name: str = "",
    tar_path: str | Path = "",
    ports: list[str] | None = None,
    dockerfile: str | Path = "",
    container_command: str = "",
    validation_level: str = "",
    container_inference: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return create_docker_plan(
        case=case,
        project_dir=project_dir,
        image_name=image_name,
        tar_path=tar_path,
        ports=ports,
        dockerfile=dockerfile,
        container_command=container_command,
        operations=None,
        validation_level=validation_level,
        container_inference=container_inference,
    )


def execute_docker_workflow(
    *,
    case: dict[str, Any] | None = None,
    output_dir: str | Path,
    project_dir: str | Path = "",
    image_name: str = "",
    tar_path: str | Path = "",
    ports: list[str] | None = None,
    dockerfile: str | Path = "",
    container_command: str = "",
    operations: list[str] | None = None,
    validation_level: str = "",
    container_inference: dict[str, Any] | None = None,
    probe_urls: list[str] | None = None,
    startup_wait: float = 2.0,
    command_timeout: int = 60,
    probe_timeout: float = 3.0,
    authorization_workdir: str | Path = "",
    authorization_path: str | Path = "",
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    plan = create_docker_plan(
        case=case,
        project_dir=project_dir,
        image_name=image_name,
        tar_path=tar_path,
        ports=ports,
        dockerfile=dockerfile,
        container_command=container_command,
        operations=operations,
        validation_level=validation_level,
        container_inference=container_inference,
    )
    if "run" in set(plan.get("operations", [])):
        rewrite_ports_to_available(plan)
    evidence: dict[str, Any] = {
        "schema_version": "cloversec.ctf.docker_evidence.v1",
        "case_id": plan["case_id"],
        "executed_at": utc_now(),
        "plan": plan,
        "steps": [],
        "probes": [],
        "artifacts": {},
        "summary": {
            "status": "fail",
            "validation_level": plan.get("validation_level", ""),
            "platform": "",
            "run_verified": False,
            "tar_sha256": "",
            "logs_path": "",
            "issues": [],
        },
    }

    issues = list(plan.get("issues", []))
    commands = plan.get("commands", {})
    container_started = False
    run_attempted = False
    container_name = str(plan.get("container_name") or "")
    selected_operations = set(plan.get("operations", []))
    auth_errors = authorization_errors(
        operations=selected_operations,
        case_id=str(plan.get("case_id") or ""),
        authorization_workdir=authorization_workdir,
        authorization_path=authorization_path,
    )
    if auth_errors:
        issues.extend(auth_errors)

    if issues:
        evidence["summary"]["issues"] = issues
        write_evidence(output, evidence)
        return evidence

    if not selected_operations:
        evidence["summary"]["status"] = "skip"
        evidence["summary"]["run_verified"] = False
        evidence["summary"]["issues"] = []
        evidence["summary"]["message"] = i18n.text("docker.no_operations_selected")
        write_evidence(output, evidence)
        return evidence

    try:
        for operation in ["build", "load", "inspect", "run"]:
            if operation not in selected_operations or operation not in commands:
                continue
            step = run_command(commands[operation], timeout=command_timeout)
            evidence["steps"].append(step)
            if operation == "inspect":
                platform = platform_from_inspect_output(step.get("stdout", ""))
                if platform:
                    evidence["summary"]["platform"] = platform
            if operation == "run":
                run_attempted = True
                container_started = step.get("status") == "pass"

        if container_started:
            time.sleep(max(startup_wait, 0))

        if "logs" in selected_operations and "logs" in commands:
            logs_step = run_command(commands["logs"], timeout=command_timeout)
            logs_path = output / "docker_logs.txt"
            logs_path.write_text(str(logs_step.get("stdout") or "") + str(logs_step.get("stderr") or ""), encoding="utf-8")
            logs_step["path"] = logs_path.as_posix()
            evidence["summary"]["logs_path"] = logs_path.as_posix()
            evidence["steps"].append(logs_step)

        planned_http_urls = list(probe_urls or []) + [str(item) for item in plan.get("probe_urls", []) if str(item).strip()]
        if planned_http_urls:
            for url in planned_http_urls:
                evidence["probes"].append(probe_url(url, timeout=probe_timeout))
        for probe in plan.get("tcp_probes", []) if isinstance(plan.get("tcp_probes"), list) else []:
            if isinstance(probe, dict):
                evidence["probes"].append(probe_tcp(probe.get("host", "127.0.0.1"), probe.get("port", ""), timeout=probe_timeout))

        if "save" in selected_operations and "save" in commands:
            tar_path_obj = Path(str(plan.get("tar_path") or ""))
            tar_path_obj.parent.mkdir(parents=True, exist_ok=True)
            save_step = run_command(commands["save"], timeout=command_timeout)
            evidence["steps"].append(save_step)
            if tar_path_obj.is_file():
                digest = sha256_file(tar_path_obj)
                evidence["summary"]["tar_sha256"] = digest
                evidence["artifacts"]["image_tar"] = {
                    "path": tar_path_obj.as_posix(),
                    "size": tar_path_obj.stat().st_size,
                    "sha256": digest,
                }
            else:
                issues.append(f"tar not generated: {tar_path_obj}")
    finally:
        if "stop" in selected_operations and container_started:
            evidence["steps"].append(run_command(commands.get("stop", ["docker", "stop", container_name]), timeout=command_timeout))
            evidence["steps"].append(run_command(commands.get("rm", ["docker", "rm", container_name]), timeout=command_timeout))
        elif "stop" in selected_operations and run_attempted and container_name:
            evidence["steps"].append(run_command(["docker", "rm", "-f", container_name], timeout=command_timeout))

    if not evidence["summary"]["platform"]:
        for step in evidence["steps"]:
            if step.get("id") == "docker-image-inspect":
                platform = platform_from_inspect_output(step.get("stdout", ""))
                if platform:
                    evidence["summary"]["platform"] = platform
                    break
    if evidence["summary"]["platform"] and evidence["summary"]["platform"] != TARGET_PLATFORM:
        issues.append(f"platform mismatch: {evidence['summary']['platform']} != {TARGET_PLATFORM}")
    for step in evidence["steps"]:
        if step.get("status") == "fail":
            issues.append(f"{step.get('id')}: exit_code={step.get('exit_code')}")
    for probe in evidence["probes"]:
        if probe.get("status") == "fail":
            target = probe.get("url") or probe.get("target") or ""
            issues.append(f"probe failed: {target}")

    run_requested = "run" in selected_operations
    run_ok = not run_requested or any(step.get("id") == "docker-run" and step.get("status") == "pass" for step in evidence["steps"])
    probe_ok = all(item.get("status") in {"pass", "skip"} for item in evidence["probes"])
    evidence["summary"]["run_verified"] = run_ok and probe_ok and not issues
    evidence["summary"]["issues"] = dedupe_text(issues)
    evidence["summary"]["status"] = "pass" if not evidence["summary"]["issues"] else "fail"
    write_evidence(output, evidence)
    return evidence


def compact_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    summary = evidence.get("summary", {})
    return {
        "schema_version": "cloversec.ctf.docker_evidence.compact.v1",
        "case_id": evidence.get("case_id", ""),
        "status": summary.get("status", ""),
        "validation_level": summary.get("validation_level", ""),
        "platform": summary.get("platform", ""),
        "run_verified": summary.get("run_verified", False),
        "tar_sha256": summary.get("tar_sha256", ""),
        "logs_path": summary.get("logs_path", ""),
        "evidence_path": evidence.get("evidence_path", ""),
        "report_path": evidence.get("report_path", ""),
        "steps": [
            {
                "id": step.get("id", ""),
                "status": step.get("status", ""),
                "exit_code": step.get("exit_code", ""),
                "message": step.get("message", ""),
            }
            for step in evidence.get("steps", [])
        ],
        "probes": evidence.get("probes", []),
        "issues": summary.get("issues", []),
    }


def write_evidence(output_dir: Path, evidence: dict[str, Any]) -> None:
    evidence_path = output_dir / "docker_evidence.json"
    report_path = output_dir / "docker_evidence.md"
    sync_evidence_summary(evidence)
    evidence["evidence_path"] = evidence_path.as_posix()
    evidence["report_path"] = report_path.as_posix()
    sync_evidence_summary(evidence)
    evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report_path.write_text(render_docker_report(evidence), encoding="utf-8")


def sync_evidence_summary(evidence: dict[str, Any]) -> None:
    summary = evidence.get("summary") if isinstance(evidence.get("summary"), dict) else {}
    plan = evidence.get("plan") if isinstance(evidence.get("plan"), dict) else {}
    for key in ["status", "validation_level", "platform", "run_verified", "tar_sha256", "logs_path", "issues"]:
        if key == "run_verified":
            default: Any = False
        elif key == "issues":
            default = []
        else:
            default = ""
        evidence[key] = summary.get(key, default)
    evidence["operations"] = plan.get("operations", [])
    evidence["target_platform"] = plan.get("target_platform", TARGET_PLATFORM)
    evidence["port_rewrites"] = plan.get("port_rewrites", [])


def render_docker_report(evidence: dict[str, Any]) -> str:
    summary = evidence.get("summary", {})
    lines = [
        "# Docker 执行证据",
        "",
        f"- 题目 ID：{evidence.get('case_id', '')}",
        f"- 状态：{summary.get('status', '')}",
        f"- 验证等级：{summary.get('validation_level', '')}",
        f"- 平台：{summary.get('platform', '')}",
        f"- run_verified：{summary.get('run_verified', False)}",
        f"- tar SHA256：{summary.get('tar_sha256', '')}",
        f"- 日志路径：{summary.get('logs_path', '')}",
        "",
        "| 步骤 | 状态 | 退出码 | 说明 |",
        "|---|---|---|---|",
    ]
    for step in evidence.get("steps", []):
        lines.append(
            "| "
            + " | ".join(
                escape_table(value)
                for value in [step.get("id", ""), step.get("status", ""), step.get("exit_code", ""), step.get("message", "")]
            )
            + " |"
        )
    if evidence.get("probes"):
        lines.extend(["", "## 端口探测", ""])
        for item in evidence["probes"]:
            lines.append(f"- {item.get('url', '')}：{item.get('status', '')} {item.get('message', '')}")
    if summary.get("issues"):
        lines.extend(["", "## 问题", ""])
        lines.extend(f"- {issue}" for issue in summary["issues"])
    return "\n".join(lines) + "\n"


def run_command(args: list[str], *, timeout: int) -> dict[str, Any]:
    started = time.time()
    command_id = command_id_for(args)
    try:
        result = subprocess.run(args, check=False, capture_output=True, text=True, timeout=timeout)
        status = "pass" if result.returncode == 0 else "fail"
        return {
            "id": command_id,
            "status": status,
            "command": args,
            "exit_code": result.returncode,
            "stdout": truncate(result.stdout),
            "stderr": truncate(result.stderr),
            "duration_seconds": round(time.time() - started, 3),
            "message": "ok" if status == "pass" else truncate(result.stderr or result.stdout),
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
            "stdout": truncate(exc.stdout or ""),
            "stderr": truncate(exc.stderr or ""),
            "duration_seconds": round(time.time() - started, 3),
            "message": f"timeout after {timeout}s",
        }


def command_id_for(args: list[str]) -> str:
    if args[:2] == ["docker", "build"]:
        return "docker-build"
    if args[:2] == ["docker", "load"]:
        return "docker-load"
    if args[:3] == ["docker", "image", "inspect"]:
        return "docker-image-inspect"
    if args[:2] == ["docker", "run"]:
        return "docker-run"
    if args[:2] == ["docker", "logs"]:
        return "docker-logs"
    if args[:2] == ["docker", "stop"]:
        return "docker-stop"
    if args[:2] == ["docker", "rm"]:
        return "docker-rm"
    if args[:2] == ["docker", "save"]:
        return "docker-save"
    return "-".join(args[:3])


def normalize_operations(operations: list[str]) -> list[str]:
    allowed = set(DEFAULT_OPERATIONS)
    output = []
    for item in operations:
        value = str(item or "").strip().lower()
        mapped = OPERATION_ALIASES.get(value, [value])
        for operation in mapped:
            if operation in allowed and operation not in output:
                output.append(operation)
    return output


def normalize_validation_level(value: str) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    return text if text in VALIDATION_LEVELS else "custom"


def resolve_dockerfile_path(project_dir: Path | None, dockerfile: Path) -> Path:
    if dockerfile.is_absolute() or not project_dir:
        return dockerfile
    dockerfile_text = dockerfile.as_posix()
    project_text = project_dir.as_posix().rstrip("/")
    if dockerfile.exists():
        return dockerfile
    if dockerfile_text == "Dockerfile":
        return project_dir / dockerfile
    if project_text and (dockerfile_text == project_text or dockerfile_text.startswith(project_text + "/")):
        return dockerfile
    joined = project_dir / dockerfile
    if joined.exists():
        return joined
    if dockerfile.parent == Path("."):
        return joined
    return dockerfile


def infer_case_id(*, case: dict[str, Any], project_dir: Path | None, image_name: str) -> str:
    for value in [
        case.get("case_id"),
        case.get("id"),
        case.get("记录ID"),
        (case.get("metadata") if isinstance(case.get("metadata"), dict) else {}).get("名称"),
        image_name.rsplit("/", 1)[-1].split(":", 1)[0] if image_name else "",
        project_dir.name if project_dir else "",
    ]:
        text = str(value or "").strip()
        if text:
            return safe_token(text)
    return "case"


def operations_for_validation_level(level: str, *, tar_path: str = "") -> list[str]:
    normalized = normalize_validation_level(level)
    if normalized == "static_only":
        return []
    if normalized == "inspect_only":
        return ["load", "inspect"] if str(tar_path or "").strip() else ["inspect"]
    if normalized == "build_only":
        return ["build", "inspect"]
    if normalized in {"run_probe", "solve_verify"}:
        return ["build", "inspect", "run", "logs", "stop"]
    return list(DEFAULT_OPERATIONS)


def normalize_ports(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    output = []
    for item in value:
        text = str(item or "").strip()
        if text:
            output.append(text)
    return output


def normalize_probe_protocol(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"tcp", "socket", "nc", "netcat"}:
        return "tcp"
    if text in {"http", "https", "web"}:
        return "http"
    return "http"


def rewrite_ports_to_available(plan: dict[str, Any]) -> None:
    ports = [str(item) for item in plan.get("ports", []) if str(item).strip()]
    rewritten = []
    rewrites = []
    for mapping in ports:
        host_port, container_port = split_port_mapping(mapping)
        if not container_port:
            rewritten.append(mapping)
            continue
        selected_host = host_port
        if not selected_host or not is_host_port_available(selected_host):
            selected_host = find_available_port()
            if selected_host:
                rewrites.append({"from": mapping, "to": f"{selected_host}:{container_port}", "reason": "host_port_unavailable"})
        rewritten.append(f"{selected_host}:{container_port}" if selected_host else mapping)
    if not rewrites:
        return
    plan["ports"] = rewritten
    plan["port_rewrites"] = rewrites
    if plan.get("probe_protocol") == "tcp":
        plan["tcp_probes"] = tcp_probes_from_ports(rewritten)
        plan["probe_urls"] = []
    else:
        plan["probe_urls"] = probe_urls_from_ports(rewritten)
    commands = plan.get("commands") if isinstance(plan.get("commands"), dict) else {}
    run_args = commands.get("run")
    if isinstance(run_args, list):
        commands["run"] = rewrite_run_command_ports(run_args, rewritten)


def rewrite_run_command_ports(args: list[str], ports: list[str]) -> list[str]:
    output: list[str] = []
    index = 0
    while index < len(args):
        if args[index] == "-p" and index + 1 < len(args):
            index += 2
            continue
        output.append(args[index])
        index += 1
    insert_at = docker_run_image_index(output)
    port_args: list[str] = []
    for mapping in ports:
        port_args.extend(["-p", mapping])
    return output[:insert_at] + port_args + output[insert_at:]


def docker_run_image_index(args: list[str]) -> int:
    option_value_flags = {"--name", "-e", "--env", "-v", "--volume", "-w", "--workdir", "--network", "--hostname", "--user", "-u"}
    index = 2 if args[:2] == ["docker", "run"] else 0
    while index < len(args):
        value = args[index]
        if value == "--":
            return min(index + 1, len(args))
        if value in option_value_flags:
            index += 2
            continue
        if value.startswith("--") and "=" in value:
            index += 1
            continue
        if value.startswith("-"):
            index += 1
            continue
        return index
    return len(args)


def split_port_mapping(mapping: str) -> tuple[str, str]:
    value = str(mapping or "").strip()
    if not value:
        return "", ""
    clean = value.split("/", 1)[0]
    if ":" not in clean:
        return "", clean if clean.isdigit() else ""
    host, container = clean.rsplit(":", 1)
    if ":" in host:
        host = host.rsplit(":", 1)[1]
    return (host if host.isdigit() else "", container if container.isdigit() else "")


def is_host_port_available(port: str) -> bool:
    try:
        port_int = int(port)
    except ValueError:
        return False
    if port_int <= 0 or port_int > 65535:
        return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port_int))
        except OSError:
            return False
    return True


def find_available_port() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return str(sock.getsockname()[1])


def probe_urls_from_ports(ports: list[str]) -> list[str]:
    urls = []
    for mapping in ports:
        host_port = host_port_from_mapping(mapping)
        if host_port:
            urls.append(f"http://127.0.0.1:{host_port}/")
    return urls


def tcp_probes_from_ports(ports: list[str]) -> list[dict[str, Any]]:
    probes = []
    for mapping in ports:
        host_port = host_port_from_mapping(mapping)
        if host_port:
            probes.append({"protocol": "tcp", "host": "127.0.0.1", "port": host_port, "target": f"tcp://127.0.0.1:{host_port}"})
    return probes


def host_port_from_mapping(mapping: str) -> str:
    value = mapping.strip()
    if not value or ":" not in value:
        return ""
    host_part = value.rsplit(":", 1)[0]
    if ":" in host_part:
        host_part = host_part.rsplit(":", 1)[1]
    host_part = host_part.split("/", 1)[0]
    return host_part if host_part.isdigit() else ""


def probe_url(url: str, *, timeout: float) -> dict[str, Any]:
    if not str(url or "").strip():
        return {"url": "", "status": "skip", "message": "empty probe url"}
    try:
        response = http.http_get(url, timeout=int(max(timeout, 1)), read_limit=4096, retries=0, backoff=0)
        status = int(response.get("status") or 0)
        return {
            "url": url,
            "status": "pass" if status < 400 else "fail",
            "http_status": status,
            "message": f"HTTP {status}",
        }
    except Exception as exc:  # noqa: BLE001
        return {"url": url, "status": "fail", "message": str(exc)}


def probe_tcp(host: Any, port: Any, *, timeout: float) -> dict[str, Any]:
    host_text = str(host or "127.0.0.1").strip() or "127.0.0.1"
    port_text = str(port or "").strip()
    target = f"tcp://{host_text}:{port_text}"
    if not port_text.isdigit():
        return {"protocol": "tcp", "target": target, "status": "skip", "message": "empty tcp port"}
    try:
        with socket.create_connection((host_text, int(port_text)), timeout=max(float(timeout), 0.1)):
            return {"protocol": "tcp", "target": target, "status": "pass", "message": "tcp connect ok"}
    except Exception as exc:  # noqa: BLE001
        return {"protocol": "tcp", "target": target, "status": "fail", "message": str(exc)}


def authorization_errors(
    *,
    operations: set[str],
    case_id: str,
    authorization_workdir: str | Path = "",
    authorization_path: str | Path = "",
) -> list[str]:
    required = sorted({OPERATION_AUTH_ACTIONS[operation] for operation in operations if operation in OPERATION_AUTH_ACTIONS})
    if not required:
        return []
    authorizations = load_authorizations(authorization_workdir=authorization_workdir, authorization_path=authorization_path)
    missing = [action for action in required if not has_valid_authorization(authorizations, action=action, case_id=case_id)]
    if not missing:
        return []
    return [i18n.text("docker.missing_batch_authorization", actions=", ".join(missing))]


def load_authorizations(*, authorization_workdir: str | Path = "", authorization_path: str | Path = "") -> list[dict[str, Any]]:
    paths: list[Path] = []
    if authorization_path:
        paths.append(Path(authorization_path))
    if authorization_workdir:
        auth_dir = Path(authorization_workdir) / "authorizations"
        if auth_dir.is_dir():
            paths.extend(sorted(auth_dir.glob("*.json")))
    authorizations = []
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            payload.setdefault("authorization_path", path.as_posix())
            authorizations.append(payload)
    return authorizations


def has_valid_authorization(authorizations: list[dict[str, Any]], *, action: str, case_id: str) -> bool:
    now = datetime.now(timezone.utc)
    for payload in authorizations:
        if payload.get("action") not in {action, "docker_all"}:
            continue
        if not authorization_covers_case(payload, case_id):
            continue
        expires_at = str(payload.get("expires_at") or "")
        try:
            expires = datetime.fromisoformat(expires_at)
        except ValueError:
            continue
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires >= now:
            return True
    return False


def authorization_covers_case(payload: dict[str, Any], case_id: str) -> bool:
    case_ids = payload.get("case_ids")
    if not case_ids:
        return True
    return str(case_id or "") in {str(item) for item in case_ids}


def platform_from_inspect_output(output: str) -> str:
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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_token(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    text = re.sub(r"-+", "-", text).strip(".-")
    return (text or "case")[:48]


def truncate(value: Any, limit: int = 4000) -> str:
    text = value.decode() if isinstance(value, bytes) else str(value or "")
    return text if len(text) <= limit else text[-limit:]


def dedupe_text(items: list[str]) -> list[str]:
    output = []
    seen = set()
    for item in items:
        text = str(item or "").strip()
        if text and text not in seen:
            seen.add(text)
            output.append(text)
    return output


def escape_table(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF controlled Docker execution")
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("plan", help="create a Docker execution plan")
    plan_parser.add_argument("--case-json")
    plan_parser.add_argument("--project-dir", default="")
    plan_parser.add_argument("--image-name", default="")
    plan_parser.add_argument("--tar-path", default="")
    plan_parser.add_argument("--port", action="append", default=[])
    plan_parser.add_argument("--dockerfile", default="")
    plan_parser.add_argument("--container-command", default="")
    plan_parser.add_argument("--operation", action="append", default=[])
    plan_parser.add_argument("--validation-level", choices=VALIDATION_LEVELS, default="")
    plan_parser.add_argument("--container-inference", default="")
    plan_parser.add_argument("--output", required=True)

    execute_parser = subparsers.add_parser("execute", help="run controlled Docker operations and write evidence")
    execute_parser.add_argument("--case-json")
    execute_parser.add_argument("--output-dir", required=True)
    execute_parser.add_argument("--project-dir", default="")
    execute_parser.add_argument("--image-name", default="")
    execute_parser.add_argument("--tar-path", default="")
    execute_parser.add_argument("--port", action="append", default=[])
    execute_parser.add_argument("--dockerfile", default="")
    execute_parser.add_argument("--container-command", default="")
    execute_parser.add_argument("--operation", action="append", default=[])
    execute_parser.add_argument("--validation-level", choices=VALIDATION_LEVELS, default="")
    execute_parser.add_argument("--container-inference", default="")
    execute_parser.add_argument("--probe-url", action="append", default=[])
    execute_parser.add_argument("--startup-wait", type=float, default=2.0)
    execute_parser.add_argument("--command-timeout", type=int, default=60)
    execute_parser.add_argument("--probe-timeout", type=float, default=3.0)
    execute_parser.add_argument("--authorization-workdir", default="")
    execute_parser.add_argument("--authorization-path", default="")

    args = parser.parse_args(argv)
    case = json.loads(Path(args.case_json).read_text(encoding="utf-8")) if getattr(args, "case_json", None) else {}
    container_inference = (
        json.loads(Path(args.container_inference).read_text(encoding="utf-8"))
        if getattr(args, "container_inference", "")
        else {}
    )
    if args.command == "plan":
        payload = create_docker_plan(
            case=case,
            project_dir=args.project_dir,
            image_name=args.image_name,
            tar_path=args.tar_path,
            ports=args.port,
            dockerfile=args.dockerfile,
            container_command=args.container_command,
            operations=args.operation or None,
            validation_level=args.validation_level,
            container_inference=container_inference,
        )
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.output}")
        return 0
    if args.command == "execute":
        evidence = execute_docker_workflow(
            case=case,
            output_dir=args.output_dir,
            project_dir=args.project_dir,
            image_name=args.image_name,
            tar_path=args.tar_path,
            ports=args.port,
            dockerfile=args.dockerfile,
            container_command=args.container_command,
            operations=args.operation or None,
            validation_level=args.validation_level,
            container_inference=container_inference,
            probe_urls=args.probe_url,
            startup_wait=args.startup_wait,
            command_timeout=args.command_timeout,
            probe_timeout=args.probe_timeout,
            authorization_workdir=args.authorization_workdir,
            authorization_path=args.authorization_path,
        )
        print(f"wrote {evidence['evidence_path']}")
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
