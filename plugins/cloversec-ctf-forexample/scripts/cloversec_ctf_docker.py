#!/usr/bin/env python3
"""Controlled Docker execution helpers for CloverSec CTF workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen


TARGET_PLATFORM = "linux/amd64"
DEFAULT_OPERATIONS = ["build", "load", "inspect", "run", "logs", "stop", "save"]
VERSION = "0.3.5"
VALIDATION_LEVELS = ["static_only", "inspect_only", "build_only", "run_probe", "solve_verify"]


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
    dockerfile_for_command = selected_dockerfile
    if selected_project_dir and not selected_dockerfile.is_absolute():
        dockerfile_for_command = selected_project_dir / selected_dockerfile
    selected_command = str(container_command or environment.get("start_command") or inferred_runtime.get("container_command") or "").strip()
    raw_operations = operations if operations is not None else operations_for_validation_level(selected_level, tar_path=selected_tar)
    selected_operations = [] if selected_level == "static_only" and raw_operations == [] else normalize_operations(raw_operations)
    container_name = f"cloversec-docker-{safe_token(str(case.get('case_id') or 'case'))}-{int(time.time())}"

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
    if selected_operations and not selected_image:
        issues.append("image_name is required")
    if "build" in selected_operations and not selected_project_dir_text:
        issues.append("project_dir is required for docker build")
    if "save" in selected_operations and not selected_tar:
        issues.append("tar_path is required for docker save")

    return {
        "schema_version": "cloversec.ctf.docker_plan.v1",
        "version": VERSION,
        "case_id": str(case.get("case_id") or ""),
        "validation_level": selected_level,
        "target_platform": TARGET_PLATFORM,
        "image_name": selected_image,
        "tar_path": selected_tar,
        "project_dir": selected_project_dir.as_posix() if selected_project_dir else "",
        "dockerfile": dockerfile_for_command.as_posix(),
        "ports": selected_ports,
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
    container_name = str(plan.get("container_name") or "")
    selected_operations = set(plan.get("operations", []))

    if issues:
        evidence["summary"]["issues"] = issues
        write_evidence(output, evidence)
        return evidence

    if not selected_operations:
        evidence["summary"]["status"] = "skip"
        evidence["summary"]["run_verified"] = False
        evidence["summary"]["issues"] = []
        evidence["summary"]["message"] = "no Docker operations selected"
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

        for url in list(probe_urls or []) + probe_urls_from_ports(plan.get("ports", [])):
            evidence["probes"].append(probe_url(url, timeout=probe_timeout))

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
            issues.append(f"probe failed: {probe.get('url')}")

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
    evidence["evidence_path"] = evidence_path.as_posix()
    evidence["report_path"] = report_path.as_posix()
    evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report_path.write_text(render_docker_report(evidence), encoding="utf-8")


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
        if value in allowed and value not in output:
            output.append(value)
    return output or list(DEFAULT_OPERATIONS)


def normalize_validation_level(value: str) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    return text if text in VALIDATION_LEVELS else "custom"


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


def probe_urls_from_ports(ports: list[str]) -> list[str]:
    urls = []
    for mapping in ports:
        host_port = host_port_from_mapping(mapping)
        if host_port:
            urls.append(f"http://127.0.0.1:{host_port}/")
    return urls


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
        with urlopen(url, timeout=timeout) as response:
            return {"url": url, "status": "pass", "http_status": response.status, "message": f"HTTP {response.status}"}
    except URLError as exc:
        return {"url": url, "status": "fail", "message": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"url": url, "status": "fail", "message": str(exc)}


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
        )
        print(f"wrote {evidence['evidence_path']}")
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
