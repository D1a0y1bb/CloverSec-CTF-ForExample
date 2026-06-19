#!/usr/bin/env python3
"""Quality review helpers for CloverSec CTF workflows."""

from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import cloversec_ctf_data as data
import cloversec_ctf_http as http


TARGET_PLATFORM = "linux/amd64"


def create_quality_review(
    case: dict[str, Any],
    *,
    archive_dir: str | Path | None = None,
    docker_execution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    flag = case.get("flag") if isinstance(case.get("flag"), dict) else {}
    docker_artifacts = case.get("docker_artifacts") if isinstance(case.get("docker_artifacts"), dict) else {}
    writeup = case.get("writeup") if isinstance(case.get("writeup"), dict) else {}

    validation_errors = data.validate_case(case)
    _add_check(
        checks,
        "data-model",
        "数据模型与 xlsx 必填字段",
        "pass" if not validation_errors else "fail",
        "字段完整" if not validation_errors else "; ".join(validation_errors),
    )

    _add_check(
        checks,
        "full-flag",
        "完整 Flag",
        "pass" if _text(flag.get("value")) else "fail",
        "Flag 已进入结构化字段" if _text(flag.get("value")) else "flag.value 为空",
    )

    manual_paths = _manual_paths(writeup)
    if manual_paths:
        _check_paths(checks, "manual-files", "手册文件", manual_paths, archive_dir=archive_dir)
    else:
        _add_check(checks, "manual-files", "手册文件", "skip", "writeup 中没有手册路径")

    attachments = [item.get("path") or item.get("local_path") for item in case.get("attachments", []) if isinstance(item, dict)]
    if attachments:
        _check_paths(checks, "attachment-files", "附件文件", attachments, archive_dir=archive_dir)
    else:
        _add_check(checks, "attachment-files", "附件文件", "skip", "attachments 为空")

    screenshots = _screenshot_paths(case)
    if screenshots:
        _check_paths(checks, "screenshot-files", "截图文件", screenshots, archive_dir=archive_dir)
    else:
        _add_check(checks, "screenshot-files", "截图文件", "fail", "archive.screenshots 为空，缺少截图")

    source_files = [item.get("path") or item.get("local_path") for item in case.get("source_files", []) if isinstance(item, dict)]
    if source_files:
        _check_paths(checks, "source-files", "源码文件", source_files, archive_dir=archive_dir)
    else:
        _add_check(checks, "source-files", "源码文件", "skip", "source_files 为空")

    tar_path = docker_artifacts.get("tar_path")
    if tar_path:
        _check_paths(checks, "image-tar", "镜像 tar", [tar_path], archive_dir=archive_dir)
    else:
        _add_check(checks, "image-tar", "镜像 tar", "skip", "docker_artifacts.tar_path 为空")

    platform = docker_artifacts.get("platform")
    if docker_execution and docker_execution.get("summary", {}).get("platform"):
        platform = docker_execution["summary"]["platform"]
    if platform:
        _add_check(
            checks,
            "image-platform",
            "镜像平台",
            "pass" if platform == TARGET_PLATFORM else "fail",
            f"platform={platform}",
        )
    else:
        _add_check(checks, "image-platform", "镜像平台", "skip", "docker_artifacts.platform 为空")

    if docker_execution:
        _add_docker_execution_checks(checks, docker_execution)
    elif docker_artifacts.get("run_verified") is True:
        _add_check(checks, "docker-run", "镜像启动验证", "pass", "docker_artifacts.run_verified=true")
    else:
        _add_check(checks, "docker-run", "镜像启动验证", "skip", "没有真实 Docker run 验证记录")

    if writeup.get("solve_verified") is True:
        _add_check(checks, "solve-proof", "手册解题验证", "pass", "writeup.solve_verified=true")
    else:
        _add_check(checks, "solve-proof", "手册解题验证", "skip", "没有按手册解出 Flag 的验证记录")

    if _text(metadata.get("名称")) and _text(writeup.get("title")) and metadata.get("名称") != writeup.get("title"):
        _add_check(checks, "title-consistency", "题名一致性", "fail", "metadata.名称 与 writeup.title 不一致")
    else:
        _add_check(checks, "title-consistency", "题名一致性", "pass", "未发现题名冲突")

    status = _overall_status(checks)
    issues = [f"{item['name']}: {item['message']}" for item in checks if item["status"] != "pass"]
    xlsx_fields = {
        "验证状态": status,
        "是否通过": "是" if status == "通过" else "否",
        "问题": "；".join(issues),
        "手册状态": _manual_status(manual_paths, writeup),
    }
    docker_status = docker_status_breakdown(checks, docker_execution, writeup)
    payload = {
        "case_id": str(case.get("case_id") or ""),
        "checks": checks,
        "summary": {
            "pass": sum(1 for item in checks if item["status"] == "pass"),
            "fail": sum(1 for item in checks if item["status"] == "fail"),
            "skip": sum(1 for item in checks if item["status"] == "skip"),
            "status": status,
            "docker_status": docker_status,
        },
        "xlsx_fields": xlsx_fields,
    }
    if docker_execution:
        payload["docker_execution"] = copy.deepcopy(docker_execution)
    return payload


def apply_review_outputs(case: dict[str, Any], review: dict[str, Any]) -> dict[str, Any]:
    updated = copy.deepcopy(case)
    updated.setdefault("metadata", {})
    updated["review"] = copy.deepcopy(review)
    if review.get("docker_execution"):
        updated.setdefault("docker_artifacts", {})
        execution = review["docker_execution"]
        updated["docker_artifacts"]["docker_execution"] = copy.deepcopy(execution)
        if execution.get("summary", {}).get("run_verified") is True:
            updated["docker_artifacts"]["run_verified"] = True
        if execution.get("summary", {}).get("platform"):
            updated["docker_artifacts"]["platform"] = execution["summary"]["platform"]
    for key, value in review.get("xlsx_fields", {}).items():
        updated["metadata"][key] = value
    return updated


def execute_docker_review(
    case: dict[str, Any],
    output_dir: str | Path,
    *,
    load_image: bool = True,
    startup_wait: float = 2.0,
    command_timeout: int = 30,
    probe_timeout: float = 3.0,
    probe_urls: list[str] | None = None,
    start_command: str = "",
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    docker_artifacts = case.get("docker_artifacts") if isinstance(case.get("docker_artifacts"), dict) else {}
    environment = case.get("environment") if isinstance(case.get("environment"), dict) else {}
    image_name = str(docker_artifacts.get("image_name") or "").strip()
    tar_path = str(docker_artifacts.get("tar_path") or "").strip()
    ports = [str(item) for item in docker_artifacts.get("ports", []) if str(item).strip()]
    if not ports and isinstance(environment.get("port_mappings"), list):
        ports = [str(item) for item in environment["port_mappings"] if str(item).strip()]

    container_name = f"cloversec-review-{_safe_token(str(case.get('case_id') or 'case'))}-{int(time.time())}"
    evidence: dict[str, Any] = {
        "case_id": str(case.get("case_id") or ""),
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "image_name": image_name,
        "tar_path": tar_path,
        "target_platform": TARGET_PLATFORM,
        "container_name": container_name,
        "steps": [],
        "probes": [],
        "summary": {
            "status": "fail",
            "run_verified": False,
            "platform": "",
            "issues": [],
        },
    }

    issues: list[str] = []
    container_started = False
    if not image_name:
        issues.append("docker_artifacts.image_name 为空")
        evidence["summary"]["issues"] = issues
        return evidence

    try:
        if load_image and tar_path:
            tar = Path(tar_path)
            if tar.is_file():
                evidence["steps"].append(_run_command(["docker", "load", "-i", tar.as_posix()], timeout=command_timeout))
            else:
                evidence["steps"].append({"id": "docker-load", "status": "skip", "message": f"tar 不存在：{tar_path}"})

        inspect = _run_command(["docker", "image", "inspect", image_name], timeout=command_timeout)
        evidence["steps"].append(inspect)
        platform = _platform_from_inspect_output(inspect.get("stdout", ""))
        if platform:
            evidence["summary"]["platform"] = platform

        run_args = ["docker", "run", "-d", "--name", container_name]
        for mapping in ports:
            run_args.extend(["-p", mapping])
        run_args.append(image_name)
        actual_start_command = start_command or str(environment.get("start_command") or "").strip()
        if actual_start_command:
            run_args.extend(actual_start_command.split())
        run = _run_command(run_args, timeout=command_timeout)
        evidence["steps"].append(run)
        container_started = run.get("status") == "pass"

        if container_started:
            time.sleep(max(startup_wait, 0))
            targets = list(probe_urls or []) + _probe_urls_from_ports(ports)
            if targets:
                for url in targets:
                    evidence["probes"].append(_probe_url(url, timeout=probe_timeout))
            else:
                evidence["probes"].append({"url": "", "status": "skip", "message": "没有可探测的 host 端口或 probe URL"})
            logs = _run_command(["docker", "logs", container_name], timeout=command_timeout)
            logs_path = output / "docker_logs.txt"
            logs_path.write_text(str(logs.get("stdout") or "") + str(logs.get("stderr") or ""), encoding="utf-8")
            logs["path"] = logs_path.as_posix()
            evidence["steps"].append(logs)
    finally:
        if container_started:
            evidence["steps"].append(_run_command(["docker", "stop", container_name], timeout=command_timeout))
            evidence["steps"].append(_run_command(["docker", "rm", container_name], timeout=command_timeout))

    for step in evidence["steps"]:
        if step.get("status") == "fail":
            issues.append(f"{step.get('id')}: exit_code={step.get('exit_code')}")
    for probe in evidence["probes"]:
        if probe.get("status") == "fail":
            issues.append(f"probe failed: {probe.get('url')}")
    if evidence["summary"].get("platform") and evidence["summary"]["platform"] != TARGET_PLATFORM:
        issues.append(f"镜像平台不是 {TARGET_PLATFORM}: {evidence['summary']['platform']}")

    run_ok = any(step.get("id") == "docker-run" and step.get("status") == "pass" for step in evidence["steps"])
    probe_ok = not evidence["probes"] or all(item.get("status") in {"pass", "skip"} for item in evidence["probes"])
    evidence["summary"]["run_verified"] = run_ok and probe_ok and not issues
    evidence["summary"]["status"] = "pass" if evidence["summary"]["run_verified"] else "fail"
    evidence["summary"]["issues"] = issues
    return evidence


def render_review_markdown(review: dict[str, Any]) -> str:
    lines = [
        "# 质量检查报告",
        "",
        f"- 题目 ID：{review.get('case_id', '')}",
        f"- 验证状态：{review.get('summary', {}).get('status', '')}",
        f"- 通过：{review.get('summary', {}).get('pass', 0)}",
        f"- 失败：{review.get('summary', {}).get('fail', 0)}",
        f"- 未执行：{review.get('summary', {}).get('skip', 0)}",
        "",
        "| 检查项 | 状态 | 说明 |",
        "|---|---|---|",
    ]
    for item in review.get("checks", []):
        lines.append(f"| {item.get('name', '')} | {item.get('status', '')} | {_escape_table(item.get('message', ''))} |")
    lines.extend(["", "## xlsx 字段建议", ""])
    for key, value in review.get("xlsx_fields", {}).items():
        lines.append(f"- {key}：{value}")
    if review.get("docker_execution"):
        lines.extend(["", "## Docker 执行证据", ""])
        summary = review["docker_execution"].get("summary", {})
        lines.append(f"- 状态：{summary.get('status', '')}")
        lines.append(f"- 平台：{summary.get('platform', '')}")
        lines.append(f"- 容器名：{review['docker_execution'].get('container_name', '')}")
        for item in review["docker_execution"].get("probes", []):
            lines.append(f"- Probe：{item.get('url', '')} {item.get('status', '')} {item.get('message', '')}")
    docker_status = review.get("summary", {}).get("docker_status") if isinstance(review.get("summary", {}).get("docker_status"), dict) else {}
    if docker_status:
        lines.extend(["", "## Docker 分层状态", ""])
        lines.append(f"- 契约：{docker_status.get('contract_status', '')}")
        lines.append(f"- 镜像构建/导入：{docker_status.get('image_build_status', '')}")
        lines.append(f"- 服务启动：{docker_status.get('service_start_status', '')}")
        lines.append(f"- 题目可解：{docker_status.get('solve_status', '')}")
    return "\n".join(lines) + "\n"


def _add_docker_execution_checks(checks: list[dict[str, str]], evidence: dict[str, Any]) -> None:
    steps = evidence.get("steps", []) if isinstance(evidence.get("steps"), list) else []
    by_id = {item.get("id"): item for item in steps if isinstance(item, dict)}
    if "docker-load" in by_id:
        step = by_id["docker-load"]
        _add_check(checks, "docker-load", "镜像 tar 导入", step.get("status", "fail"), step.get("message", ""))
    inspect = by_id.get("docker-image-inspect")
    if inspect:
        _add_check(checks, "docker-inspect", "镜像 inspect", inspect.get("status", "fail"), inspect.get("message", ""))
    run = by_id.get("docker-run")
    if run:
        _add_check(checks, "docker-run", "镜像启动验证", run.get("status", "fail"), run.get("message", ""))
    probes = evidence.get("probes", []) if isinstance(evidence.get("probes"), list) else []
    if probes:
        failed = [item for item in probes if item.get("status") == "fail"]
        skipped = [item for item in probes if item.get("status") == "skip"]
        if failed:
            _add_check(checks, "docker-port-probe", "端口探测", "fail", "; ".join(str(item.get("message", "")) for item in failed))
        elif len(skipped) == len(probes):
            _add_check(checks, "docker-port-probe", "端口探测", "skip", "; ".join(str(item.get("message", "")) for item in skipped))
        else:
            _add_check(checks, "docker-port-probe", "端口探测", "pass", "端口探测通过")
    if evidence.get("summary", {}).get("issues"):
        _add_check(checks, "docker-execution-summary", "Docker 执行汇总", "fail", "; ".join(evidence["summary"]["issues"]))
    elif evidence.get("summary", {}).get("status") == "pass":
        _add_check(checks, "docker-execution-summary", "Docker 执行汇总", "pass", "受控 Docker 执行通过")


def docker_status_breakdown(
    checks: list[dict[str, str]],
    docker_execution: dict[str, Any] | None,
    writeup: dict[str, Any],
) -> dict[str, str]:
    by_id = {item["id"]: item for item in checks}
    contract_status = "通过" if by_id.get("data-model", {}).get("status") == "pass" and by_id.get("image-platform", {}).get("status") in {"pass", "skip"} else "未通过"
    if docker_execution:
        load_status = by_id.get("docker-load", by_id.get("docker-inspect", {})).get("status", "")
        inspect_status = by_id.get("docker-inspect", {}).get("status", "")
        run_status = by_id.get("docker-run", {}).get("status", "")
        probe_status = by_id.get("docker-port-probe", {}).get("status", "")
        image_build_status = "通过" if inspect_status == "pass" and load_status in {"pass", "skip", ""} else "未通过"
        service_start_status = "通过" if run_status == "pass" and probe_status in {"pass", "skip", ""} else "未通过"
    else:
        image_build_status = "未执行"
        service_start_status = "未执行"
    solve_status = "通过" if writeup.get("solve_verified") is True else "未执行"
    return {
        "contract_status": contract_status,
        "image_build_status": image_build_status,
        "service_start_status": service_start_status,
        "solve_status": solve_status,
    }


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
    return "-".join(args[:3])


def _probe_urls_from_ports(ports: list[str]) -> list[str]:
    urls = []
    for mapping in ports:
        host_port = _host_port(mapping)
        if host_port:
            urls.append(f"http://127.0.0.1:{host_port}/")
    return urls


def _host_port(mapping: str) -> str:
    value = mapping.strip()
    if not value or ":" not in value:
        return ""
    host_part = value.rsplit(":", 1)[0]
    if ":" in host_part:
        host_part = host_part.rsplit(":", 1)[1]
    host_part = host_part.split("/", 1)[0]
    return host_part if host_part.isdigit() else ""


def _probe_url(url: str, *, timeout: float) -> dict[str, Any]:
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


def _safe_token(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    text = re.sub(r"-+", "-", text).strip(".-")
    return (text or "case")[:48]


def _truncate(value: Any, limit: int = 4000) -> str:
    text = value.decode() if isinstance(value, bytes) else str(value or "")
    return text if len(text) <= limit else text[-limit:]


def _check_paths(
    checks: list[dict[str, str]],
    check_id: str,
    name: str,
    paths: list[Any],
    *,
    archive_dir: str | Path | None,
) -> None:
    missing = []
    for raw_path in paths:
        if not _path_exists(raw_path, archive_dir=archive_dir):
            missing.append(str(raw_path))
    _add_check(
        checks,
        check_id,
        name,
        "pass" if not missing else "fail",
        "文件存在" if not missing else "缺失文件：" + ", ".join(missing),
    )


def _path_exists(raw_path: Any, *, archive_dir: str | Path | None) -> bool:
    if not _text(raw_path):
        return False
    path = Path(str(raw_path))
    if path.exists():
        return True
    if archive_dir:
        archive_path = Path(archive_dir) / path
        if archive_path.exists():
            return True
    return False


def _manual_paths(writeup: dict[str, Any]) -> list[str]:
    paths = []
    for key in ["formal_manual_path", "manual_path"]:
        if _text(writeup.get(key)):
            paths.append(str(writeup[key]))
    return paths


def _screenshot_paths(case: dict[str, Any]) -> list[str]:
    archive_info = case.get("archive") if isinstance(case.get("archive"), dict) else {}
    paths = []
    for item in archive_info.get("screenshots", []) if isinstance(archive_info.get("screenshots"), list) else []:
        if isinstance(item, dict):
            value = str(item.get("path") or item.get("local_path") or "").strip()
        else:
            value = str(item).strip()
        if value:
            paths.append(value)
    return paths


def _manual_status(manual_paths: list[str], writeup: dict[str, Any]) -> str:
    if not manual_paths:
        return "未开始"
    if writeup.get("solve_verified") is True:
        return "已校验"
    return "待人工完善"


def _overall_status(checks: list[dict[str, str]]) -> str:
    if any(item["status"] == "fail" for item in checks):
        return "失败"
    if any(item["status"] == "skip" for item in checks):
        return "部分通过"
    return "通过"


def _add_check(checks: list[dict[str, str]], check_id: str, name: str, status: str, message: str) -> None:
    checks.append({"id": check_id, "name": name, "status": status, "message": message})


def _escape_table(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _text(value: Any) -> bool:
    return bool(str(value or "").strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF quality review utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    review_parser = subparsers.add_parser("review", help="create quality review report")
    review_parser.add_argument("--case-json", required=True)
    review_parser.add_argument("--output-dir", required=True)
    review_parser.add_argument("--archive-dir")
    review_parser.add_argument("--output-case")
    review_parser.add_argument("--execute-docker", action="store_true", help="run controlled docker load/inspect/run/probe/logs/stop")
    review_parser.add_argument("--skip-docker-load", action="store_true", help="do not run docker load before inspect")
    review_parser.add_argument("--probe-url", action="append", default=[], help="extra HTTP URL to probe after docker run")
    review_parser.add_argument("--startup-wait", type=float, default=2.0)
    review_parser.add_argument("--command-timeout", type=int, default=30)
    review_parser.add_argument("--probe-timeout", type=float, default=3.0)
    review_parser.add_argument("--docker-start-command", default="")

    args = parser.parse_args(argv)
    if args.command == "review":
        case = json.loads(Path(args.case_json).read_text(encoding="utf-8"))
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        docker_execution = None
        if args.execute_docker:
            docker_execution = execute_docker_review(
                case,
                output_dir,
                load_image=not args.skip_docker_load,
                startup_wait=args.startup_wait,
                command_timeout=args.command_timeout,
                probe_timeout=args.probe_timeout,
                probe_urls=args.probe_url,
                start_command=args.docker_start_command,
            )
            (output_dir / "docker_execution.json").write_text(
                json.dumps(docker_execution, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        review = create_quality_review(case, archive_dir=args.archive_dir, docker_execution=docker_execution)
        (output_dir / "quality_review.json").write_text(
            json.dumps(review, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        (output_dir / "quality_review_report.md").write_text(render_review_markdown(review), encoding="utf-8")
        if args.output_case:
            updated = apply_review_outputs(case, review)
            Path(args.output_case).write_text(json.dumps(updated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {output_dir / 'quality_review.json'}")
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
