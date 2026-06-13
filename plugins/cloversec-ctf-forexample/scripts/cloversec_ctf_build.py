#!/usr/bin/env python3
"""Docker planning and artifact metadata helpers for CloverSec CTF workflows."""

from __future__ import annotations

import argparse
import copy
import json
import shlex
import sys
from pathlib import Path
from typing import Any


TARGET_PLATFORM = "linux/amd64"


def create_docker_plan(
    project_dir: str | Path,
    image_name: str,
    tar_path: str | Path,
    ports: list[str] | None = None,
    start_command: str = "/start.sh",
) -> dict[str, Any]:
    project_path = Path(project_dir)
    tar = Path(tar_path)
    port_mappings = ports or []
    exposed_ports = [_container_port(port) for port in port_mappings]
    build_command = " ".join(
        [
            "docker",
            "build",
            "--platform",
            TARGET_PLATFORM,
            "-t",
            shlex.quote(image_name),
            shlex.quote(project_path.as_posix()),
        ]
    )
    run_parts = ["docker", "run", "--rm", "-d"]
    for port in port_mappings:
        run_parts.extend(["-p", shlex.quote(port)])
    run_parts.extend([shlex.quote(image_name), shlex.quote(start_command)])
    run_command = " ".join(run_parts)
    export_command = f"docker save {shlex.quote(image_name)} -o {shlex.quote(tar.as_posix())}"
    import_command = f"docker load -i {shlex.quote(tar.as_posix())}"
    inspect_command = f"docker image inspect {shlex.quote(image_name)}"

    docker_artifacts = {
        "image_name": image_name,
        "image_id": "",
        "platform": TARGET_PLATFORM,
        "ports": port_mappings,
        "tar_path": tar.as_posix(),
        "sha256": "",
        "build_command": build_command,
        "run_command": run_command,
        "export_command": export_command,
        "import_command": import_command,
        "inspect_command": inspect_command,
    }
    environment = {
        "project_dir": project_path.as_posix(),
        "platform": TARGET_PLATFORM,
        "start_command": start_command,
        "port_mappings": port_mappings,
        "exposed_ports": exposed_ports,
    }
    xlsx_fields = {
        "题目类型": "环境型",
        "开放端口": ",".join(exposed_ports),
        "构建状态": "未开始",
        "环境包/附件包路径": tar.as_posix(),
    }
    return {
        "environment": environment,
        "docker_artifacts": docker_artifacts,
        "xlsx_fields": xlsx_fields,
    }


def platform_from_inspect(inspect_data: Any) -> str:
    if isinstance(inspect_data, str):
        inspect_data = json.loads(inspect_data)
    image = inspect_data[0] if isinstance(inspect_data, list) and inspect_data else inspect_data
    if not isinstance(image, dict):
        return ""
    os_name = image.get("Os") or image.get("OS") or ""
    arch = image.get("Architecture") or ""
    if not os_name or not arch:
        return ""
    return f"{os_name}/{arch}"


def validate_docker_artifacts(artifacts: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    platform = artifacts.get("platform")
    if platform != TARGET_PLATFORM:
        issues.append(f"platform must be {TARGET_PLATFORM}, got {platform or '<empty>'}")
    if not artifacts.get("image_name"):
        issues.append("image_name is required")
    if not artifacts.get("tar_path"):
        issues.append("tar_path is required")
    return issues


def apply_docker_outputs(case: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    updated = copy.deepcopy(case)
    updated.setdefault("metadata", {})
    updated["environment"] = copy.deepcopy(plan.get("environment", {}))
    updated["docker_artifacts"] = copy.deepcopy(plan.get("docker_artifacts", {}))
    for key, value in plan.get("xlsx_fields", {}).items():
        updated["metadata"][key] = value
    return updated


def _container_port(mapping: str) -> str:
    if not mapping:
        return ""
    if ":" not in mapping:
        return mapping.split("/", 1)[0]
    return mapping.rsplit(":", 1)[1].split("/", 1)[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF Docker artifact utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("plan", help="write Docker plan JSON")
    plan_parser.add_argument("--project-dir", required=True)
    plan_parser.add_argument("--image-name", required=True)
    plan_parser.add_argument("--tar-path", required=True)
    plan_parser.add_argument("--port", action="append", default=[])
    plan_parser.add_argument("--start-command", default="/start.sh")
    plan_parser.add_argument("--output", required=True)

    inspect_parser = subparsers.add_parser("inspect-platform", help="parse docker image inspect JSON")
    inspect_parser.add_argument("inspect_json")

    validate_parser = subparsers.add_parser("validate-artifacts", help="validate docker_artifacts JSON")
    validate_parser.add_argument("input")

    args = parser.parse_args(argv)

    if args.command == "plan":
        plan = create_docker_plan(
            project_dir=args.project_dir,
            image_name=args.image_name,
            tar_path=args.tar_path,
            ports=args.port,
            start_command=args.start_command,
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {output}")
        return 0

    if args.command == "inspect-platform":
        print(platform_from_inspect(Path(args.inspect_json).read_text(encoding="utf-8")))
        return 0

    if args.command == "validate-artifacts":
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
        artifacts = payload.get("docker_artifacts", payload) if isinstance(payload, dict) else {}
        issues = validate_docker_artifacts(artifacts)
        if issues:
            print("\n".join(issues), file=sys.stderr)
            return 1
        print("docker artifacts valid")
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
