#!/usr/bin/env python3
"""Check local capabilities for CloverSec CTF For Example."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DOCKERIZER_REQUIREMENTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "skills" / "cloversec-ctf-build-dockerizer" / "scripts" / "requirements.txt"


def main() -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF plugin environment doctor")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = build_report()
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(render_report(report))
    return 0


def build_report() -> dict[str, Any]:
    checks = [
        check_python(),
        check_pyyaml(),
        check_gh(),
        check_docker(),
        check_chrome(),
    ]
    return {
        "schema_version": "cloversec.ctf.doctor.v1",
        "checks": checks,
        "capabilities": {
            "search": capability_status(checks, ["python"]),
            "github_search": capability_status(checks, ["python", "gh"]),
            "dockerizer": capability_status(checks, ["python", "pyyaml"]),
            "docker_runtime": capability_status(checks, ["docker"]),
            "hub_browser_assist": capability_status(checks, ["chrome"]),
        },
    }


def check_python() -> dict[str, Any]:
    return {"id": "python", "name": "Python", "status": "ok", "detail": sys.version.split()[0]}


def check_pyyaml() -> dict[str, Any]:
    try:
        import yaml  # noqa: F401
    except ModuleNotFoundError:
        return {
            "id": "pyyaml",
            "name": "PyYAML",
            "status": "missing",
            "detail": f"容器改造需要 PyYAML：pip install -r {DOCKERIZER_REQUIREMENTS.as_posix()}",
        }
    return {"id": "pyyaml", "name": "PyYAML", "status": "ok", "detail": "installed"}


def check_gh() -> dict[str, Any]:
    gh = shutil.which("gh")
    if not gh:
        return {"id": "gh", "name": "GitHub CLI", "status": "missing", "detail": "未找到 gh，GitHub 搜索会降级"}
    result = run(["gh", "auth", "status"])
    status = "ok" if result["returncode"] == 0 else "warning"
    return {"id": "gh", "name": "GitHub CLI", "status": status, "detail": result["stderr"] or result["stdout"] or gh}


def check_docker() -> dict[str, Any]:
    docker = shutil.which("docker")
    if not docker:
        return {"id": "docker", "name": "Docker", "status": "missing", "detail": "容器验证、save/load 和 amd64 检查不可用"}
    result = run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=8)
    status = "ok" if result["returncode"] == 0 else "warning"
    return {"id": "docker", "name": "Docker", "status": status, "detail": result["stdout"] or result["stderr"] or docker}


def check_chrome() -> dict[str, Any]:
    chrome_paths = [
        Path("/Applications/Google Chrome.app"),
        Path.home() / "Applications" / "Google Chrome.app",
    ]
    existing = next((path for path in chrome_paths if path.exists()), None)
    if not existing:
        return {"id": "chrome", "name": "Chrome", "status": "missing", "detail": "Hub 浏览器辅助需要用户已登录的 Chrome 页面"}
    return {"id": "chrome", "name": "Chrome", "status": "ok", "detail": existing.as_posix()}


def capability_status(checks: list[dict[str, Any]], required_ids: list[str]) -> str:
    by_id = {item["id"]: item for item in checks}
    statuses = [by_id.get(item, {}).get("status", "missing") for item in required_ids]
    if all(status == "ok" for status in statuses):
        return "available"
    if any(status == "ok" for status in statuses):
        return "limited"
    return "unavailable"


def run(command: list[str], *, timeout: int = 10) -> dict[str, Any]:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - doctor should report local failures.
        return {"returncode": 1, "stdout": "", "stderr": str(exc)}
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def render_report(report: dict[str, Any]) -> str:
    lines = ["CloverSec CTF For Example 环境检查", ""]
    for item in report["checks"]:
        lines.append(f"- {item['name']}: {item['status']} - {single_line(item.get('detail', ''))}")
    lines.extend(["", "能力状态："])
    for name, status in report["capabilities"].items():
        lines.append(f"- {name}: {status}")
    return "\n".join(lines)


def single_line(value: str) -> str:
    return " ".join(str(value).split())


if __name__ == "__main__":
    raise SystemExit(main())
