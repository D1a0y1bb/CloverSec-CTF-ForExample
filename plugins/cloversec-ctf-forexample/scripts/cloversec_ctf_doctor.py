#!/usr/bin/env python3
"""Check local and installed CloverSec CTF plugin capabilities."""

from __future__ import annotations

import argparse
import importlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
PLUGIN_ROOT = SCRIPT_DIR.parent
DOCKERIZER_REQUIREMENTS = PLUGIN_ROOT / "skills" / "cloversec-ctf-build-dockerizer" / "scripts" / "requirements.txt"


def main() -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF plugin environment doctor")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--installed", action="store_true", help="also check files that must exist inside an installed plugin package")
    args = parser.parse_args()
    report = build_report(installed=args.installed)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(render_report(report))
    return 0


def build_report(*, installed: bool = False) -> dict[str, Any]:
    checks = [
        check_python(),
        check_pyyaml(),
        check_openpyxl(),
        check_gh(),
        check_docker(),
        check_chrome(),
    ]
    package_checks = package_file_checks() if installed else []
    import_checks = core_import_checks() if installed else []
    all_checks = checks + package_checks + import_checks
    return {
        "schema_version": "cloversec.ctf.doctor.v2",
        "plugin_root": PLUGIN_ROOT.as_posix(),
        "installed_checks_enabled": installed,
        "checks": all_checks,
        "capabilities": {
            "search": capability_status(all_checks, ["python"]),
            "github_search": capability_status(all_checks, ["python", "gh"]),
            "dockerizer": capability_status(all_checks, ["python", "pyyaml"]),
            "xlsx_polished_export": capability_status(all_checks, ["python", "openpyxl"]),
            "docker_runtime": capability_status(all_checks, ["docker"]),
            "hub_browser_assist": capability_status(all_checks, ["chrome"]),
            "installed_package": capability_status(all_checks, [item["id"] for item in package_checks]) if installed else "not_checked",
            "core_imports": capability_status(all_checks, [item["id"] for item in import_checks]) if installed else "not_checked",
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


def check_openpyxl() -> dict[str, Any]:
    try:
        import openpyxl  # noqa: F401
    except ModuleNotFoundError:
        return {
            "id": "openpyxl",
            "name": "openpyxl",
            "status": "warning",
            "detail": "未安装时仍可导出 xlsx；安装 openpyxl 后表格样式更适合人工查看",
        }
    return {"id": "openpyxl", "name": "openpyxl", "status": "ok", "detail": "installed"}


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


def package_file_checks() -> list[dict[str, Any]]:
    required = {
        "plugin_manifest": PLUGIN_ROOT / ".codex-plugin" / "plugin.json",
        "mcp_config": PLUGIN_ROOT / ".mcp.json",
        "app_icon": PLUGIN_ROOT / "assets" / "app-icon.png",
        "search_recall_benchmark": PLUGIN_ROOT / "references" / "search-recall-benchmark.json",
        "show_progress": SCRIPT_DIR / "show_progress.py",
        "handoff": SCRIPT_DIR / "cloversec_ctf_handoff.py",
    }
    checks = []
    for check_id, path in required.items():
        checks.append(
            {
                "id": check_id,
                "name": check_id,
                "status": "ok" if path.exists() else "missing",
                "detail": path.as_posix(),
            }
        )
    return checks


def core_import_checks() -> list[dict[str, Any]]:
    modules = [
        "cloversec_ctf_search",
        "cloversec_ctf_search_plus",
        "cloversec_ctf_workflow",
        "cloversec_ctf_handoff",
        "cloversec_ctf_progress",
    ]
    checks = []
    for module in modules:
        try:
            importlib.import_module(module)
        except Exception as exc:  # noqa: BLE001
            checks.append({"id": f"import_{module}", "name": module, "status": "missing", "detail": str(exc)})
        else:
            checks.append({"id": f"import_{module}", "name": module, "status": "ok", "detail": "import ok"})
    return checks


def capability_status(checks: list[dict[str, Any]], required_ids: list[str]) -> str:
    if not required_ids:
        return "not_checked"
    by_id = {item["id"]: item for item in checks}
    statuses = [by_id.get(item, {}).get("status", "missing") for item in required_ids]
    if all(status in {"ok", "warning"} for status in statuses):
        return "available"
    if any(status in {"ok", "warning"} for status in statuses):
        return "limited"
    return "unavailable"


def run(command: list[str], *, timeout: int = 10) -> dict[str, Any]:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
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
