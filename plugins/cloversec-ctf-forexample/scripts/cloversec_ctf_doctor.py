#!/usr/bin/env python3
"""Check local and installed CloverSec CTF plugin capabilities."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
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
        check_node(),
        check_pyyaml(),
        check_openpyxl(),
        check_gh(),
        check_docker(),
        check_chrome(),
    ]
    package_checks = package_file_checks() if installed else []
    import_checks = core_import_checks() if installed else []
    mcp_checks = mcp_runtime_checks() if installed else []
    all_checks = checks + package_checks + import_checks + mcp_checks
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
            "mcp_runtime": capability_status(all_checks, [item["id"] for item in mcp_checks]) if installed else "not_checked",
        },
    }


def check_python() -> dict[str, Any]:
    return {"id": "python", "name": "Python", "status": "ok", "detail": sys.version.split()[0]}


def check_node() -> dict[str, Any]:
    node = shutil.which("node")
    if not node:
        return {"id": "node", "name": "Node.js", "status": "missing", "detail": "MCP 启动器需要 node"}
    result = run([node, "--version"])
    status = "ok" if result["returncode"] == 0 else "missing"
    return {"id": "node", "name": "Node.js", "status": status, "detail": result["stdout"] or result["stderr"] or node}


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


def mcp_runtime_checks() -> list[dict[str, Any]]:
    config_path = PLUGIN_ROOT / ".mcp.json"
    if not config_path.is_file():
        return [{"id": "mcp_config_readable", "name": "MCP config", "status": "missing", "detail": config_path.as_posix()}]
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [{"id": "mcp_config_readable", "name": "MCP config", "status": "missing", "detail": str(exc)}]
    servers = config.get("mcpServers") if isinstance(config.get("mcpServers"), dict) else {}
    checks: list[dict[str, Any]] = [
        {
            "id": "mcp_config_readable",
            "name": "MCP config",
            "status": "ok" if servers else "missing",
            "detail": f"{len(servers)} servers",
        }
    ]
    with tempfile.TemporaryDirectory(prefix="cloversec-mcp-doctor-") as tmp:
        for name, server in servers.items():
            if not isinstance(server, dict):
                checks.append({"id": f"mcp_command_{name}", "name": f"MCP command {name}", "status": "missing", "detail": "server config is not object"})
                continue
            checks.append(check_mcp_command(name, server))
            checks.append(check_mcp_encoding_env(name, server))
            checks.append(smoke_mcp_server(name, server, Path(tmp) / name))
    return checks


def check_mcp_command(name: str, server: dict[str, Any]) -> dict[str, Any]:
    command = str(server.get("command") or "").strip()
    args = [str(item) for item in server.get("args", [])] if isinstance(server.get("args"), list) else []
    if not command:
        return {"id": f"mcp_command_{name}", "name": f"MCP command {name}", "status": "missing", "detail": "command is empty"}
    command_exists = shutil.which(command) is not None if Path(command).name == command else Path(command).exists()
    missing = []
    if not command_exists:
        missing.append(f"command not found: {command}")
    for index, arg in enumerate(args):
        if arg.startswith("-"):
            continue
        if index > 1:
            continue
        path = (PLUGIN_ROOT / arg).resolve()
        if not path.exists():
            missing.append(f"arg path missing: {arg}")
    return {
        "id": f"mcp_command_{name}",
        "name": f"MCP command {name}",
        "status": "ok" if not missing else "missing",
        "detail": "; ".join(missing) if missing else f"{command} {' '.join(args)}",
    }


def check_mcp_encoding_env(name: str, server: dict[str, Any]) -> dict[str, Any]:
    env = server.get("env") if isinstance(server.get("env"), dict) else {}
    required = {"PYTHONUNBUFFERED": "1", "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    missing = [f"{key}={value}" for key, value in required.items() if str(env.get(key) or "").lower() != value]
    return {
        "id": f"mcp_encoding_{name}",
        "name": f"MCP UTF-8 {name}",
        "status": "ok" if not missing else "warning",
        "detail": "ok" if not missing else "missing " + ", ".join(missing),
    }


def smoke_mcp_server(name: str, server: dict[str, Any], runtime_dir: Path) -> dict[str, Any]:
    command = str(server.get("command") or "").strip()
    args = [str(item) for item in server.get("args", [])] if isinstance(server.get("args"), list) else []
    cwd = (PLUGIN_ROOT / str(server.get("cwd") or ".")).resolve()
    env = {**os_environ(), **{str(k): str(v) for k, v in (server.get("env") or {}).items()}}
    env["CLOVERSEC_CTF_MCP_STATE_DIR"] = runtime_dir.as_posix()
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    try:
        completed = subprocess.run(
            [command, *args],
            input=("\n".join(json.dumps(item) for item in requests) + "\n").encode("utf-8"),
            cwd=str(cwd),
            env=env,
            capture_output=True,
            timeout=12,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return {"id": f"mcp_smoke_{name}", "name": f"MCP smoke {name}", "status": "missing", "detail": str(exc)}
    try:
        stdout = completed.stdout.decode("utf-8")
        stderr = completed.stderr.decode("utf-8")
    except UnicodeDecodeError as exc:
        return {"id": f"mcp_smoke_{name}", "name": f"MCP smoke {name}", "status": "missing", "detail": f"stdout/stderr not UTF-8: {exc}"}
    if completed.returncode != 0:
        return {
            "id": f"mcp_smoke_{name}",
            "name": f"MCP smoke {name}",
            "status": "missing",
            "detail": single_line(stderr or stdout or f"exit {completed.returncode}"),
        }
    try:
        rows = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    except json.JSONDecodeError as exc:
        return {"id": f"mcp_smoke_{name}", "name": f"MCP smoke {name}", "status": "missing", "detail": f"invalid JSON-RPC output: {exc}"}
    tools = rows[1].get("result", {}).get("tools", []) if len(rows) >= 2 and isinstance(rows[1], dict) else []
    status = "ok" if len(rows) >= 2 and tools else "missing"
    detail = f"tools={len(tools)}" if status == "ok" else single_line(stdout or stderr)
    return {"id": f"mcp_smoke_{name}", "name": f"MCP smoke {name}", "status": status, "detail": detail}


def os_environ() -> dict[str, str]:
    return {str(key): str(value) for key, value in os.environ.items()}


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
