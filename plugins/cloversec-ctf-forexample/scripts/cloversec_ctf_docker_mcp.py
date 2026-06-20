#!/usr/bin/env python3
"""Minimal stdio MCP server for controlled CloverSec CTF Docker workflows."""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any

import cloversec_ctf_docker as docker_runner
import cloversec_ctf_mcp_runtime as mcp_runtime


SERVER_VERSION = "1.0.1"
SERVER_NAME = "cloversec-ctf-docker"

TOOLS = [
    {
        "name": "cloversec_ctf_docker_plan",
        "description": "Create a controlled Docker build/load/inspect/run/logs/stop/save plan without executing it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case": {"type": "object"},
                "project_dir": {"type": "string"},
                "image_name": {"type": "string"},
                "tar_path": {"type": "string"},
                "ports": {"type": "array", "items": {"type": "string"}},
                "dockerfile": {"type": "string"},
                "container_command": {"type": "string"},
                "operations": {"type": "array", "items": {"type": "string", "enum": docker_runner.DEFAULT_OPERATIONS}},
                "validation_level": {"type": "string", "enum": docker_runner.VALIDATION_LEVELS},
                "container_inference": {"type": "object"},
            },
        },
    },
    {
        "name": "cloversec_ctf_docker_validation_plan",
        "description": "Create a Docker validation plan from a validation level such as static_only, inspect_only, build_only, run_probe, or solve_verify.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case": {"type": "object"},
                "project_dir": {"type": "string"},
                "image_name": {"type": "string"},
                "tar_path": {"type": "string"},
                "ports": {"type": "array", "items": {"type": "string"}},
                "dockerfile": {"type": "string"},
                "container_command": {"type": "string"},
                "validation_level": {"type": "string", "enum": docker_runner.VALIDATION_LEVELS},
                "container_inference": {"type": "object"},
            },
        },
    },
    {
        "name": "cloversec_ctf_docker_execute",
        "description": "Run controlled Docker operations and write evidence with platform, probes, logs, hash, and failures.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case": {"type": "object"},
                "output_dir": {"type": "string"},
                "project_dir": {"type": "string"},
                "image_name": {"type": "string"},
                "tar_path": {"type": "string"},
                "ports": {"type": "array", "items": {"type": "string"}},
                "dockerfile": {"type": "string"},
                "container_command": {"type": "string"},
                "operations": {"type": "array", "items": {"type": "string", "enum": docker_runner.DEFAULT_OPERATIONS}},
                "validation_level": {"type": "string", "enum": docker_runner.VALIDATION_LEVELS},
                "container_inference": {"type": "object"},
                "probe_urls": {"type": "array", "items": {"type": "string"}},
                "startup_wait": {"type": "number"},
                "command_timeout": {"type": "integer", "minimum": 1, "maximum": 600},
                "probe_timeout": {"type": "number"},
                "authorization_workdir": {"type": "string"},
                "authorization_path": {"type": "string"},
            },
            "required": ["output_dir"],
        },
    },
]


def handle_request(request: dict[str, Any]) -> dict[str, Any] | None:
    method = request.get("method")
    request_id = request.get("id")
    try:
        if method == "initialize":
            return response(
                request_id,
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "cloversec-ctf-docker", "version": SERVER_VERSION},
                },
            )
        if method == "tools/list":
            return response(request_id, {"tools": TOOLS})
        if method == "tools/call":
            params = request.get("params") if isinstance(request.get("params"), dict) else {}
            name = params.get("name")
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            payload = mcp_runtime.record_tool_call(
                server_name=SERVER_NAME,
                request_id=request_id,
                tool_name=str(name or ""),
                arguments=arguments,
                handler=lambda: call_tool(str(name or ""), arguments),
            )
            return response(request_id, {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, separators=(",", ":"))}]})
        if request_id is None:
            return None
        return error_response(request_id, -32601, f"unknown method: {method}")
    except Exception as exc:  # noqa: BLE001
        return error_response(request_id, -32000, str(exc), {"traceback": traceback.format_exc(limit=5)})


def call_tool(name: str, arguments: dict[str, Any]) -> Any:
    if name == "cloversec_ctf_docker_plan":
        return docker_runner.create_docker_plan(
            case=arguments.get("case", {}),
            project_dir=str(arguments.get("project_dir") or ""),
            image_name=str(arguments.get("image_name") or ""),
            tar_path=str(arguments.get("tar_path") or ""),
            ports=[str(item) for item in arguments.get("ports", [])],
            dockerfile=str(arguments.get("dockerfile") or ""),
            container_command=str(arguments.get("container_command") or ""),
            operations=optional_operations(arguments),
            validation_level=str(arguments.get("validation_level") or ""),
            container_inference=arguments.get("container_inference", {}),
        )
    if name == "cloversec_ctf_docker_validation_plan":
        return docker_runner.create_docker_validation_plan(
            case=arguments.get("case", {}),
            project_dir=str(arguments.get("project_dir") or ""),
            image_name=str(arguments.get("image_name") or ""),
            tar_path=str(arguments.get("tar_path") or ""),
            ports=[str(item) for item in arguments.get("ports", [])],
            dockerfile=str(arguments.get("dockerfile") or ""),
            container_command=str(arguments.get("container_command") or ""),
            validation_level=str(arguments.get("validation_level") or ""),
            container_inference=arguments.get("container_inference", {}),
        )
    if name == "cloversec_ctf_docker_execute":
        evidence = docker_runner.execute_docker_workflow(
            case=arguments.get("case", {}),
            output_dir=str(arguments.get("output_dir") or ""),
            project_dir=str(arguments.get("project_dir") or ""),
            image_name=str(arguments.get("image_name") or ""),
            tar_path=str(arguments.get("tar_path") or ""),
            ports=[str(item) for item in arguments.get("ports", [])],
            dockerfile=str(arguments.get("dockerfile") or ""),
            container_command=str(arguments.get("container_command") or ""),
            operations=optional_operations(arguments),
            validation_level=str(arguments.get("validation_level") or ""),
            container_inference=arguments.get("container_inference", {}),
            probe_urls=[str(item) for item in arguments.get("probe_urls", [])],
            startup_wait=float(arguments.get("startup_wait", 2.0)),
            command_timeout=int(arguments.get("command_timeout", 60)),
            probe_timeout=float(arguments.get("probe_timeout", 3.0)),
            authorization_workdir=str(arguments.get("authorization_workdir") or ""),
            authorization_path=str(arguments.get("authorization_path") or ""),
        )
        return docker_runner.compact_evidence(evidence)
    raise ValueError(f"unknown tool: {name}")


def optional_operations(arguments: dict[str, Any]) -> list[str] | None:
    if "operations" not in arguments:
        return None
    return [str(item) for item in arguments.get("operations", [])]


def response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def error_response(request_id: Any, code: int, message: str, data: Any | None = None) -> dict[str, Any]:
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps(error_response(None, -32700, "parse error")) + "\n")
            sys.stdout.flush()
            continue
        result = handle_request(request)
        if result is not None:
            sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
