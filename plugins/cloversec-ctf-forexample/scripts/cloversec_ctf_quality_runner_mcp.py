#!/usr/bin/env python3
"""Minimal stdio MCP server for CloverSec CTF quality runner."""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any

import cloversec_ctf_quality_runner as quality_runner


SERVER_VERSION = "0.3.1"

TOOLS = [
    {
        "name": "cloversec_ctf_quality_run",
        "description": "Run batch quality checks over ctf_cases.jsonl, including resources, Docker evidence, writeup status, Flag, and archive status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cases_path": {"type": "string"},
                "output_dir": {"type": "string"},
                "output_cases": {"type": "string"},
                "execute_docker": {"type": "boolean"},
                "archive_dir": {"type": "string"},
                "probe_urls": {"type": "array", "items": {"type": "string"}},
                "startup_wait": {"type": "number"},
                "command_timeout": {"type": "integer", "minimum": 1, "maximum": 600},
                "probe_timeout": {"type": "number"},
            },
            "required": ["cases_path", "output_dir"],
        },
    }
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
                    "serverInfo": {"name": "cloversec-ctf-quality-runner", "version": SERVER_VERSION},
                },
            )
        if method == "tools/list":
            return response(request_id, {"tools": TOOLS})
        if method == "tools/call":
            params = request.get("params") if isinstance(request.get("params"), dict) else {}
            name = params.get("name")
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            payload = call_tool(str(name or ""), arguments)
            return response(request_id, {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, separators=(",", ":"))}]})
        if request_id is None:
            return None
        return error_response(request_id, -32601, f"unknown method: {method}")
    except Exception as exc:  # noqa: BLE001
        return error_response(request_id, -32000, str(exc), {"traceback": traceback.format_exc(limit=5)})


def call_tool(name: str, arguments: dict[str, Any]) -> Any:
    if name == "cloversec_ctf_quality_run":
        payload = quality_runner.run_quality_batch(
            cases_path=str(arguments.get("cases_path") or ""),
            output_dir=str(arguments.get("output_dir") or ""),
            output_cases=str(arguments.get("output_cases") or ""),
            execute_docker=bool(arguments.get("execute_docker", False)),
            archive_dir=str(arguments.get("archive_dir") or ""),
            probe_urls=[str(item) for item in arguments.get("probe_urls", [])],
            startup_wait=float(arguments.get("startup_wait", 2.0)),
            command_timeout=int(arguments.get("command_timeout", 30)),
            probe_timeout=float(arguments.get("probe_timeout", 3.0)),
        )
        return quality_runner.compact_quality_payload(payload)
    raise ValueError(f"unknown tool: {name}")


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
