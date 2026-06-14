#!/usr/bin/env python3
"""Minimal stdio MCP server for CloverSec CTF archive workflows."""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any

import cloversec_ctf_archive_runner as archive_runner


SERVER_VERSION = "0.3.1"

TOOLS = [
    {
        "name": "cloversec_ctf_archive_batch",
        "description": "Read ctf_cases.jsonl and generate archive directories, resource index, manifests, final xlsx, Yuque table, and missing report.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cases_path": {"type": "string"},
                "output_root": {"type": "string"},
                "output_cases": {"type": "string"},
                "final_output_dir": {"type": "string"},
                "copy_files": {"type": "boolean"},
            },
            "required": ["cases_path", "output_root"],
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
                    "serverInfo": {"name": "cloversec-ctf-archive", "version": SERVER_VERSION},
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
    if name == "cloversec_ctf_archive_batch":
        payload = archive_runner.run_archive_workflow(
            cases_path=str(arguments.get("cases_path") or ""),
            output_root=str(arguments.get("output_root") or ""),
            output_cases=str(arguments.get("output_cases") or ""),
            final_output_dir=str(arguments.get("final_output_dir") or ""),
            copy_files=bool(arguments.get("copy_files", True)),
        )
        return archive_runner.compact_archive_payload(payload)
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
