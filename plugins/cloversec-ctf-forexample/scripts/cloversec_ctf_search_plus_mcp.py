#!/usr/bin/env python3
"""Minimal stdio MCP server for CloverSec CTF search-plus."""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any

import cloversec_ctf_mcp_runtime as mcp_runtime
import cloversec_ctf_search as search
import cloversec_ctf_search_plus as search_plus

SERVER_NAME = "cloversec-ctf-search-plus"

TOOLS = [
    {
        "name": "cloversec_ctf_search_plus",
        "description": (
            "Unified CTF search across free sources, Agent web results, browser visible results, "
            "direct attachment URLs, GitHub releases/tree files, evidence scoring, and short JSON output."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "years": {"type": "array", "items": {"type": "integer"}},
                "sources": {"type": "array", "items": {"type": "string", "enum": search.SEARCH_SOURCES}},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
                "agent_results": {"description": "Web results from the current Agent search tool."},
                "browser_visible_results": {"description": "Visible browser results from Chrome/Codex browser helpers."},
                "direct_urls": {"type": "array", "items": {"type": "string"}},
                "github_repos": {"type": "array", "items": {}},
                "output_path": {"type": "string"},
                "cache_dir": {"type": "string"},
                "compact": {"type": "boolean"},
                "compact_results": {"type": "integer", "minimum": 1, "maximum": 20},
            },
            "required": ["query"],
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
                    "serverInfo": {"name": "cloversec-ctf-search-plus", "version": "1.0.14"},
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
    except Exception as exc:  # noqa: BLE001 - MCP callers need JSON-RPC errors.
        return error_response(request_id, -32000, str(exc), {"traceback": traceback.format_exc(limit=5)})


def call_tool(name: str, arguments: dict[str, Any]) -> Any:
    if name == "cloversec_ctf_search_plus":
        return search_plus.search_plus(
            str(arguments.get("query", "")),
            years=[int(item) for item in arguments.get("years", [])],
            sources=arguments.get("sources"),
            limit=int(arguments.get("limit", 20)),
            agent_results=arguments.get("agent_results"),
            browser_visible_results=arguments.get("browser_visible_results"),
            direct_urls=[str(item) for item in arguments.get("direct_urls", [])],
            github_repos=arguments.get("github_repos", []),
            output_path=str(arguments.get("output_path") or "") or None,
            cache_dir=str(arguments.get("cache_dir") or "") or None,
            compact=bool(arguments.get("compact", True)),
            compact_results=int(arguments.get("compact_results", search_plus.DEFAULT_COMPACT_RESULTS)),
        )
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
