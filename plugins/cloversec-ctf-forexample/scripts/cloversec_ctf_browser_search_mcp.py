#!/usr/bin/env python3
"""Minimal stdio MCP server for browser-assisted CloverSec CTF search."""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any

import cloversec_ctf_browser_search as browser_search
import cloversec_ctf_mcp_runtime as mcp_runtime

SERVER_NAME = "cloversec-ctf-browser-search"

TOOLS = [
    {
        "name": "cloversec_ctf_browser_search_plan",
        "description": "Create a browser-assisted search plan for Google, Baidu, CSDN, Cnblogs, or Yuque.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "engine": {"type": "string", "enum": sorted(browser_search.BROWSER_SEARCH_ENGINES)},
                "open_browser": {"type": "boolean"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "cloversec_ctf_browser_search_import_visible",
        "description": "Normalize visible browser search results into CloverSec scored search results without reading browser secrets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "engine": {"type": "string", "enum": sorted(browser_search.BROWSER_SEARCH_ENGINES)},
                "results": {"type": "array", "items": {"type": "object"}},
                "blocked_by_captcha": {"type": "boolean"},
                "blocked_reason": {"type": "string"},
            },
            "required": ["query", "engine"],
        },
    },
    {
        "name": "cloversec_ctf_browser_search_dom_to_visible",
        "description": "Convert user-confirmed Chrome/Codex visible DOM, HTML, links, or text into visible_results.json and scored results.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "engine": {"type": "string", "enum": sorted(browser_search.BROWSER_SEARCH_ENGINES)},
                "page_url": {"type": "string"},
                "dom": {"type": "object"},
                "output_path": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                "compact": {"type": "boolean"},
            },
            "required": ["query", "engine", "dom"],
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
                    "serverInfo": {"name": "cloversec-ctf-browser-search", "version": "1.0.1"},
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
    except Exception as exc:  # noqa: BLE001 - must return MCP JSON-RPC errors.
        return error_response(request_id, -32000, str(exc), {"traceback": traceback.format_exc(limit=5)})


def call_tool(name: str, arguments: dict[str, Any]) -> Any:
    if name == "cloversec_ctf_browser_search_plan":
        return browser_search.create_browser_search_plan(
            str(arguments.get("query", "")),
            engine=str(arguments.get("engine", "google")),
            open_browser=bool(arguments.get("open_browser", False)),
        )
    if name == "cloversec_ctf_browser_search_import_visible":
        payload = {
            "results": arguments.get("results", []),
            "blocked_by_captcha": bool(arguments.get("blocked_by_captcha", False)),
            "blocked_reason": str(arguments.get("blocked_reason", "")),
        }
        return browser_search.normalize_visible_results(
            payload,
            query=str(arguments.get("query", "")),
            engine=str(arguments.get("engine", "google")),
        )
    if name == "cloversec_ctf_browser_search_dom_to_visible":
        return browser_search.dom_to_visible_bundle(
            arguments.get("dom", {}),
            query=str(arguments.get("query", "")),
            engine=str(arguments.get("engine", "google")),
            page_url=str(arguments.get("page_url", "")),
            limit=int(arguments.get("limit", 50)),
            output_path=str(arguments.get("output_path") or "") or None,
            compact=bool(arguments.get("compact", True)),
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
            sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
