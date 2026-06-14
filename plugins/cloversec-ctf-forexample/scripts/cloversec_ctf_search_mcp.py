#!/usr/bin/env python3
"""Minimal stdio MCP server for CloverSec CTF search helpers."""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any

import cloversec_ctf_search as search


TOOLS = [
    {
        "name": "cloversec_ctf_discover",
        "description": "Search public CTF sources using free providers and optional GitHub code search.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "years": {"type": "array", "items": {"type": "integer"}},
                "sources": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": search.SEARCH_SOURCES,
                    },
                },
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            },
            "required": ["query"],
        },
    },
    {
        "name": "cloversec_ctf_fetch_url",
        "description": "Fetch a URL and return status, content type, hash, title, and text when safe.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "max_bytes": {"type": "integer", "minimum": 1024, "maximum": 10485760},
            },
            "required": ["url"],
        },
    },
    {
        "name": "cloversec_ctf_ctftime_events",
        "description": "Fetch CTFTime events for a year and optional title query.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "year": {"type": "integer"},
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
            "required": ["year"],
        },
    },
    {
        "name": "cloversec_ctf_github_release_assets",
        "description": "List downloadable assets from GitHub Releases for a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
            "required": ["repo"],
        },
    },
    {
        "name": "cloversec_ctf_import_agent_web_results",
        "description": "Normalize web search results gathered by the current Agent into CloverSec scored search results.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "results": {"type": "array", "items": {"type": "object"}},
                "provider": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
            "required": ["query", "results"],
        },
    },
    {
        "name": "cloversec_ctf_results_to_cases",
        "description": "Convert a scored search manifest into structured ctf_cases draft rows with confidence, candidates, and missing reasons.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest": {"type": "object"},
            },
            "required": ["manifest"],
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
                    "serverInfo": {"name": "cloversec-ctf-search", "version": "0.3.4"},
                },
            )
        if method == "tools/list":
            return response(request_id, {"tools": TOOLS})
        if method == "tools/call":
            params = request.get("params") if isinstance(request.get("params"), dict) else {}
            name = params.get("name")
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            return response(request_id, {"content": [{"type": "text", "text": json.dumps(call_tool(name, arguments), ensure_ascii=False, indent=2)}]})
        if request_id is None:
            return None
        return error_response(request_id, -32601, f"unknown method: {method}")
    except Exception as exc:  # noqa: BLE001 - must return MCP JSON-RPC errors.
        return error_response(request_id, -32000, str(exc), {"traceback": traceback.format_exc(limit=5)})


def call_tool(name: str, arguments: dict[str, Any]) -> Any:
    if name == "cloversec_ctf_discover":
        return search.discover(
            str(arguments.get("query", "")),
            years=[int(item) for item in arguments.get("years", [])],
            sources=arguments.get("sources"),
            limit=int(arguments.get("limit", 20)),
        )
    if name == "cloversec_ctf_fetch_url":
        return search.fetch_url(str(arguments.get("url", "")), max_bytes=int(arguments.get("max_bytes", 2 * 1024 * 1024)))
    if name == "cloversec_ctf_ctftime_events":
        return {
            "year": int(arguments.get("year")),
            "query": str(arguments.get("query", "")),
            "results": search.search_ctftime_events(
                year=int(arguments.get("year")),
                query=str(arguments.get("query", "")),
                limit=int(arguments.get("limit", 100)),
            ),
        }
    if name == "cloversec_ctf_github_release_assets":
        errors = []
        try:
            results = search.github_release_assets(str(arguments.get("repo", "")), limit=int(arguments.get("limit", 30)))
        except Exception as exc:  # noqa: BLE001 - MCP callers need structured provider failures.
            results = []
            errors.append(search.provider_issue("github-release", exc))
        return {
            "repository": search.safe_normalize_repo_name(str(arguments.get("repo", ""))),
            "results": results,
            "errors": errors,
            "summary": {"total_results": len(results), "errors": len(errors)},
        }
    if name == "cloversec_ctf_import_agent_web_results":
        return search.import_agent_search_results(
            arguments.get("results", []),
            query=str(arguments.get("query", "")),
            provider=str(arguments.get("provider", "agent-web-search")),
            limit=int(arguments.get("limit", 50)),
        )
    if name == "cloversec_ctf_results_to_cases":
        cases = search.results_to_cases(arguments.get("manifest", {}))
        return {
            "schema_version": "cloversec.ctf.results_to_cases.compact.v1",
            "case_count": len(cases),
            "cases": cases[:20],
            "response_note": "短 JSON 默认返回。需要写入 ctf_cases.jsonl 时使用脚本 results-to-cases。",
        }
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
