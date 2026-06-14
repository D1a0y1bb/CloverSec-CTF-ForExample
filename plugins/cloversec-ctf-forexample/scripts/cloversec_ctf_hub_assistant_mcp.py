#!/usr/bin/env python3
"""Minimal stdio MCP server for CloverSec CTF Hub assistant helpers."""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any

import cloversec_ctf_hub as hub


TOOLS = [
    {
        "name": "cloversec_ctf_hub_browser_plan",
        "description": "Create a safe browser-assisted Hub submission plan from an upload manifest.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest": {"type": "object"},
                "hub_url": {"type": "string"},
                "classify_options": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["manifest"],
        },
    },
    {
        "name": "cloversec_ctf_hub_chrome_plan",
        "description": "Create a Chrome-assisted Hub plan that stops before final submit and never reads browser secrets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest": {"type": "object"},
                "hub_url": {"type": "string"},
                "classify_options": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["manifest"],
        },
    },
    {
        "name": "cloversec_ctf_hub_validate_manifest",
        "description": "Validate Hub payload readiness, classify mapping, upload results, and screenshot slots.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest": {"type": "object"},
                "classify_options": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["manifest"],
        },
    },
    {
        "name": "cloversec_ctf_hub_apply_upload_results",
        "description": "Merge visible Hub upload results back into an upload manifest.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest": {"type": "object"},
                "upload_results": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["manifest", "upload_results"],
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
                    "serverInfo": {"name": "cloversec-ctf-hub-assistant", "version": "0.3.2"},
                },
            )
        if method == "tools/list":
            return response(request_id, {"tools": TOOLS})
        if method == "tools/call":
            params = request.get("params") if isinstance(request.get("params"), dict) else {}
            name = str(params.get("name") or "")
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            payload = call_tool(name, arguments)
            return response(request_id, {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}]})
        if request_id is None:
            return None
        return error_response(request_id, -32601, f"unknown method: {method}")
    except Exception as exc:  # noqa: BLE001 - MCP callers need JSON-RPC errors.
        return error_response(request_id, -32000, str(exc), {"traceback": traceback.format_exc(limit=5)})


def call_tool(name: str, arguments: dict[str, Any]) -> Any:
    manifest = arguments.get("manifest") if isinstance(arguments.get("manifest"), dict) else {}
    classify_options = arguments.get("classify_options") if isinstance(arguments.get("classify_options"), list) else None
    hub_url = str(arguments.get("hub_url") or "https://hub.yunyansec.com/#/resource/ctf")
    if name == "cloversec_ctf_hub_browser_plan":
        return hub.create_browser_assist_plan(manifest, hub_url=hub_url, classify_options=classify_options)
    if name == "cloversec_ctf_hub_chrome_plan":
        return hub.create_chrome_assist_plan(manifest, hub_url=hub_url, classify_options=classify_options)
    if name == "cloversec_ctf_hub_validate_manifest":
        fields = manifest.get("hub_fields", {}) if isinstance(manifest.get("hub_fields"), dict) else {}
        payload = hub.create_hub_form_payload(fields, manifest=manifest, classify_options=classify_options)
        return {"form_payload": payload, "validation": hub.validate_hub_form_payload(payload, manifest=manifest)}
    if name == "cloversec_ctf_hub_apply_upload_results":
        upload_results = arguments.get("upload_results") if isinstance(arguments.get("upload_results"), list) else []
        return hub.apply_upload_results(manifest, upload_results)
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
