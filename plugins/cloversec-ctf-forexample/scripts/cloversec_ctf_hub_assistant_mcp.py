#!/usr/bin/env python3
"""Minimal stdio MCP server for CloverSec CTF Hub assistant helpers."""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any

import cloversec_ctf_hub as hub
import cloversec_ctf_mcp_runtime as mcp_runtime
import cloversec_ctf_retag as retag


SERVER_VERSION = "1.0.12"
SERVER_NAME = "cloversec-ctf-hub-assistant"


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
    {
        "name": "cloversec_ctf_hub_draft",
        "description": "Create Hub draft, upload manifest, screenshot checklist, browser/chrome plans, and diff report without final submit.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case": {"type": "object"},
                "hub_fields": {"type": "object"},
                "manual_markdown": {"type": "string"},
                "output_dir": {"type": "string"},
                "classify_options": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["case", "hub_fields", "manual_markdown", "output_dir"],
        },
    },
    {
        "name": "cloversec_ctf_hub_review_state",
        "description": "Record Hub submission/review state, returned comments, visible Hub id, and retag task without inventing Hub numbers.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case": {"type": "object"},
                "output_dir": {"type": "string"},
                "submission_status": {"type": "string"},
                "review_status": {"type": "string"},
                "hub_id": {"type": "string"},
                "reviewer": {"type": "string"},
                "review_comment": {"type": "string"},
                "visible_page": {"type": "object"},
                "hub_id_confirmed": {"type": "boolean"},
            },
            "required": ["case", "output_dir"],
        },
    },
    {
        "name": "cloversec_ctf_hub_session_state",
        "description": "Record the logged-in Hub browser filling session: login check, field fill status, uploads, pre-submit screenshot, manual submit status, and visible Hub id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output_dir": {"type": "string"},
                "case": {"type": "object"},
                "draft": {"type": "object"},
                "manifest": {"type": "object"},
                "visible_page": {"type": "object"},
                "login_confirmed": {"type": "boolean"},
                "field_fill_status": {"type": "string"},
                "upload_results": {"type": "array", "items": {"type": "object"}},
                "pre_submit_screenshot": {"type": "string"},
                "user_submitted": {"type": "boolean"},
                "hub_id": {"type": "string"},
                "notes": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["output_dir"],
        },
    },
    {
        "name": "cloversec_ctf_image_naming_plan",
        "description": "Create image_naming_plan.json and retag_inputs.json from Hub id, case metadata, image source, and tag rules.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case": {"type": "object"},
                "hub_id": {"type": "string"},
                "output_dir": {"type": "string"},
                "registry_prefix": {"type": "string"},
                "tag_template": {"type": "string"},
                "hub_id_confirmed": {"type": "boolean"},
            },
            "required": ["case", "output_dir"],
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
                    "serverInfo": {"name": "cloversec-ctf-hub-assistant", "version": SERVER_VERSION},
                },
            )
        if method == "tools/list":
            return response(request_id, {"tools": TOOLS})
        if method == "tools/call":
            params = request.get("params") if isinstance(request.get("params"), dict) else {}
            name = str(params.get("name") or "")
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            payload = mcp_runtime.record_tool_call(
                server_name=SERVER_NAME,
                request_id=request_id,
                tool_name=name,
                arguments=arguments,
                handler=lambda: call_tool(name, arguments),
            )
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
    if name == "cloversec_ctf_hub_draft":
        return hub.create_hub_draft(
            arguments.get("case", {}),
            arguments.get("hub_fields", {}),
            str(arguments.get("manual_markdown") or ""),
            str(arguments.get("output_dir") or ""),
            classify_options=classify_options,
        )
    if name == "cloversec_ctf_hub_review_state":
        return hub.create_hub_review_state(
            arguments.get("case", {}),
            str(arguments.get("output_dir") or ""),
            submission_status=str(arguments.get("submission_status") or "draft"),
            review_status=str(arguments.get("review_status") or "not_submitted"),
            hub_id=str(arguments.get("hub_id") or ""),
            reviewer=str(arguments.get("reviewer") or ""),
            review_comment=str(arguments.get("review_comment") or ""),
            visible_page=arguments.get("visible_page") if isinstance(arguments.get("visible_page"), dict) else None,
            hub_id_confirmed=bool(arguments.get("hub_id_confirmed", False)),
        )
    if name == "cloversec_ctf_hub_session_state":
        return hub.create_hub_session_state(
            str(arguments.get("output_dir") or ""),
            case=arguments.get("case") if isinstance(arguments.get("case"), dict) else {},
            draft=arguments.get("draft") if isinstance(arguments.get("draft"), dict) else {},
            manifest=arguments.get("manifest") if isinstance(arguments.get("manifest"), dict) else {},
            visible_page=arguments.get("visible_page") if isinstance(arguments.get("visible_page"), dict) else {},
            login_confirmed=bool(arguments.get("login_confirmed", False)),
            field_fill_status=str(arguments.get("field_fill_status") or "not_started"),
            upload_results=arguments.get("upload_results") if isinstance(arguments.get("upload_results"), list) else [],
            pre_submit_screenshot=str(arguments.get("pre_submit_screenshot") or ""),
            user_submitted=bool(arguments.get("user_submitted", False)),
            hub_id=str(arguments.get("hub_id") or ""),
            notes=[str(item) for item in arguments.get("notes", [])] if isinstance(arguments.get("notes"), list) else [],
        )
    if name == "cloversec_ctf_image_naming_plan":
        return retag.create_image_naming_plan(
            arguments.get("case", {}),
            str(arguments.get("hub_id") or ""),
            str(arguments.get("output_dir") or ""),
            registry_prefix=str(arguments.get("registry_prefix") or ""),
            tag_template=str(arguments.get("tag_template") or "{hub_id}"),
            hub_id_confirmed=bool(arguments.get("hub_id_confirmed", False)),
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
