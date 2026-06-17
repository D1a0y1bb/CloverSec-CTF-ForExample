#!/usr/bin/env python3
"""Minimal stdio MCP server for CloverSec CTF quality runner."""

from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path
from typing import Any

import cloversec_ctf_audit as audit
import cloversec_ctf_data as data
import cloversec_ctf_manual_quality as manual_quality
import cloversec_ctf_mcp_runtime as mcp_runtime
import cloversec_ctf_quality_runner as quality_runner
import cloversec_ctf_proof as proof


SERVER_VERSION = "0.7.1"
SERVER_NAME = "cloversec-ctf-quality-runner"

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
    },
    {
        "name": "cloversec_ctf_proof_pack",
        "description": "Create a proof package with copied evidence, hashes, manifest, and review report from resource, container, Docker, and quality JSON files.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output_dir": {"type": "string"},
                "case": {"type": "object"},
                "case_json": {"type": "string"},
                "resource_classification_path": {"type": "string"},
                "container_inference_path": {"type": "string"},
                "docker_evidence_path": {"type": "string"},
                "quality_review_path": {"type": "string"},
                "extra_files": {"type": "array", "items": {"type": "string"}},
                "notes": {"type": "string"},
            },
            "required": ["output_dir"],
        },
    },
    {
        "name": "cloversec_ctf_manual_quality",
        "description": "Check manual fields, sections, steps, screenshots, Flag, attachments, and Hub field consistency.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case": {"type": "object"},
                "manual_markdown": {"type": "string"},
                "manual_path": {"type": "string"},
                "hub_fields": {"type": "object"},
                "archive_manifest": {"type": "object"},
                "resource_manifest": {"type": "object"},
                "output_dir": {"type": "string"},
            },
            "required": ["case", "output_dir"],
        },
    },
    {
        "name": "cloversec_ctf_batch_status_report",
        "description": "Create batch_status_report.json/md/xlsx grouped by event, year, category, state, missing resources, and human confirmations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cases": {"type": "array", "items": {"type": "object"}},
                "cases_path": {"type": "string"},
                "output_dir": {"type": "string"},
                "workflow_state": {"type": "object"},
            },
            "required": ["output_dir"],
        },
    },
    {
        "name": "cloversec_ctf_failure_cases",
        "description": "Create failure_cases.jsonl from search, download, build, Hub return, manual mismatch, and missing-resource evidence.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cases": {"type": "array", "items": {"type": "object"}},
                "cases_path": {"type": "string"},
                "output_path": {"type": "string"},
                "extra_failures": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["output_path"],
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
                    "serverInfo": {"name": "cloversec-ctf-quality-runner", "version": SERVER_VERSION},
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
    if name == "cloversec_ctf_proof_pack":
        payload = proof.create_proof_package(
            output_dir=str(arguments.get("output_dir") or ""),
            case=arguments.get("case", {}),
            case_json=str(arguments.get("case_json") or ""),
            resource_classification_path=str(arguments.get("resource_classification_path") or ""),
            container_inference_path=str(arguments.get("container_inference_path") or ""),
            docker_evidence_path=str(arguments.get("docker_evidence_path") or ""),
            quality_review_path=str(arguments.get("quality_review_path") or ""),
            extra_files=[str(item) for item in arguments.get("extra_files", [])],
            notes=str(arguments.get("notes") or ""),
        )
        return proof.compact_proof_payload(payload)
    if name == "cloversec_ctf_manual_quality":
        manual = str(arguments.get("manual_markdown") or "")
        if not manual and arguments.get("manual_path"):
            manual = Path(str(arguments.get("manual_path") or "")).read_text(encoding="utf-8")
        return manual_quality.check_manual_quality(
            case=arguments.get("case", {}),
            manual_markdown=manual,
            hub_fields=arguments.get("hub_fields") if isinstance(arguments.get("hub_fields"), dict) else None,
            archive_manifest=arguments.get("archive_manifest") if isinstance(arguments.get("archive_manifest"), dict) else None,
            resource_manifest=arguments.get("resource_manifest") if isinstance(arguments.get("resource_manifest"), dict) else None,
            output_dir=str(arguments.get("output_dir") or ""),
        )
    if name == "cloversec_ctf_batch_status_report":
        cases = arguments.get("cases") if isinstance(arguments.get("cases"), list) else []
        if not cases and arguments.get("cases_path"):
            cases = data.load_cases(str(arguments.get("cases_path") or ""))
        return audit.create_batch_status_report(
            cases,
            str(arguments.get("output_dir") or ""),
            workflow_state=arguments.get("workflow_state") if isinstance(arguments.get("workflow_state"), dict) else None,
        )
    if name == "cloversec_ctf_failure_cases":
        cases = arguments.get("cases") if isinstance(arguments.get("cases"), list) else []
        if not cases and arguments.get("cases_path"):
            cases = data.load_cases(str(arguments.get("cases_path") or ""))
        return audit.create_failure_library(
            cases,
            str(arguments.get("output_path") or ""),
            extra_failures=arguments.get("extra_failures") if isinstance(arguments.get("extra_failures"), list) else None,
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
