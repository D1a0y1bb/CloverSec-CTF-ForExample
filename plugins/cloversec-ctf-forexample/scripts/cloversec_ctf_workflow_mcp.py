#!/usr/bin/env python3
"""Minimal stdio MCP server for CloverSec CTF workflow orchestration."""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any

import cloversec_ctf_audit as audit
import cloversec_ctf_container as container
import cloversec_ctf_mcp_runtime as mcp_runtime
import cloversec_ctf_resource as resource
import cloversec_ctf_workflow as workflow


SERVER_VERSION = "0.7.1"
SERVER_NAME = "cloversec-ctf-workflow"

PLATFORM_CONTRACT = {
    "schema_version": "cloversec.ctf.platform_contract.v1",
    "summary": "涉及源码、Dockerfile、compose、镜像 tar、端口服务、Web/Pwn 在线服务题或镜像构建需求时，必须使用 cloversec-ctf-build-dockerizer。",
    "must_use_skill": "cloversec-ctf-build-dockerizer",
    "trigger_resources": [
        "source",
        "Dockerfile",
        "docker-compose",
        "compose",
        "image_tar",
        "container_service",
        "web_service",
        "pwn_service",
        "port_service",
        "image_build",
    ],
    "reference_only": ["upstream Dockerfile", "docker-compose.yml", "README run command", "existing image tar"],
    "blocking_fields": {
        "confirmation_action": "dockerizer",
        "failure_category": "platform_conversion_required",
        "next_skill": "cloversec-ctf-build-dockerizer",
        "can_archive": False,
    },
    "required_artifacts": [
        "Dockerfile",
        "start.sh",
        "changeflag.sh",
        "flag",
        "environment",
        "docker_artifacts",
        "xlsx_fields",
    ],
    "required_evidence": [
        "/start.sh can start the real service",
        "/bin/bash /changeflag.sh is available",
        "/flag exists and matches flag handling",
        "Dockerfile EXPOSE and runtime port match",
        "linux/amd64 image or tar verification",
    ],
    "docker_execution_scope": "docker build/run/probe only records runtime evidence and never replaces Dockerizer platform conversion",
}

TOOLS = [
    {
        "name": "cloversec_ctf_workflow_init",
        "description": "Create a workflow run directory from year/event/category/limit with task_plan, ctf_cases.jsonl, logs, evidence, snapshots, sandbox, and next steps.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "event": {"type": "string"},
                "years": {"type": "array", "items": {"type": "integer"}},
                "categories": {"type": "array", "items": {"type": "string"}},
                "limit": {"type": "integer"},
                "out_dir": {"type": "string"},
                "allow_browser_search": {"type": "boolean"},
                "dry_run": {"type": "boolean"},
            },
            "required": ["event"],
        },
    },
    {
        "name": "cloversec_ctf_collect_execute",
        "description": "Run task_plan.search_tasks across free sources, Agent/browser visible results, direct URLs, and GitHub repos; write search_results.json, ctf_cases.jsonl, and evidence.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workdir": {"type": "string"},
                "task_plan_path": {"type": "string"},
                "max_tasks": {"type": "integer"},
                "limit": {"type": "integer"},
                "sources": {"type": "array", "items": {"type": "string"}},
                "agent_results_path": {"type": "string"},
                "browser_visible_results_path": {"type": "string"},
                "direct_urls": {"type": "array", "items": {"type": "string"}},
                "github_repos": {"type": "array", "items": {}},
                "download_preview": {"type": "boolean"},
                "fetch_snapshots": {"type": "boolean"},
            },
            "required": ["workdir"],
        },
    },
    {
        "name": "cloversec_ctf_collect_materials",
        "description": "Turn search result links into local material candidates: direct attachment download preview, GitHub release assets, repository tree preview, and failure reasons.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest_path": {"type": "string"},
                "output_dir": {"type": "string"},
                "max_direct_downloads": {"type": "integer"},
                "max_repo_previews": {"type": "integer"},
                "max_repo_files": {"type": "integer"},
                "github_ref": {"type": "string"},
                "download_direct": {"type": "boolean"},
            },
            "required": ["manifest_path", "output_dir"],
        },
    },
    {
        "name": "cloversec_ctf_resource_route",
        "description": "Classify a local material directory, infer container hints when needed, and create the next skill handoff including Dockerizer input when required.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "root": {"type": "string"},
                "output_dir": {"type": "string"},
                "max_files": {"type": "integer"},
            },
            "required": ["root"],
        },
    },
    {
        "name": "cloversec_ctf_workflow_batch",
        "description": "Preview or apply a workflow stage update with dry-run/apply, resume, and per-case state tracking.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workdir": {"type": "string"},
                "stage": {"type": "string", "enum": workflow.STAGES},
                "mode": {"type": "string", "enum": ["dry-run", "apply"]},
                "cases_path": {"type": "string"},
                "resume": {"type": "boolean"},
                "force": {"type": "boolean"},
            },
            "required": ["workdir", "stage"],
        },
    },
    {
        "name": "cloversec_ctf_workflow_run",
        "description": "Execute deterministic workflow stages with persisted evidence-backed state, resume, lock, progress, and pending-user gates.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workdir": {"type": "string"},
                "stages": {"type": "array", "items": {"type": "string", "enum": workflow.STAGES}},
                "resume": {"type": "boolean"},
                "force": {"type": "boolean"},
                "stop_on_blocked": {"type": "boolean"},
                "max_search_tasks": {"type": "integer"},
                "search_limit": {"type": "integer"},
                "sources": {"type": "array", "items": {"type": "string"}},
                "allow_download_accept": {"type": "boolean"},
                "execute_docker": {"type": "boolean"},
            },
            "required": ["workdir"],
        },
    },
    {
        "name": "cloversec_ctf_search_strategy",
        "description": "Generate category-specific search queries for CTF research.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "event": {"type": "string"},
                "years": {"type": "array", "items": {"type": "integer"}},
                "categories": {"type": "array", "items": {"type": "string"}},
                "limit": {"type": "integer"},
            },
            "required": ["event"],
        },
    },
    {
        "name": "cloversec_ctf_platform_contract",
        "description": "Return the current CloverSec container challenge platform contract summary for workflow, resource classification, and batch review.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "cloversec_ctf_github_doctor",
        "description": "Check gh auth login, token source, sample GitHub repository/code search, rate limit, failures, and available sources.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sample_query": {"type": "string"},
                "output_path": {"type": "string"},
            },
        },
    },
    {
        "name": "cloversec_ctf_source_evidence",
        "description": "Create source evidence records, confidence fields, and optional raw page snapshots from a search manifest.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest_path": {"type": "string"},
                "evidence_dir": {"type": "string"},
                "snapshots_dir": {"type": "string"},
                "limit": {"type": "integer"},
                "fetch_snapshots": {"type": "boolean"},
            },
            "required": ["manifest_path", "evidence_dir", "snapshots_dir"],
        },
    },
    {
        "name": "cloversec_ctf_dedupe_candidates",
        "description": "Group duplicate candidate challenges by event, title, category, attachment hash, writeup title, and URL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cases_path": {"type": "string"},
                "output_path": {"type": "string"},
            },
            "required": ["cases_path", "output_path"],
        },
    },
    {
        "name": "cloversec_ctf_dedupe_apply",
        "description": "Apply only human-approved duplicate merge groups and write merged ctf_cases.jsonl.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cases_path": {"type": "string"},
                "candidates_path": {"type": "string"},
                "output_path": {"type": "string"},
            },
            "required": ["cases_path", "candidates_path", "output_path"],
        },
    },
    {
        "name": "cloversec_ctf_download_sandbox",
        "description": "Download external attachment URLs into an isolated sandbox with protocol, size, filename, redirect, and archive-path preview checks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "urls": {"type": "array", "items": {"type": "string"}},
                "manifest_path": {"type": "string"},
                "output_dir": {"type": "string"},
                "accept": {"type": "boolean"},
                "max_file_size": {"type": "integer"},
                "max_redirects": {"type": "integer"},
            },
            "required": ["output_dir"],
        },
    },
    {
        "name": "cloversec_ctf_resource_classify",
        "description": "Classify local CTF resources into Docker/compose/source/attachment/writeup/screenshot/pcap/binary/database types and recommend the next skill.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "root": {"type": "string"},
                "output_path": {"type": "string"},
                "max_files": {"type": "integer"},
                "archive_preview_entries": {"type": "integer"},
            },
            "required": ["root"],
        },
    },
    {
        "name": "cloversec_ctf_container_infer",
        "description": "Infer whether a local challenge is a container challenge, extract Docker/compose runtime hints, recommend a Docker validation level, and write container_inference.json.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_dir": {"type": "string"},
                "resource_classification_path": {"type": "string"},
                "resource_classification": {"type": "object"},
                "output_path": {"type": "string"},
            },
            "required": ["project_dir"],
        },
    },
    {
        "name": "cloversec_ctf_visible_content_evidence",
        "description": "Import user-confirmed Chrome/Codex visible page content into evidence for 403/login-blocked writeup pages without bypassing controls.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "visible_content_path": {"type": "string"},
                "evidence_dir": {"type": "string"},
                "output_path": {"type": "string"},
            },
            "required": ["visible_content_path", "evidence_dir"],
        },
    },
    {
        "name": "cloversec_ctf_confirmation_request",
        "description": "Create confirmation_request.json/md before download, extract, Dockerizer conversion, Docker execution, Hub, retag, archive, or final output.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": sorted(audit.CONFIRMATION_ACTIONS)},
                "output_dir": {"type": "string"},
                "case": {"type": "object"},
                "inputs": {"type": "array", "items": {"type": "string"}},
                "planned_outputs": {"type": "array", "items": {"type": "string"}},
                "risks": {"type": "array", "items": {"type": "string"}},
                "checks": {"type": "array", "items": {"type": "string"}},
                "risk_level": {"type": "string"},
            },
            "required": ["action", "output_dir"],
        },
    },
    {
        "name": "cloversec_ctf_stage_notification",
        "description": "Create stage_notification.json/md with completed, failed, pending-user, next-input, and artifact sections.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "stage": {"type": "string"},
                "output_dir": {"type": "string"},
                "completed": {"type": "array", "items": {"type": "string"}},
                "failed": {"type": "array", "items": {"type": "string"}},
                "pending_user": {"type": "array", "items": {"type": "string"}},
                "next_inputs": {"type": "array", "items": {"type": "string"}},
                "artifacts": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["stage", "output_dir"],
        },
    },
    {
        "name": "cloversec_ctf_codex_warning_report",
        "description": "Classify codex exec warnings into CloverSec blockers, CloverSec warnings, and external plugin warnings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "log_text": {"type": "string"},
            },
            "required": ["log_text"],
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
                    "serverInfo": {"name": "cloversec-ctf-workflow", "version": SERVER_VERSION},
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
    if name == "cloversec_ctf_workflow_init":
        return compact(
            workflow.init_workflow(
                event=str(arguments.get("event") or ""),
                years=[int(item) for item in arguments.get("years", [])],
                categories=[str(item) for item in arguments.get("categories", [])],
                limit=int(arguments.get("limit", 20)),
                out_dir=str(arguments.get("out_dir") or "") or None,
                allow_browser_search=bool(arguments.get("allow_browser_search", False)),
                dry_run=bool(arguments.get("dry_run", False)),
            )
        )
    if name == "cloversec_ctf_collect_execute":
        return workflow.execute_search_tasks(
            workdir=str(arguments.get("workdir") or ""),
            task_plan_path=str(arguments.get("task_plan_path") or "") or None,
            max_tasks=int(arguments.get("max_tasks", 0)),
            limit=int(arguments.get("limit", 20)),
            sources=[str(item) for item in arguments.get("sources", [])] if isinstance(arguments.get("sources"), list) else None,
            agent_results_path=str(arguments.get("agent_results_path") or "") or None,
            browser_visible_results_path=str(arguments.get("browser_visible_results_path") or "") or None,
            direct_urls=[str(item) for item in arguments.get("direct_urls", [])] if isinstance(arguments.get("direct_urls"), list) else None,
            github_repos=arguments.get("github_repos", []) if isinstance(arguments.get("github_repos"), list) else None,
            download_preview=bool(arguments.get("download_preview", False)),
            fetch_snapshots=bool(arguments.get("fetch_snapshots", False)),
        )
    if name == "cloversec_ctf_collect_materials":
        return workflow.collect_materials(
            manifest_path=str(arguments.get("manifest_path") or ""),
            output_dir=str(arguments.get("output_dir") or ""),
            max_direct_downloads=int(arguments.get("max_direct_downloads", 10)),
            max_repo_previews=int(arguments.get("max_repo_previews", 10)),
            max_repo_files=int(arguments.get("max_repo_files", 80)),
            github_ref=str(arguments.get("github_ref") or "main"),
            download_direct=bool(arguments.get("download_direct", True)),
        )
    if name == "cloversec_ctf_resource_route":
        return workflow.route_resource(
            root=str(arguments.get("root") or ""),
            output_dir=str(arguments.get("output_dir") or "") or None,
            max_files=int(arguments.get("max_files", 2000)),
        )
    if name == "cloversec_ctf_workflow_batch":
        return workflow.batch_orchestrate(
            workdir=str(arguments.get("workdir") or ""),
            stage=str(arguments.get("stage") or ""),
            mode=str(arguments.get("mode") or "dry-run"),
            cases_path=str(arguments.get("cases_path") or "") or None,
            resume=bool(arguments.get("resume", False)),
            force=bool(arguments.get("force", False)),
        )
    if name == "cloversec_ctf_workflow_run":
        return workflow.run_workflow_engine(
            workdir=str(arguments.get("workdir") or ""),
            stages=[str(item) for item in arguments.get("stages", [])] if isinstance(arguments.get("stages"), list) else None,
            resume=bool(arguments.get("resume", True)),
            force=bool(arguments.get("force", False)),
            stop_on_blocked=bool(arguments.get("stop_on_blocked", False)),
            max_search_tasks=int(arguments.get("max_search_tasks", 0)),
            search_limit=int(arguments.get("search_limit", 20)),
            sources=[str(item) for item in arguments.get("sources", [])] if isinstance(arguments.get("sources"), list) else None,
            allow_download_accept=bool(arguments.get("allow_download_accept", False)),
            execute_docker=bool(arguments.get("execute_docker", False)),
        )
    if name == "cloversec_ctf_search_strategy":
        return {
            "queries": workflow.build_search_queries(
                event=str(arguments.get("event") or ""),
                years=[int(item) for item in arguments.get("years", [])],
                categories=[str(item) for item in arguments.get("categories", [])],
                limit=int(arguments.get("limit", 20)),
            )
        }
    if name == "cloversec_ctf_platform_contract":
        return PLATFORM_CONTRACT
    if name == "cloversec_ctf_github_doctor":
        return workflow.github_doctor(
            sample_query=str(arguments.get("sample_query") or "ctf writeup"),
            output_path=str(arguments.get("output_path") or "") or None,
        )
    if name == "cloversec_ctf_source_evidence":
        return workflow.record_source_evidence(
            manifest_path=str(arguments.get("manifest_path") or ""),
            evidence_dir=str(arguments.get("evidence_dir") or ""),
            snapshots_dir=str(arguments.get("snapshots_dir") or ""),
            limit=int(arguments.get("limit", 50)),
            fetch_snapshots=bool(arguments.get("fetch_snapshots", True)),
        )
    if name == "cloversec_ctf_dedupe_candidates":
        return workflow.dedupe_cases(
            cases_path=str(arguments.get("cases_path") or ""),
            output_path=str(arguments.get("output_path") or ""),
        )
    if name == "cloversec_ctf_dedupe_apply":
        return workflow.apply_dedupe(
            cases_path=str(arguments.get("cases_path") or ""),
            candidates_path=str(arguments.get("candidates_path") or ""),
            output_path=str(arguments.get("output_path") or ""),
        )
    if name == "cloversec_ctf_download_sandbox":
        if arguments.get("manifest_path"):
            return workflow.download_sandbox_from_manifest(
                manifest_path=str(arguments.get("manifest_path") or ""),
                output_dir=str(arguments.get("output_dir") or ""),
                accept=bool(arguments.get("accept", False)),
                max_file_size=int(arguments.get("max_file_size", workflow.DEFAULT_MAX_FILE_SIZE)),
                max_redirects=int(arguments.get("max_redirects", workflow.DEFAULT_MAX_REDIRECTS)),
            )
        return workflow.download_sandbox(
            urls=[str(item) for item in arguments.get("urls", [])],
            output_dir=str(arguments.get("output_dir") or ""),
            accept=bool(arguments.get("accept", False)),
            max_file_size=int(arguments.get("max_file_size", workflow.DEFAULT_MAX_FILE_SIZE)),
            max_redirects=int(arguments.get("max_redirects", workflow.DEFAULT_MAX_REDIRECTS)),
        )
    if name == "cloversec_ctf_resource_classify":
        payload = resource.classify_resource_root(
            root=str(arguments.get("root") or ""),
            output_path=str(arguments.get("output_path") or "") or None,
            max_files=int(arguments.get("max_files", 2000)),
            archive_preview_entries=int(arguments.get("archive_preview_entries", 200)),
        )
        return {
            "schema_version": payload.get("schema_version", ""),
            "version": payload.get("version", ""),
            "root": payload.get("root", ""),
            "root_classification": payload.get("root_classification", {}),
            "summary": payload.get("summary", {}),
            "recommendations": payload.get("recommendations", []),
            "warnings": payload.get("warnings", []),
            "output_path": str(arguments.get("output_path") or ""),
        }
    if name == "cloversec_ctf_container_infer":
        resource_input: dict[str, Any] | str = arguments.get("resource_classification", {})
        if not resource_input and arguments.get("resource_classification_path"):
            resource_input = str(arguments.get("resource_classification_path") or "")
        payload = container.infer_container_project(
            project_dir=str(arguments.get("project_dir") or ""),
            resource_classification=resource_input or None,
            output_path=str(arguments.get("output_path") or "") or None,
        )
        compact_payload = container.compact_inference(payload)
        compact_payload["output_path"] = str(arguments.get("output_path") or "")
        return compact_payload
    if name == "cloversec_ctf_visible_content_evidence":
        return workflow.import_visible_content_evidence(
            visible_content_path=str(arguments.get("visible_content_path") or ""),
            evidence_dir=str(arguments.get("evidence_dir") or ""),
            output_path=str(arguments.get("output_path") or "") or "",
        )
    if name == "cloversec_ctf_confirmation_request":
        return audit.create_confirmation_request(
            action=str(arguments.get("action") or ""),
            output_dir=str(arguments.get("output_dir") or ""),
            case=arguments.get("case") if isinstance(arguments.get("case"), dict) else {},
            inputs=[str(item) for item in arguments.get("inputs", [])] if isinstance(arguments.get("inputs"), list) else None,
            planned_outputs=[str(item) for item in arguments.get("planned_outputs", [])] if isinstance(arguments.get("planned_outputs"), list) else None,
            risks=[str(item) for item in arguments.get("risks", [])] if isinstance(arguments.get("risks"), list) else None,
            checks=[str(item) for item in arguments.get("checks", [])] if isinstance(arguments.get("checks"), list) else None,
            risk_level=str(arguments.get("risk_level") or "medium"),
        )
    if name == "cloversec_ctf_stage_notification":
        return audit.create_stage_notification(
            stage=str(arguments.get("stage") or ""),
            output_dir=str(arguments.get("output_dir") or ""),
            completed=[str(item) for item in arguments.get("completed", [])] if isinstance(arguments.get("completed"), list) else None,
            failed=[str(item) for item in arguments.get("failed", [])] if isinstance(arguments.get("failed"), list) else None,
            pending_user=[str(item) for item in arguments.get("pending_user", [])] if isinstance(arguments.get("pending_user"), list) else None,
            next_inputs=[str(item) for item in arguments.get("next_inputs", [])] if isinstance(arguments.get("next_inputs"), list) else None,
            artifacts=[str(item) for item in arguments.get("artifacts", [])] if isinstance(arguments.get("artifacts"), list) else None,
        )
    if name == "cloversec_ctf_codex_warning_report":
        return audit.classify_codex_warnings(str(arguments.get("log_text") or ""))
    raise ValueError(f"unknown tool: {name}")


def compact(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": payload.get("schema_version", ""),
        "dry_run": payload.get("dry_run", False),
        "workdir": payload.get("workdir", ""),
        "created_files": payload.get("created_files", []),
        "search_task_count": len(payload.get("task_plan", {}).get("search_tasks", [])),
        "next_steps": payload.get("task_plan", {}).get("next_steps", []),
    }


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
