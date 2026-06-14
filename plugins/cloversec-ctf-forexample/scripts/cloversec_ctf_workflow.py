#!/usr/bin/env python3
"""Workflow, evidence, GitHub, dedupe, and download-sandbox helpers for CloverSec CTF."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

import cloversec_ctf_data as data
import cloversec_ctf_container as container
import cloversec_ctf_resource as resource
import cloversec_ctf_search as search
import cloversec_ctf_search_plus as search_plus


SCHEMA_PREFIX = "cloversec.ctf.workflow"
WORKFLOW_VERSION = "0.4.1"
SCRIPT_DIR = Path(__file__).resolve().parent
PLUGIN_ROOT = SCRIPT_DIR.parent
REFERENCES = PLUGIN_ROOT / "references"
SEARCH_STRATEGIES = REFERENCES / "search-strategies.json"

STAGES = [
    "research",
    "collect",
    "dedupe",
    "download_preview",
    "download_accept",
    "archive",
    "quality",
    "hub_prepare",
    "final_report",
]

WORKFLOW_DIRS = [
    "logs",
    "evidence",
    "snapshots",
    "downloads_sandbox",
    "downloads_accepted",
    "classification",
    "reports",
]

DEFAULT_MAX_FILE_SIZE = 300 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_UNPACKED = 1500 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_FILES = 5000
DEFAULT_MAX_REDIRECTS = 5
ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def utc_date() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def safe_slug(value: str, *, fallback: str = "ctf") -> str:
    cleaned = re.sub(r"[^0-9A-Za-z\u4e00-\u9fff._-]+", "-", value.strip())
    cleaned = re.sub(r"-{2,}", "-", cleaned).strip(".-_")
    return cleaned[:100] or fallback


def parse_csv(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        raw = []
        for item in value:
            raw.extend(parse_csv(item))
        return raw
    return [item.strip() for item in re.split(r"[,，/|]", str(value)) if item.strip()]


def parse_years(value: str | list[int] | list[str] | int | None) -> list[int]:
    if value is None:
        return []
    if isinstance(value, int):
        return [value]
    if isinstance(value, list):
        years: list[int] = []
        for item in value:
            years.extend(parse_years(item))
        return sorted(set(years))
    years = []
    for item in re.split(r"[,，/| ]+", str(value)):
        if not item:
            continue
        years.append(int(item))
    return sorted(set(years))


def load_search_strategies(path: str | Path = SEARCH_STRATEGIES) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def canonical_category(category: str, strategies: dict[str, Any] | None = None) -> str:
    strategies = strategies or load_search_strategies()
    lowered = category.strip().lower()
    categories = strategies.get("categories") if isinstance(strategies.get("categories"), dict) else {}
    for name, config in categories.items():
        aliases = [str(item).lower() for item in config.get("aliases", [])] if isinstance(config, dict) else []
        if lowered == name.lower() or lowered in aliases:
            return str(name)
    return lowered or "general"


def build_search_queries(
    *,
    event: str,
    years: list[int],
    categories: list[str],
    limit: int = 20,
    challenge: str = "",
    strategies_path: str | Path = SEARCH_STRATEGIES,
) -> list[dict[str, Any]]:
    strategies = load_search_strategies(strategies_path)
    defaults = strategies.get("defaults") if isinstance(strategies.get("defaults"), dict) else {}
    default_templates = [str(item) for item in defaults.get("templates", [])]
    category_configs = strategies.get("categories") if isinstance(strategies.get("categories"), dict) else {}
    years = years or [datetime.now().year]
    categories = categories or ["general"]
    queries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_category in categories:
        category = canonical_category(raw_category, strategies)
        config = category_configs.get(category, {}) if isinstance(category_configs.get(category), dict) else {}
        templates = [str(item) for item in config.get("templates", [])] or default_templates
        if not templates:
            templates = ["{event} {year} {category} CTF writeup"]
        for year in years:
            for template in templates:
                query = template.format(event=event, year=year, category=category, challenge=challenge).strip()
                query = re.sub(r"\s+", " ", query)
                key = query.lower()
                if not query or key in seen:
                    continue
                seen.add(key)
                queries.append(
                    {
                        "query_id": f"q-{len(queries)+1:04d}",
                        "query": query,
                        "year": year,
                        "category": category,
                        "source_hint": "strategy-library",
                        "expected_layers": ["confirmed_challenge", "writeup_candidate", "attachment_candidate"],
                    }
                )
                if len(queries) >= max(limit, 1) * max(len(categories), 1):
                    return queries
    return queries


def default_workdir(event: str, years: list[int], categories: list[str]) -> Path:
    date_prefix = datetime.now().strftime("%Y%m%d")
    years_part = "-".join(str(year) for year in years) if years else str(datetime.now().year)
    category_part = "-".join(safe_slug(item) for item in categories) if categories else "general"
    return Path("runs") / safe_slug(f"{date_prefix}-{years_part}-{event}-{category_part}")


def init_workflow(
    *,
    event: str,
    years: list[int],
    categories: list[str],
    limit: int,
    out_dir: str | Path | None = None,
    allow_browser_search: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    years = years or [datetime.now().year]
    categories = categories or ["general"]
    workdir = Path(out_dir) if out_dir else default_workdir(event, years, categories)
    queries = build_search_queries(event=event, years=years, categories=categories, limit=limit)
    run_id = safe_slug(workdir.name)
    directories = {name: (workdir / name).as_posix() for name in WORKFLOW_DIRS}
    task_plan = {
        "schema_version": f"{SCHEMA_PREFIX}.task_plan.v1",
        "workflow_version": WORKFLOW_VERSION,
        "run_id": run_id,
        "created_at": utc_now(),
        "request": {
            "event": event,
            "years": years,
            "categories": [canonical_category(item) for item in categories],
            "limit": limit,
            "allow_browser_search": allow_browser_search,
        },
        "workdir": workdir.as_posix(),
        "directories": directories,
        "search_tasks": queries,
        "next_steps": [
            "先运行 GitHub 配置向导，确认 gh auth login 或 token 可用。",
            "按 search_tasks 执行 search-plus，结果写入 evidence/ 和 ctf_cases.jsonl。",
            "对直接附件 URL 使用 downloads_sandbox 做安全预览。",
            "对下载或用户提供的资源目录运行 resource classify，生成 resource_classification.json。",
            "对重复候选执行 dedupe，人工确认后再合并字段。",
        ],
    }
    workflow_state = initial_workflow_state(run_id, event, years, categories, limit, workdir)
    output = {
        "schema_version": f"{SCHEMA_PREFIX}.init_result.v1",
        "dry_run": dry_run,
        "workdir": workdir.as_posix(),
        "task_plan": task_plan,
        "workflow_state": workflow_state,
        "created_files": [],
    }
    if dry_run:
        return output

    workdir.mkdir(parents=True, exist_ok=True)
    for directory in directories.values():
        Path(directory).mkdir(parents=True, exist_ok=True)
    write_json(workdir / "task_plan.json", task_plan)
    write_json(workdir / "workflow_state.json", workflow_state)
    write_jsonl(workdir / "ctf_cases.jsonl", [])
    (workdir / "next_steps.md").write_text(render_next_steps(task_plan), encoding="utf-8")
    append_log(workdir, "workflow initialized")
    output["created_files"] = [
        (workdir / "task_plan.json").as_posix(),
        (workdir / "workflow_state.json").as_posix(),
        (workdir / "ctf_cases.jsonl").as_posix(),
        (workdir / "next_steps.md").as_posix(),
    ] + list(directories.values())
    return output


def execute_search_tasks(
    *,
    workdir: str | Path,
    task_plan_path: str | Path | None = None,
    max_tasks: int = 0,
    limit: int = 20,
    sources: list[str] | None = None,
    agent_results_path: str | Path | None = None,
    browser_visible_results_path: str | Path | None = None,
    direct_urls: list[str] | None = None,
    github_repos: list[Any] | None = None,
    download_preview: bool = False,
    fetch_snapshots: bool = False,
) -> dict[str, Any]:
    """Run task_plan.search_tasks and write usable cases/evidence files."""
    base = Path(workdir)
    plan_path = Path(task_plan_path) if task_plan_path else base / "task_plan.json"
    plan = read_json(plan_path)
    request = plan.get("request") if isinstance(plan.get("request"), dict) else {}
    tasks = [item for item in plan.get("search_tasks", []) if isinstance(item, dict)]
    if max_tasks > 0:
        tasks = tasks[:max_tasks]
    if not tasks:
        raise ValueError("task_plan.search_tasks is empty")

    base.mkdir(parents=True, exist_ok=True)
    search_dir = base / "evidence" / "search"
    search_dir.mkdir(parents=True, exist_ok=True)
    (base / "snapshots").mkdir(parents=True, exist_ok=True)
    (base / "evidence").mkdir(parents=True, exist_ok=True)

    agent_results = read_json(agent_results_path) if agent_results_path else None
    browser_visible_results = read_json(browser_visible_results_path) if browser_visible_results_path else None
    selected_sources = sources or None
    all_results: list[dict[str, Any]] = []
    all_errors: list[dict[str, Any]] = []
    query_outputs: list[dict[str, Any]] = []

    for index, task in enumerate(tasks, start=1):
        query = str(task.get("query") or "").strip()
        if not query:
            continue
        year = task.get("year")
        years = [int(year)] if isinstance(year, int) or str(year).isdigit() else []
        query_id = str(task.get("query_id") or f"q-{index:04d}")
        output_path = search_dir / f"{safe_slug(query_id)}.json"
        payload = search_plus.search_plus(
            query,
            years=years,
            sources=selected_sources,
            limit=limit,
            agent_results=agent_results,
            browser_visible_results=browser_visible_results,
            direct_urls=direct_urls or [],
            github_repos=github_repos or [],
            output_path=output_path,
            compact=False,
        )
        all_results.extend([item for item in payload.get("results", []) if isinstance(item, dict)])
        all_errors.extend([item for item in payload.get("errors", []) if isinstance(item, dict)])
        query_outputs.append(
            {
                "query_id": query_id,
                "query": query,
                "output_path": output_path.as_posix(),
                "summary": payload.get("summary", {}),
                "decision_required": payload.get("decision_required", []),
            }
        )

    aggregate_query = aggregate_query_from_request(request, tasks)
    aggregate_years = [int(item) for item in request.get("years", []) if str(item).isdigit()]
    ranked = search.rank_results(search.enrich_results(search.dedupe_results(all_results), query=aggregate_query, years=aggregate_years))
    case_limit = int(request.get("limit") or 0)
    case_results = [
        item for item in ranked
        if item.get("layer") in {"confirmed_challenge", "writeup_candidate", "attachment_candidate"}
    ]
    cases = search.results_to_cases({"query": aggregate_query, "years": aggregate_years, "results": case_results})
    if case_limit > 0:
        cases = cases[:case_limit]
    search_results_path = base / "search_results.json"
    aggregate = {
        "schema_version": f"{SCHEMA_PREFIX}.collect_execute.v1",
        "workflow_version": WORKFLOW_VERSION,
        "generated_at": utc_now(),
        "workdir": base.as_posix(),
        "task_plan_path": plan_path.as_posix(),
        "query": aggregate_query,
        "years": aggregate_years,
        "sources": selected_sources or search.DEFAULT_DISCOVER_SOURCES,
        "query_outputs": query_outputs,
        "results": ranked,
        "errors": all_errors,
        "summary": {
            "search_tasks": len(query_outputs),
            "results": len(ranked),
            "cases": len(cases),
            "case_candidate_results": len(case_results),
            "errors": len(all_errors),
            "provider_counts": search.provider_counts(ranked),
            "layer_counts": search.layer_counts(ranked),
        },
        "next_files": {
            "cases": (base / "ctf_cases.jsonl").as_posix(),
            "evidence": (base / "evidence" / "source_evidence.json").as_posix(),
            "download_preview": (base / "download_preview.json").as_posix(),
        },
    }
    write_json(search_results_path, aggregate)
    write_jsonl(base / "ctf_cases.jsonl", cases)
    evidence = record_source_evidence(
        manifest_path=search_results_path,
        evidence_dir=base / "evidence",
        snapshots_dir=base / "snapshots",
        limit=max(len(ranked), 1),
        fetch_snapshots=fetch_snapshots,
    )
    download_payload: dict[str, Any] = {}
    if download_preview:
        download_payload = download_sandbox_from_manifest(manifest_path=search_results_path, output_dir=base, accept=False)
    update_workflow_collect_state(
        base,
        stage="research",
        status="completed" if cases else "pending_user",
        summary={
            "search_tasks": len(query_outputs),
            "results": len(ranked),
            "cases": len(cases),
            "evidence_records": evidence.get("summary", {}).get("records", 0),
            "download_preview_records": download_payload.get("summary", {}).get("total", 0) if download_payload else 0,
        },
        errors=all_errors,
    )
    append_log(base, f"executed {len(query_outputs)} search tasks and wrote {len(cases)} cases")
    return {
        "schema_version": f"{SCHEMA_PREFIX}.collect_execute_result.v1",
        "workdir": base.as_posix(),
        "search_results_path": search_results_path.as_posix(),
        "ctf_cases_path": (base / "ctf_cases.jsonl").as_posix(),
        "source_evidence_path": (base / "evidence" / "source_evidence.json").as_posix(),
        "download_preview_path": (base / "download_preview.json").as_posix() if download_preview else "",
        "query_outputs": query_outputs,
        "summary": aggregate["summary"],
        "next_action": "查看 ctf_cases.jsonl，随后对可下载候选执行 collect-materials 或把本地材料目录交给 route-resource。",
    }


def collect_materials(
    *,
    manifest_path: str | Path,
    output_dir: str | Path,
    max_direct_downloads: int = 10,
    max_repo_previews: int = 10,
    max_repo_files: int = 80,
    github_ref: str = "main",
    download_direct: bool = True,
) -> dict[str, Any]:
    """Turn search links into local previews/download candidates."""
    manifest = read_json(manifest_path)
    results = [item for item in manifest.get("results", []) if isinstance(item, dict)] if isinstance(manifest, dict) else []
    base = Path(output_dir)
    base.mkdir(parents=True, exist_ok=True)
    candidate_dir = base / "materials"
    candidate_dir.mkdir(parents=True, exist_ok=True)

    direct_urls = direct_asset_urls_from_results(results)[: max(max_direct_downloads, 0)]
    repos = github_repos_from_results(results)[: max(max_repo_previews, 0)]
    download_payload: dict[str, Any] = {}
    if download_direct and direct_urls:
        download_payload = download_sandbox(urls=direct_urls, output_dir=base, accept=False)

    repo_previews = []
    repo_errors = []
    for repo in repos:
        release_assets = []
        tree_files = []
        github_ref_used = github_ref
        try:
            release_assets = search.github_release_assets(repo, limit=30)
        except Exception as exc:  # noqa: BLE001
            repo_errors.append({"repo": repo, "provider": "github-release", "error": str(exc)})
        tree_error = ""
        for ref in dict.fromkeys([github_ref, "master"]):
            try:
                tree_files = search.github_tree_files(repo, ref=ref, limit=max_repo_files)
                if tree_files:
                    github_ref_used = ref
                    break
            except Exception as exc:  # noqa: BLE001
                tree_error = str(exc)
                github_ref_used = ref
        if tree_error and not tree_files:
            repo_errors.append({"repo": repo, "provider": "github-tree", "error": tree_error})
        repo_previews.append(
            {
                "repo": repo,
                "ref": github_ref_used if tree_files else github_ref,
                "release_assets": release_assets,
                "tree_files": tree_files,
                "summary": {
                    "release_assets": len(release_assets),
                    "tree_files": len(tree_files),
                    "docker_hints": github_tree_docker_hints(tree_files),
                    "attachment_hints": github_tree_attachment_hints(tree_files),
                },
            }
        )

    payload = {
        "schema_version": f"{SCHEMA_PREFIX}.material_collection.v1",
        "workflow_version": WORKFLOW_VERSION,
        "generated_at": utc_now(),
        "manifest_path": Path(manifest_path).as_posix(),
        "output_dir": base.as_posix(),
        "direct_asset_urls": direct_urls,
        "github_repositories": repos,
        "download_preview_path": (base / "download_preview.json").as_posix() if download_payload else "",
        "download_preview_summary": download_payload.get("summary", {}) if download_payload else {},
        "repo_previews": repo_previews,
        "errors": repo_errors,
        "summary": {
            "direct_asset_urls": len(direct_urls),
            "github_repositories": len(repos),
            "downloaded_or_previewed": download_payload.get("summary", {}).get("total", 0) if download_payload else 0,
            "repo_errors": len(repo_errors),
        },
        "next_action": "下载成功或仓库预览可用后，把材料目录交给 route-resource 自动分流。",
    }
    write_json(base / "material_candidates.json", payload)
    write_text(base / "material_collection_report.md", render_material_collection_report(payload))
    return payload


def route_resource(
    *,
    root: str | Path,
    output_dir: str | Path | None = None,
    max_files: int = 2000,
) -> dict[str, Any]:
    """Classify a local challenge/material directory and prepare the next handoff."""
    source_root = Path(root)
    base = Path(output_dir) if output_dir else source_root / "classification"
    base.mkdir(parents=True, exist_ok=True)
    classification_path = base / "resource_classification.json"
    classification = resource.classify_resource_root(source_root, output_path=classification_path, max_files=max_files)
    container_payload: dict[str, Any] = {}
    container_path = base / "container_inference.json"
    if should_infer_container(classification):
        container_payload = container.infer_container_project(
            project_dir=source_root,
            resource_classification=classification,
            output_path=container_path,
        )
    route = build_resource_route(source_root, classification, container_payload, classification_path, container_path if container_payload else None)
    route_path = base / "resource_route.json"
    write_json(route_path, route)
    write_text(base / "resource_route_report.md", render_resource_route_report(route))
    return {
        "schema_version": f"{SCHEMA_PREFIX}.resource_route_result.v1",
        "root": source_root.as_posix(),
        "output_dir": base.as_posix(),
        "resource_classification_path": classification_path.as_posix(),
        "container_inference_path": container_path.as_posix() if container_payload else "",
        "resource_route_path": route_path.as_posix(),
        "recommended_next": route.get("recommended_next", {}),
        "dockerizer_handoff": route.get("dockerizer_handoff", {}),
        "summary": route.get("summary", {}),
    }


def aggregate_query_from_request(request: dict[str, Any], tasks: list[dict[str, Any]]) -> str:
    event = str(request.get("event") or "").strip()
    years = " ".join(str(item) for item in request.get("years", []) if str(item).strip())
    categories = " ".join(str(item) for item in request.get("categories", []) if str(item).strip())
    if event or years or categories:
        return re.sub(r"\s+", " ", f"{event} {years} {categories} CTF writeup attachment source").strip()
    first_query = next((str(item.get("query") or "") for item in tasks if item.get("query")), "")
    return first_query or "CTF writeup attachment source"


def update_workflow_collect_state(
    workdir: Path,
    *,
    stage: str,
    status: str,
    summary: dict[str, Any],
    errors: list[dict[str, Any]],
) -> None:
    state_path = workdir / "workflow_state.json"
    if not state_path.exists():
        return
    state = read_json(state_path)
    stages = state.setdefault("stages", {})
    stages[stage] = {
        "status": status,
        "started_at": stages.get(stage, {}).get("started_at") or utc_now(),
        "finished_at": utc_now(),
        "summary": summary,
        "errors": errors[:20],
    }
    state["status"] = "in_progress" if status in {"completed", "pending_user"} else status
    state["updated_at"] = utc_now()
    write_json(state_path, state)


def direct_asset_urls_from_results(results: list[dict[str, Any]]) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for result in results:
        metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
        candidates = [
            str(result.get("url") or ""),
            str(result.get("source_url") or ""),
            str(metadata.get("raw_url") or ""),
            str(metadata.get("download_url") or ""),
        ]
        for url in candidates:
            clean = url.strip()
            if not clean or clean in seen or not search.looks_direct_asset_url(clean):
                continue
            seen.add(clean)
            urls.append(clean)
    return urls


def github_repos_from_results(results: list[dict[str, Any]]) -> list[str]:
    repos: list[str] = []
    seen: set[str] = set()
    for result in results:
        metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
        candidates = [str(metadata.get("repository") or ""), str(result.get("url") or ""), str(result.get("source_url") or "")]
        for candidate in candidates:
            repo = github_repo_from_value(candidate)
            if repo and repo not in seen:
                seen.add(repo)
                repos.append(repo)
    return repos


def github_repo_from_value(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        owner, repo = search.parse_github_repo(text)
        return f"{owner}/{repo}"
    except Exception:  # noqa: BLE001
        return ""


def github_tree_docker_hints(tree_files: list[dict[str, Any]]) -> list[str]:
    hints = []
    for item in tree_files:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        path = str(metadata.get("path") or item.get("title") or "")
        lower = path.lower()
        if lower.endswith("dockerfile") or "docker-compose" in lower or lower.endswith(("compose.yml", "compose.yaml")):
            hints.append(path)
    return hints[:20]


def github_tree_attachment_hints(tree_files: list[dict[str, Any]]) -> list[str]:
    hints = []
    for item in tree_files:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        path = str(metadata.get("path") or item.get("title") or "")
        if search.looks_direct_asset_url(path):
            hints.append(path)
    return hints[:20]


def should_infer_container(classification: dict[str, Any]) -> bool:
    if classification.get("must_use_dockerizer") or classification.get("platform_contract_required"):
        return True
    types = set(resource_types_from_classification(classification))
    return bool(types & {"dockerfile", "compose_file", "docker_helper", "source_manifest", "source_file", "source_archive", "docker_image_tar"})


def resource_types_from_classification(classification: dict[str, Any]) -> list[str]:
    resources = classification.get("resources") if isinstance(classification.get("resources"), list) else []
    return [str(item.get("resource_type") or "") for item in resources if isinstance(item, dict)]


def build_resource_route(
    root: Path,
    classification: dict[str, Any],
    container_payload: dict[str, Any],
    classification_path: Path,
    container_path: Path | None,
) -> dict[str, Any]:
    root_classification = classification.get("root_classification") if isinstance(classification.get("root_classification"), dict) else {}
    project_type = str(root_classification.get("project_type") or "")
    types = resource_types_from_classification(classification)
    next_skill = str(root_classification.get("recommended_next_skill") or "")
    recommended_next = {
        "scenario": "manual_review",
        "skill": next_skill or "cloversec-ctf-asset-collector",
        "reason": "资源类型不够明确，需要人工确认。",
    }
    dockerizer_handoff: dict[str, Any] = {}
    if classification.get("must_use_dockerizer") or (container_payload and container_payload.get("must_use_dockerizer")):
        recommended_next = {
            "scenario": "platform_dockerizer",
            "skill": "cloversec-ctf-build-dockerizer",
            "reason": "检测到源码、Dockerfile、compose、镜像 tar 或服务型题目，必须进入 CloverSec 平台镜像改造。",
        }
        dockerizer_handoff = {
            "schema_version": f"{SCHEMA_PREFIX}.dockerizer_handoff.v1",
            "required_skill": "cloversec-ctf-build-dockerizer",
            "project_dir": root.as_posix(),
            "resource_classification_path": classification_path.as_posix(),
            "container_inference_path": container_path.as_posix() if container_path else "",
            "existing_docker_is_reference_only": True,
            "confirmation_action": "dockerizer",
            "failure_category": "platform_conversion_required",
            "can_archive": False,
            "input_prompt": (
                f"使用 cloversec-ctf-build-dockerizer 处理 {root.as_posix()}。"
                f"先读取 {classification_path.as_posix()}"
                + (f" 和 {container_path.as_posix()}" if container_path else "")
                + "，把已有 Dockerfile/compose/启动说明作为迁移输入，先给方案，等用户确认后再写平台交付文件。"
            ),
        }
    elif any(item in types for item in ["source_archive", "binary", "pcap", "database_dump", "vm_image"]):
        recommended_next = {
            "scenario": "attachment_packaging",
            "skill": "cloversec-ctf-attachment-packager",
            "reason": "更像附件题或离线材料，先做解压、hash、风险路径和清单检查。",
        }
    elif any(item in types for item in ["writeup", "screenshot", "note"]):
        recommended_next = {
            "scenario": "writeup_or_manual",
            "skill": "cloversec-ctf-writeup-scaffold",
            "reason": "材料主要是手册、题解或截图，适合生成手册和录题字段。",
        }
    elif project_type == "empty_or_missing":
        recommended_next = {
            "scenario": "missing_material",
            "skill": "cloversec-ctf-research-intake",
            "reason": "目录里没有可用题目材料，需要继续采集或让用户提供入口。",
        }

    return {
        "schema_version": f"{SCHEMA_PREFIX}.resource_route.v1",
        "workflow_version": WORKFLOW_VERSION,
        "generated_at": utc_now(),
        "root": root.as_posix(),
        "summary": {
            "project_type": project_type,
            "resource_types": dict(sorted((classification.get("summary", {}).get("by_resource_type") or {}).items())),
            "must_use_dockerizer": bool(classification.get("must_use_dockerizer") or container_payload.get("must_use_dockerizer")),
            "has_container_inference": bool(container_payload),
        },
        "recommended_next": recommended_next,
        "dockerizer_handoff": dockerizer_handoff,
        "resource_classification_path": classification_path.as_posix(),
        "container_inference_path": container_path.as_posix() if container_path else "",
        "notes": [
            "已有 Dockerfile、compose 或镜像 tar 只能作为迁移输入。",
            "涉及容器题时，最终平台交付必须经过 cloversec-ctf-build-dockerizer。",
        ]
        if dockerizer_handoff
        else [],
    }


def render_material_collection_report(payload: dict[str, Any]) -> str:
    lines = [
        "# 材料收集报告",
        "",
        f"- 直接附件链接：{len(payload.get('direct_asset_urls', []))}",
        f"- GitHub 仓库：{len(payload.get('github_repositories', []))}",
        f"- 下载预览：{payload.get('download_preview_path') or '无'}",
        "",
        "## GitHub 仓库预览",
        "",
    ]
    for repo in payload.get("repo_previews", []):
        if not isinstance(repo, dict):
            continue
        summary = repo.get("summary", {}) if isinstance(repo.get("summary"), dict) else {}
        lines.append(f"- {repo.get('repo')}: Release 附件 {summary.get('release_assets', 0)} 个，文件预览 {summary.get('tree_files', 0)} 个")
        docker_hints = summary.get("docker_hints", []) if isinstance(summary.get("docker_hints"), list) else []
        if docker_hints:
            lines.append(f"  - Docker 线索：{', '.join(str(item) for item in docker_hints[:5])}")
    if payload.get("errors"):
        lines.extend(["", "## 失败原因", ""])
        for item in payload["errors"]:
            lines.append(f"- {item.get('repo', '')} {item.get('provider', '')}: {item.get('error', '')}")
    return "\n".join(lines) + "\n"


def render_resource_route_report(route: dict[str, Any]) -> str:
    recommended = route.get("recommended_next", {}) if isinstance(route.get("recommended_next"), dict) else {}
    lines = [
        "# 资源分流报告",
        "",
        f"- 目录：`{route.get('root', '')}`",
        f"- 推荐下一步：`{recommended.get('skill', '')}`",
        f"- 场景：`{recommended.get('scenario', '')}`",
        f"- 原因：{recommended.get('reason', '')}",
        "",
    ]
    handoff = route.get("dockerizer_handoff") if isinstance(route.get("dockerizer_handoff"), dict) else {}
    if handoff:
        lines.extend(
            [
                "## Dockerizer 输入",
                "",
                f"- 题目目录：`{handoff.get('project_dir', '')}`",
                f"- 资源识别：`{handoff.get('resource_classification_path', '')}`",
                f"- 容器推断：`{handoff.get('container_inference_path', '')}`",
                "",
                handoff.get("input_prompt", ""),
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def initial_workflow_state(
    run_id: str,
    event: str,
    years: list[int],
    categories: list[str],
    limit: int,
    workdir: Path,
) -> dict[str, Any]:
    return {
        "schema_version": f"{SCHEMA_PREFIX}.state.v1",
        "workflow_version": WORKFLOW_VERSION,
        "run_id": run_id,
        "status": "initialized",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "workdir": workdir.as_posix(),
        "request": {
            "event": event,
            "years": years,
            "categories": [canonical_category(item) for item in categories],
            "limit": limit,
        },
        "stages": {
            stage: {
                "status": "pending",
                "started_at": "",
                "finished_at": "",
                "summary": {},
                "errors": [],
            }
            for stage in STAGES
        },
        "cases": [],
        "resume": {"last_stage": "", "last_case_id": "", "can_resume": True},
    }


def render_next_steps(task_plan: dict[str, Any]) -> str:
    lines = [
        "# CloverSec CTF Workflow Next Steps",
        "",
        f"- run_id: `{task_plan.get('run_id', '')}`",
        f"- workdir: `{task_plan.get('workdir', '')}`",
        "",
        "## 推荐顺序",
        "",
    ]
    lines.extend(f"- {item}" for item in task_plan.get("next_steps", []))
    lines.extend(["", "## 搜索任务", ""])
    for task in task_plan.get("search_tasks", []):
        lines.append(f"- [{task.get('query_id')}] {task.get('query')}")
    return "\n".join(lines) + "\n"


def batch_orchestrate(
    *,
    workdir: str | Path,
    stage: str,
    mode: str = "dry-run",
    cases_path: str | Path | None = None,
    resume: bool = False,
) -> dict[str, Any]:
    if stage not in STAGES:
        raise ValueError(f"unsupported stage: {stage}")
    if mode not in {"dry-run", "apply"}:
        raise ValueError("mode must be dry-run or apply")
    base = Path(workdir)
    state_path = base / "workflow_state.json"
    state = read_json(state_path) if state_path.exists() else initial_workflow_state(base.name, "", [], [], 0, base)
    cases_file = Path(cases_path) if cases_path else base / "ctf_cases.jsonl"
    cases = data.load_cases(cases_file) if cases_file.exists() else []
    case_ids = [str(case.get("case_id") or f"case-{index:06d}") for index, case in enumerate(cases, start=1)]
    skipped = []
    planned = []
    completed = []
    errors: list[dict[str, Any]] = []
    existing_cases = {item.get("case_id"): item for item in state.get("cases", []) if isinstance(item, dict)}

    for case_id in case_ids:
        case_state = existing_cases.get(case_id, {"case_id": case_id, "stages": {}})
        stage_state = case_state.setdefault("stages", {}).get(stage, {})
        if resume and stage_state.get("status") == "completed":
            skipped.append(case_id)
            existing_cases[case_id] = case_state
            continue
        planned.append(case_id)
        if mode == "apply":
            case_state["stages"][stage] = {
                "status": "completed",
                "started_at": utc_now(),
                "finished_at": utc_now(),
                "evidence_path": "",
                "errors": [],
            }
            completed.append(case_id)
        else:
            case_state["stages"][stage] = {
                "status": "planned",
                "planned_at": utc_now(),
                "errors": [],
            }
        existing_cases[case_id] = case_state

    state["cases"] = list(existing_cases.values())
    state["updated_at"] = utc_now()
    state["resume"] = {"last_stage": stage, "last_case_id": completed[-1] if completed else "", "can_resume": True}
    state["stages"][stage] = {
        "status": "completed" if mode == "apply" else "planned",
        "started_at": utc_now(),
        "finished_at": utc_now() if mode == "apply" else "",
        "summary": {"planned": len(planned), "completed": len(completed), "skipped": len(skipped)},
        "errors": errors,
    }
    result = {
        "schema_version": f"{SCHEMA_PREFIX}.batch_result.v1",
        "mode": mode,
        "stage": stage,
        "workdir": base.as_posix(),
        "cases_path": cases_file.as_posix(),
        "planned": planned,
        "completed": completed,
        "skipped": skipped,
        "errors": errors,
        "workflow_state_path": state_path.as_posix(),
    }
    if mode == "apply":
        base.mkdir(parents=True, exist_ok=True)
        write_json(state_path, state)
        append_log(base, f"stage {stage} applied for {len(completed)} cases")
    else:
        result["dry_run_note"] = "No workflow_state.json changes were written."
    return result


def github_doctor(*, sample_query: str = "ctf writeup", output_path: str | Path | None = None) -> dict[str, Any]:
    gh_path = shutil.which("gh")
    env_token = "GITHUB_TOKEN" if os.environ.get("GITHUB_TOKEN") else ("GH_TOKEN" if os.environ.get("GH_TOKEN") else "")
    report: dict[str, Any] = {
        "schema_version": f"{SCHEMA_PREFIX}.github_doctor.v1",
        "generated_at": utc_now(),
        "gh_cli": "available" if gh_path else "missing",
        "gh_path": gh_path or "",
        "token_source": env_token,
        "auth": "unknown",
        "checks": [],
        "available_sources": [],
        "next_actions": [],
    }

    if gh_path:
        auth_status = run_command(["gh", "auth", "status"])
        report["checks"].append(command_check("gh auth status", auth_status))
        report["auth"] = "ok" if auth_status["returncode"] == 0 else "failed"
        token_result = run_command(["gh", "auth", "token"])
        if token_result["returncode"] == 0 and token_result["stdout"].strip():
            report["token_source"] = report["token_source"] or "gh auth token"
        report["checks"].append({**command_check("gh auth token", token_result), "stdout": mask_secret(token_result["stdout"])})

        repo_result = run_command(
            ["gh", "api", "--method", "GET", "/search/repositories", "-f", f"q={sample_query}", "-f", "per_page=1"],
            timeout=15,
        )
        report["checks"].append(command_check("github repository search", repo_result))
        if repo_result["returncode"] == 0:
            report["available_sources"].append("github-repository-search")

        code_result = run_command(
            ["gh", "api", "--method", "GET", "/search/code", "-f", f"q={sample_query} filename:README", "-f", "per_page=1"],
            timeout=15,
        )
        report["checks"].append(command_check("github code search", code_result))
        if code_result["returncode"] == 0:
            report["available_sources"].append("github-code-search")

        rate_result = run_command(["gh", "api", "rate_limit"], timeout=15)
        report["checks"].append(command_check("github rate_limit", rate_result))
        if rate_result["returncode"] == 0:
            report["rate_limit"] = parse_rate_limit(rate_result["stdout"])
    elif env_token:
        report["available_sources"].append("github-token-env")
        report["next_actions"].append("gh CLI missing, but environment token exists. Plugin can still use GitHub HTTP API in search helpers.")
    else:
        report["auth"] = "missing"
        report["next_actions"].append("Run `gh auth login` to enable GitHub repository and code search.")

    if not report["available_sources"]:
        report["next_actions"].append("GitHub-backed search is not currently usable; default free web sources can still run.")
    if output_path:
        write_json(output_path, report)
    return report


def run_command(command: list[str], *, timeout: int = 10) -> dict[str, Any]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
        return {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    except FileNotFoundError:
        return {"returncode": 127, "stdout": "", "stderr": "command not found"}
    except subprocess.TimeoutExpired as exc:
        return {"returncode": 124, "stdout": exc.stdout or "", "stderr": "command timed out"}


def command_check(name: str, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "status": "ok" if result.get("returncode") == 0 else "failed",
        "returncode": result.get("returncode"),
        "stderr": str(result.get("stderr") or "").strip()[:500],
    }


def mask_secret(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) <= 8:
        return "***"
    return text[:4] + "***" + text[-4:]


def parse_rate_limit(text: str) -> dict[str, Any]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {"parse_error": "invalid JSON"}
    resources = payload.get("resources") if isinstance(payload, dict) else {}
    output = {}
    for name in ["core", "search", "graphql"]:
        item = resources.get(name) if isinstance(resources, dict) else None
        if isinstance(item, dict):
            output[name] = {
                "limit": item.get("limit"),
                "remaining": item.get("remaining"),
                "reset": item.get("reset"),
                "used": item.get("used"),
            }
    return output


def record_source_evidence(
    *,
    manifest_path: str | Path,
    evidence_dir: str | Path,
    snapshots_dir: str | Path,
    limit: int = 50,
    fetch_snapshots: bool = True,
) -> dict[str, Any]:
    manifest = read_json(manifest_path)
    results = manifest.get("results", []) if isinstance(manifest, dict) else []
    evidence_base = Path(evidence_dir)
    snapshot_base = Path(snapshots_dir)
    evidence_base.mkdir(parents=True, exist_ok=True)
    snapshot_base.mkdir(parents=True, exist_ok=True)
    records = []
    errors = []
    for index, item in enumerate([row for row in results if isinstance(row, dict)][: max(limit, 0)], start=1):
        url = str(item.get("source_url") or item.get("url") or "")
        record = evidence_record_from_result(item, index=index)
        if fetch_snapshots and url:
            try:
                snapshot = snapshot_url(url, snapshot_base, prefix=f"{index:04d}")
                record["snapshot_path"] = snapshot.get("snapshot_path", "")
                record["snapshot_metadata_path"] = snapshot.get("metadata_path", "")
                record["http_status"] = snapshot.get("status")
                record["content_sha256"] = snapshot.get("sha256", "")
                status = int(snapshot.get("status") or 0)
                if status >= 400:
                    reason = f"http_status={status}"
                    record["missing_reason"] = append_reason(str(record.get("missing_reason") or ""), reason)
                    errors.append({"url": url, "error": reason, "status": status})
            except Exception as exc:  # noqa: BLE001
                record["missing_reason"] = str(exc)
                errors.append({"url": url, "error": str(exc)})
        records.append(record)
    payload = {
        "schema_version": f"{SCHEMA_PREFIX}.source_evidence.v1",
        "generated_at": utc_now(),
        "manifest_path": Path(manifest_path).as_posix(),
        "records": records,
        "summary": {"records": len(records), "snapshots": sum(1 for row in records if row.get("snapshot_path")), "errors": len(errors)},
        "errors": errors,
    }
    write_json(evidence_base / "source_evidence.json", payload)
    return payload


def import_visible_content_evidence(
    *,
    visible_content_path: str | Path,
    evidence_dir: str | Path,
    output_path: str | Path = "",
) -> dict[str, Any]:
    payload = read_json(visible_content_path)
    rows = visible_content_rows(payload)
    evidence_base = Path(evidence_dir)
    evidence_base.mkdir(parents=True, exist_ok=True)
    records = []
    for index, item in enumerate(rows, start=1):
        title = str(item.get("title") or item.get("page_title") or "")
        url = str(item.get("url") or item.get("source_url") or "")
        text = str(item.get("summary") or item.get("snippet") or item.get("visible_text") or item.get("text") or "")
        links = item.get("links") if isinstance(item.get("links"), list) else []
        records.append(
            {
                "evidence_id": f"visible-{index:04d}",
                "source_url": url,
                "title": title,
                "snippet": text[:1000],
                "provider": str(item.get("provider") or "browser-visible-content"),
                "layer": str(item.get("layer") or "writeup_candidate"),
                "confidence": str(item.get("confidence") or "medium"),
                "score": item.get("score", 0),
                "captured_at": str(item.get("captured_at") or utc_now()),
                "download_url": "",
                "sha256": search.sha256_bytes(text.encode("utf-8")) if text else "",
                "missing_reason": "",
                "visible_links": [
                    {
                        "title": str(link.get("title") or link.get("text") or ""),
                        "url": str(link.get("url") or link.get("href") or ""),
                    }
                    for link in links
                    if isinstance(link, dict)
                ][:50],
                "raw": {
                    "source_type": "browser_visible_content",
                    "user_confirmed_visible": bool(item.get("user_confirmed_visible", True)),
                    "blocked_page_recovery": bool(item.get("blocked_page_recovery", True)),
                },
            }
        )
    result = {
        "schema_version": f"{SCHEMA_PREFIX}.visible_content_evidence.v1",
        "workflow_version": WORKFLOW_VERSION,
        "generated_at": utc_now(),
        "visible_content_path": Path(visible_content_path).as_posix(),
        "records": records,
        "summary": {"records": len(records), "source": "browser_visible_content"},
        "notes": [
            "This imports user-confirmed visible page content only.",
            "It does not bypass 403, login, captcha, paywall, or site risk controls.",
        ],
    }
    target = Path(output_path) if str(output_path).strip() else evidence_base / "visible_content_evidence.json"
    write_json(target, result)
    return result


def visible_content_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ["results", "items", "pages", "visible_pages", "records"]:
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    if {"title", "url"} & set(payload):
        return [payload]
    return []


def append_reason(existing: str, reason: str) -> str:
    current = str(existing or "").strip()
    new_reason = str(reason or "").strip()
    if not current:
        return new_reason
    if not new_reason or new_reason in current.split("; "):
        return current
    return f"{current}; {new_reason}"


def evidence_record_from_result(item: dict[str, Any], *, index: int) -> dict[str, Any]:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    preview = metadata.get("preview") if isinstance(metadata.get("preview"), dict) else {}
    return {
        "evidence_id": f"evidence-{index:04d}",
        "source_url": str(item.get("source_url") or item.get("url") or ""),
        "title": str(item.get("title") or ""),
        "snippet": str(item.get("snippet") or item.get("summary") or ""),
        "provider": str(item.get("provider") or ""),
        "layer": str(item.get("layer") or ""),
        "confidence": str(item.get("confidence") or "low"),
        "score": item.get("score", 0),
        "captured_at": utc_now(),
        "download_url": str(item.get("url") or "") if search.looks_direct_asset_url(str(item.get("url") or "")) else "",
        "sha256": preview.get("sha256", ""),
        "missing_reason": "; ".join(str(issue) for issue in item.get("quality_issues", [])),
        "raw": {
            "kind": item.get("kind", ""),
            "source_type": item.get("source_type", ""),
            "lead_only": item.get("lead_only", False),
        },
    }


def snapshot_url(url: str, output_dir: str | Path, *, prefix: str) -> dict[str, Any]:
    fetched = search.fetch_url(url, max_bytes=1024 * 1024)
    base = Path(output_dir)
    base.mkdir(parents=True, exist_ok=True)
    slug = safe_slug(f"{prefix}-{Path(urlparse(url).path).name or urlparse(url).netloc}", fallback=prefix)
    metadata_path = base / f"{slug}.metadata.json"
    snapshot_path = ""
    if fetched.get("text"):
        snapshot_file = base / f"{slug}.html"
        snapshot_file.write_text(str(fetched.get("text") or ""), encoding="utf-8")
        snapshot_path = snapshot_file.as_posix()
    metadata = {key: value for key, value in fetched.items() if key != "text"}
    metadata["snapshot_path"] = snapshot_path
    write_json(metadata_path, metadata)
    return {**metadata, "metadata_path": metadata_path.as_posix()}


def dedupe_cases(
    *,
    cases_path: str | Path,
    output_path: str | Path,
    min_group_size: int = 2,
) -> dict[str, Any]:
    cases = data.load_cases(cases_path)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        for key, reason in dedupe_keys(case):
            groups[key].append({"case": case, "reason": reason})
    candidates = []
    seen_groups: set[tuple[str, ...]] = set()
    for key, items in groups.items():
        if len(items) < min_group_size:
            continue
        case_ids = tuple(sorted(str(item["case"].get("case_id") or "") for item in items))
        if case_ids in seen_groups:
            continue
        seen_groups.add(case_ids)
        reasons = sorted(set(str(item["reason"]) for item in items))
        candidates.append(
            {
                "group_id": f"merge-{len(candidates)+1:04d}",
                "approved": False,
                "confidence": dedupe_confidence(reasons),
                "key": key,
                "reasons": reasons,
                "cases": [case_summary(item["case"]) for item in items],
            }
        )
    payload = {
        "schema_version": f"{SCHEMA_PREFIX}.dedupe_candidates.v1",
        "generated_at": utc_now(),
        "cases_path": Path(cases_path).as_posix(),
        "candidates": candidates,
        "summary": {"cases": len(cases), "candidate_groups": len(candidates)},
        "next_action": "人工确认 candidates[].approved=true 后再执行 apply-dedupe。",
    }
    write_json(output_path, payload)
    return payload


def dedupe_keys(case: dict[str, Any]) -> list[tuple[str, str]]:
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    event = normalize_text(metadata.get("赛事来源") or metadata.get("题目来源") or "")
    title = normalize_text(metadata.get("名称") or "")
    category = canonical_category(str(metadata.get("分类") or "")) if metadata.get("分类") else ""
    keys = []
    year = first_year(str(metadata.get("赛事来源") or metadata.get("题目来源") or ""))
    if event and title and category:
        keys.append((f"event-title-category:{year}:{event}:{title}:{category}", "same_event_year_title_category"))
    elif title and category:
        keys.append((f"title-category:{title}:{category}", "same_title_category"))
    for evidence in case.get("evidence", []) if isinstance(case.get("evidence"), list) else []:
        if not isinstance(evidence, dict):
            continue
        url = canonical_url(str(evidence.get("source_url") or ""))
        if url:
            keys.append((f"url:{url}", "same_source_url"))
        evidence_title = normalize_text(evidence.get("title") or "")
        if evidence_title and category:
            keys.append((f"writeup-title:{evidence_title}:{category}", "same_writeup_title_category"))
    for attachment in case.get("attachments", []) if isinstance(case.get("attachments"), list) else []:
        if isinstance(attachment, dict) and attachment.get("sha256"):
            keys.append((f"attachment-sha256:{attachment.get('sha256')}", "same_attachment_hash"))
    return keys


def apply_dedupe(
    *,
    cases_path: str | Path,
    candidates_path: str | Path,
    output_path: str | Path,
) -> dict[str, Any]:
    cases = data.load_cases(cases_path)
    by_id = {str(case.get("case_id") or ""): case for case in cases}
    candidates = read_json(candidates_path).get("candidates", [])
    merged_ids: set[str] = set()
    output_cases = []
    merge_records = []
    for candidate in candidates:
        if not isinstance(candidate, dict) or not candidate.get("approved"):
            continue
        ids = [str(item.get("case_id") or "") for item in candidate.get("cases", []) if isinstance(item, dict)]
        group_cases = [by_id[case_id] for case_id in ids if case_id in by_id and case_id not in merged_ids]
        if len(group_cases) < 2:
            continue
        merged = merge_case_group(group_cases)
        output_cases.append(merged)
        merged_ids.update(str(case.get("case_id") or "") for case in group_cases)
        merge_records.append({"group_id": candidate.get("group_id"), "merged_case_id": merged.get("case_id"), "source_case_ids": ids})
    for case in cases:
        if str(case.get("case_id") or "") not in merged_ids:
            output_cases.append(case)
    write_jsonl(output_path, output_cases)
    return {
        "schema_version": f"{SCHEMA_PREFIX}.dedupe_apply.v1",
        "generated_at": utc_now(),
        "output_path": Path(output_path).as_posix(),
        "merge_records": merge_records,
        "summary": {"input_cases": len(cases), "output_cases": len(output_cases), "merged_groups": len(merge_records)},
    }


def merge_case_group(cases: list[dict[str, Any]]) -> dict[str, Any]:
    base = json.loads(json.dumps(cases[0], ensure_ascii=False))
    base["case_id"] = str(base.get("case_id") or "merged-case") + "-merged"
    for other in cases[1:]:
        for field in ["metadata", "research", "asset_collection", "environment", "docker_artifacts", "writeup", "hub_fields", "review", "archive"]:
            base[field] = merge_dicts(base.get(field, {}), other.get(field, {}))
        for field in ["source_files", "attachments", "evidence"]:
            base[field] = unique_records(list(base.get(field, [])) + list(other.get(field, [])))
        if not base.get("flag", {}).get("value") and isinstance(other.get("flag"), dict):
            base["flag"] = other["flag"]
    base.setdefault("research", {})["merged_from"] = [case.get("case_id") for case in cases]
    return base


def merge_dicts(left: Any, right: Any) -> dict[str, Any]:
    result = dict(left) if isinstance(left, dict) else {}
    if not isinstance(right, dict):
        return result
    for key, value in right.items():
        if key not in result or is_empty_value(result[key]):
            result[key] = value
    return result


def is_empty_value(value: Any) -> bool:
    return value == "" or value is None or value == [] or value == {}


def unique_records(records: list[Any]) -> list[Any]:
    output = []
    seen = set()
    for record in records:
        key = json.dumps(record, ensure_ascii=False, sort_keys=True) if isinstance(record, (dict, list)) else str(record)
        if key in seen:
            continue
        seen.add(key)
        output.append(record)
    return output


def dedupe_confidence(reasons: list[str]) -> str:
    if "same_attachment_hash" in reasons or "same_source_url" in reasons:
        return "high"
    if "same_event_year_title_category" in reasons:
        return "medium"
    return "low"


def case_summary(case: dict[str, Any]) -> dict[str, Any]:
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    return {
        "case_id": case.get("case_id", ""),
        "event": metadata.get("赛事来源", ""),
        "title": metadata.get("名称", ""),
        "category": metadata.get("分类", ""),
        "flag_present": bool(case.get("flag", {}).get("value")) if isinstance(case.get("flag"), dict) else False,
    }


def normalize_text(value: Any) -> str:
    return re.sub(r"\s+", "", str(value or "").strip().lower())


def first_year(value: str) -> str:
    match = re.search(r"\b(20\d{2})\b", value)
    return match.group(1) if match else ""


def canonical_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url.strip())
    if not parsed.scheme or not parsed.netloc:
        return ""
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/"), "", "", ""))


def download_sandbox(
    *,
    urls: list[str],
    output_dir: str | Path,
    accept: bool = False,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_archive_unpacked: int = DEFAULT_MAX_ARCHIVE_UNPACKED,
    max_archive_files: int = DEFAULT_MAX_ARCHIVE_FILES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
) -> dict[str, Any]:
    base = Path(output_dir)
    sandbox_dir = base / "downloads_sandbox"
    accepted_dir = base / "downloads_accepted"
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    if accept:
        accepted_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for index, url in enumerate(urls, start=1):
        record = sandbox_one_url(
            url,
            sandbox_dir,
            index=index,
            max_file_size=max_file_size,
            max_archive_unpacked=max_archive_unpacked,
            max_archive_files=max_archive_files,
            max_redirects=max_redirects,
        )
        if accept and record.get("safety_status") == "safe" and record.get("local_path"):
            source_path = Path(record["local_path"])
            target = accepted_dir / source_path.name
            shutil.copy2(source_path, target)
            record["accepted_path"] = target.as_posix()
        records.append(record)
    payload = {
        "schema_version": f"{SCHEMA_PREFIX}.download_sandbox.v1",
        "generated_at": utc_now(),
        "output_dir": base.as_posix(),
        "max_file_size": max_file_size,
        "max_redirects": max_redirects,
        "records": records,
        "summary": {
            "total": len(records),
            "safe": sum(1 for item in records if item.get("safety_status") == "safe"),
            "needs_review": sum(1 for item in records if item.get("safety_status") == "needs_review"),
            "blocked": sum(1 for item in records if item.get("safety_status") == "blocked"),
            "accepted": sum(1 for item in records if item.get("accepted_path")),
        },
    }
    write_json(base / "download_preview.json", payload)
    (base / "download_safety_report.md").write_text(render_download_report(payload), encoding="utf-8")
    return payload


def download_sandbox_from_manifest(
    *,
    manifest_path: str | Path,
    output_dir: str | Path,
    accept: bool = False,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
) -> dict[str, Any]:
    manifest = read_json(manifest_path)
    urls = []
    for item in manifest.get("results", []) if isinstance(manifest, dict) else []:
        if not isinstance(item, dict):
            continue
        url = str(item.get("source_url") or item.get("url") or "")
        if url and search.looks_direct_asset_url(url):
            urls.append(url)
    return download_sandbox(urls=urls, output_dir=output_dir, accept=accept, max_file_size=max_file_size, max_redirects=max_redirects)


def sandbox_one_url(
    url: str,
    sandbox_dir: Path,
    *,
    index: int,
    max_file_size: int,
    max_archive_unpacked: int,
    max_archive_files: int,
    max_redirects: int,
) -> dict[str, Any]:
    clean_url = str(url or "").strip()
    blocked_reason = blocked_url_reason(clean_url)
    if blocked_reason:
        return {"url": clean_url, "safety_status": "blocked", "issues": [blocked_reason]}
    issues = []
    try:
        response = http_request_limited_redirects(clean_url, read_limit=max_file_size + 1, max_redirects=max_redirects)
    except Exception as exc:  # noqa: BLE001
        return {"url": clean_url, "safety_status": "blocked", "issues": [str(exc)]}
    body = response["body"]
    status = int(response.get("status") or 0)
    content_type = response.get("headers", {}).get("content-type", "")
    if status >= 400:
        return {"url": clean_url, "status": status, "content_type": content_type, "safety_status": "blocked", "issues": [f"HTTP {status}"]}
    if len(body) > max_file_size:
        return {
            "url": clean_url,
            "status": status,
            "content_type": content_type,
            "safety_status": "blocked",
            "issues": [f"file exceeds max_file_size={max_file_size}"],
        }
    filename = search.safe_filename(Path(urlparse(clean_url).path).name or f"download-{index:04d}.bin")
    path = sandbox_dir / f"{index:04d}-{filename}"
    path.write_bytes(body)
    record = {
        "url": clean_url,
        "final_url": str(response.get("final_url") or clean_url),
        "redirect_count": int(response.get("redirect_count") or 0),
        "status": status,
        "content_type": content_type,
        "local_path": path.as_posix(),
        "name": path.name,
        "size": path.stat().st_size,
        "sha256": search.sha256_file(path),
        "issues": issues,
        "archive_preview": {},
    }
    if "html" in content_type.lower() and search.looks_direct_asset_url(clean_url):
        issues.append("direct asset URL returned HTML content")
    if is_archive_path(path):
        preview = search.preview_archive(path, max_entries=min(max_archive_files, 2000))
        record["archive_preview"] = preview
        summary = preview.get("summary", {})
        if summary.get("issues"):
            issues.append("archive preview has unsafe paths or unsupported entries")
        if int(summary.get("total_uncompressed") or 0) > max_archive_unpacked:
            issues.append(f"archive unpacked size exceeds {max_archive_unpacked}")
        if int(summary.get("entries") or 0) >= max_archive_files:
            issues.append(f"archive file count reaches limit {max_archive_files}")
    record["safety_status"] = "safe" if not issues else "needs_review"
    return record


class RedirectLimitExceeded(RuntimeError):
    pass


class RedirectTargetBlocked(RuntimeError):
    pass


class LimitedRedirectHandler(HTTPRedirectHandler):
    def __init__(self, max_redirects: int):
        self.max_redirects = max(0, int(max_redirects))
        self.redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        self.redirect_count += 1
        if self.redirect_count > self.max_redirects:
            raise RedirectLimitExceeded(f"redirect count exceeds max_redirects={self.max_redirects}")
        blocked_reason = blocked_url_reason(str(newurl or ""))
        if blocked_reason:
            raise RedirectTargetBlocked(f"redirect target blocked: {blocked_reason}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_request_limited_redirects(
    url: str,
    *,
    read_limit: int,
    max_redirects: int,
    timeout: int = search.DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    search.validate_http_url(url)
    handler = LimitedRedirectHandler(max_redirects)
    opener = build_opener(handler)
    request = Request(url, headers={"User-Agent": search.USER_AGENT})
    try:
        with opener.open(request, timeout=timeout) as response:  # noqa: S310 - public-source fetch helper.
            body = response.read(read_limit)
            return {
                "status": getattr(response, "status", 200),
                "headers": {key.lower(): value for key, value in response.headers.items()},
                "body": body,
                "final_url": response.geturl(),
                "redirect_count": handler.redirect_count,
            }
    except HTTPError as exc:
        try:
            body = exc.read(read_limit)
            return {
                "status": exc.code,
                "headers": {key.lower(): value for key, value in exc.headers.items()},
                "body": body,
                "final_url": exc.geturl(),
                "redirect_count": handler.redirect_count,
            }
        finally:
            exc.close()
    except (RedirectLimitExceeded, RedirectTargetBlocked):
        raise
    except URLError as exc:
        raise RuntimeError(f"failed to fetch {url}: {exc}") from exc


def blocked_url_reason(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES or not parsed.netloc:
        return "unsupported URL scheme"
    host = (parsed.hostname or "").lower()
    if host in BLOCKED_HOSTS:
        return "blocked localhost/private host"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return ""
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return "blocked private IP address"
    return ""


def is_archive_path(path: Path) -> bool:
    lower = path.name.lower()
    return lower.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".rar", ".7z"))


def render_download_report(payload: dict[str, Any]) -> str:
    lines = [
        "# Download Sandbox Report",
        "",
        f"- generated_at: `{payload.get('generated_at', '')}`",
        f"- output_dir: `{payload.get('output_dir', '')}`",
        "",
        "| URL | status | size | safety | issues |",
        "|---|---:|---:|---|---|",
    ]
    for record in payload.get("records", []):
        if not isinstance(record, dict):
            continue
        issues = "; ".join(str(item) for item in record.get("issues", []))
        lines.append(
            f"| {record.get('url', '')} | {record.get('status', '')} | {record.get('size', '')} | {record.get('safety_status', '')} | {issues} |"
        )
    return "\n".join(lines) + "\n"


def append_log(workdir: str | Path, message: str) -> None:
    log_dir = Path(workdir) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    with (log_dir / "workflow.log").open("a", encoding="utf-8") as handle:
        handle.write(f"{utc_now()} {message}\n")


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, payload: Any) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: str | Path, rows: list[dict[str, Any]]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + ("\n" if rows else ""), encoding="utf-8")


def write_text(path: str | Path, text: str) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF workflow orchestration helpers")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="create a workflow run directory and task plan")
    init_parser.add_argument("--event", required=True)
    init_parser.add_argument("--year", action="append", type=int, default=[])
    init_parser.add_argument("--category", action="append", default=[])
    init_parser.add_argument("--limit", type=int, default=20)
    init_parser.add_argument("--out")
    init_parser.add_argument("--allow-browser-search", action="store_true")
    init_parser.add_argument("--dry-run", action="store_true")
    init_parser.add_argument("--output")

    execute_parser = subparsers.add_parser("execute-search", help="run task_plan.search_tasks and write search_results.json plus ctf_cases.jsonl")
    execute_parser.add_argument("--workdir", required=True)
    execute_parser.add_argument("--task-plan")
    execute_parser.add_argument("--max-tasks", type=int, default=0)
    execute_parser.add_argument("--limit", type=int, default=20)
    execute_parser.add_argument("--source", action="append", default=[])
    execute_parser.add_argument("--agent-results")
    execute_parser.add_argument("--browser-visible-results")
    execute_parser.add_argument("--direct-url", action="append", default=[])
    execute_parser.add_argument("--github-repo", action="append", default=[])
    execute_parser.add_argument("--download-preview", action="store_true")
    execute_parser.add_argument("--fetch-snapshots", action="store_true")
    execute_parser.add_argument("--output")

    materials_parser = subparsers.add_parser("collect-materials", help="preview/download direct assets and GitHub release/tree candidates from search results")
    materials_parser.add_argument("--manifest", required=True)
    materials_parser.add_argument("--output-dir", required=True)
    materials_parser.add_argument("--max-direct-downloads", type=int, default=10)
    materials_parser.add_argument("--max-repo-previews", type=int, default=10)
    materials_parser.add_argument("--max-repo-files", type=int, default=80)
    materials_parser.add_argument("--github-ref", default="main")
    materials_parser.add_argument("--no-download-direct", action="store_true")
    materials_parser.add_argument("--output")

    route_parser = subparsers.add_parser("route-resource", help="classify a local resource directory and prepare the next skill handoff")
    route_parser.add_argument("root")
    route_parser.add_argument("--output-dir")
    route_parser.add_argument("--max-files", type=int, default=2000)
    route_parser.add_argument("--output")

    strategy_parser = subparsers.add_parser("strategy", help="generate category-specific search queries")
    strategy_parser.add_argument("--event", required=True)
    strategy_parser.add_argument("--year", action="append", type=int, default=[])
    strategy_parser.add_argument("--category", action="append", default=[])
    strategy_parser.add_argument("--limit", type=int, default=20)
    strategy_parser.add_argument("--output", required=True)

    batch_parser = subparsers.add_parser("batch", help="write or preview workflow stage state")
    batch_parser.add_argument("--workdir", required=True)
    batch_parser.add_argument("--stage", choices=STAGES, required=True)
    batch_parser.add_argument("--mode", choices=["dry-run", "apply"], default="dry-run")
    batch_parser.add_argument("--cases")
    batch_parser.add_argument("--resume", action="store_true")
    batch_parser.add_argument("--output", required=True)

    github_parser = subparsers.add_parser("github-doctor", help="check gh auth and GitHub search availability")
    github_parser.add_argument("--sample-query", default="ctf writeup")
    github_parser.add_argument("--output", required=True)

    evidence_parser = subparsers.add_parser("source-evidence", help="write evidence records and optional page snapshots")
    evidence_parser.add_argument("--manifest", required=True)
    evidence_parser.add_argument("--evidence-dir", required=True)
    evidence_parser.add_argument("--snapshots-dir", required=True)
    evidence_parser.add_argument("--limit", type=int, default=50)
    evidence_parser.add_argument("--no-fetch-snapshots", action="store_true")
    evidence_parser.add_argument("--output")

    visible_parser = subparsers.add_parser("visible-content-evidence", help="import user-confirmed browser visible page content into evidence")
    visible_parser.add_argument("--input", required=True)
    visible_parser.add_argument("--evidence-dir", required=True)
    visible_parser.add_argument("--output")

    dedupe_parser = subparsers.add_parser("dedupe", help="generate duplicate candidate groups")
    dedupe_parser.add_argument("--cases", required=True)
    dedupe_parser.add_argument("--output", required=True)

    apply_parser = subparsers.add_parser("apply-dedupe", help="merge approved duplicate groups")
    apply_parser.add_argument("--cases", required=True)
    apply_parser.add_argument("--candidates", required=True)
    apply_parser.add_argument("--output", required=True)
    apply_parser.add_argument("--report", required=True)

    sandbox_parser = subparsers.add_parser("download-sandbox", help="download URLs into a sandbox and write safety preview")
    sandbox_parser.add_argument("--url", action="append", default=[])
    sandbox_parser.add_argument("--manifest")
    sandbox_parser.add_argument("--output-dir", required=True)
    sandbox_parser.add_argument("--accept", action="store_true")
    sandbox_parser.add_argument("--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE)
    sandbox_parser.add_argument("--max-redirects", type=int, default=DEFAULT_MAX_REDIRECTS)
    sandbox_parser.add_argument("--output")

    args = parser.parse_args(argv)

    if args.command == "init":
        payload = init_workflow(
            event=args.event,
            years=args.year,
            categories=args.category,
            limit=args.limit,
            out_dir=args.out,
            allow_browser_search=args.allow_browser_search,
            dry_run=args.dry_run,
        )
        if args.output:
            write_json(args.output, payload)
        print(json.dumps({"workdir": payload["workdir"], "dry_run": payload["dry_run"]}, ensure_ascii=False))
        return 0

    if args.command == "execute-search":
        payload = execute_search_tasks(
            workdir=args.workdir,
            task_plan_path=args.task_plan,
            max_tasks=args.max_tasks,
            limit=args.limit,
            sources=args.source or None,
            agent_results_path=args.agent_results,
            browser_visible_results_path=args.browser_visible_results,
            direct_urls=args.direct_url,
            github_repos=args.github_repo,
            download_preview=args.download_preview,
            fetch_snapshots=args.fetch_snapshots,
        )
        if args.output:
            write_json(args.output, payload)
        print(json.dumps({"cases": payload["summary"]["cases"], "results": payload["summary"]["results"], "workdir": payload["workdir"]}, ensure_ascii=False))
        return 0

    if args.command == "collect-materials":
        payload = collect_materials(
            manifest_path=args.manifest,
            output_dir=args.output_dir,
            max_direct_downloads=args.max_direct_downloads,
            max_repo_previews=args.max_repo_previews,
            max_repo_files=args.max_repo_files,
            github_ref=args.github_ref,
            download_direct=not args.no_download_direct,
        )
        if args.output:
            write_json(args.output, payload)
        print(json.dumps(payload["summary"], ensure_ascii=False))
        return 0

    if args.command == "route-resource":
        payload = route_resource(root=args.root, output_dir=args.output_dir, max_files=args.max_files)
        if args.output:
            write_json(args.output, payload)
        print(json.dumps({"next": payload["recommended_next"], "route": payload["resource_route_path"]}, ensure_ascii=False))
        return 0

    if args.command == "strategy":
        payload = {
            "schema_version": f"{SCHEMA_PREFIX}.search_strategy_result.v1",
            "generated_at": utc_now(),
            "queries": build_search_queries(event=args.event, years=args.year, categories=args.category, limit=args.limit),
        }
        write_json(args.output, payload)
        print(f"wrote {args.output}")
        return 0

    if args.command == "batch":
        payload = batch_orchestrate(workdir=args.workdir, stage=args.stage, mode=args.mode, cases_path=args.cases, resume=args.resume)
        write_json(args.output, payload)
        print(f"wrote {args.output}")
        return 0

    if args.command == "github-doctor":
        github_doctor(sample_query=args.sample_query, output_path=args.output)
        print(f"wrote {args.output}")
        return 0

    if args.command == "source-evidence":
        payload = record_source_evidence(
            manifest_path=args.manifest,
            evidence_dir=args.evidence_dir,
            snapshots_dir=args.snapshots_dir,
            limit=args.limit,
            fetch_snapshots=not args.no_fetch_snapshots,
        )
        if args.output:
            write_json(args.output, payload)
        print(f"wrote {Path(args.evidence_dir) / 'source_evidence.json'}")
        return 0

    if args.command == "visible-content-evidence":
        payload = import_visible_content_evidence(
            visible_content_path=args.input,
            evidence_dir=args.evidence_dir,
            output_path=args.output or "",
        )
        print(f"wrote {args.output or Path(args.evidence_dir) / 'visible_content_evidence.json'}")
        return 0

    if args.command == "dedupe":
        dedupe_cases(cases_path=args.cases, output_path=args.output)
        print(f"wrote {args.output}")
        return 0

    if args.command == "apply-dedupe":
        payload = apply_dedupe(cases_path=args.cases, candidates_path=args.candidates, output_path=args.output)
        write_json(args.report, payload)
        print(f"wrote {args.output}")
        return 0

    if args.command == "download-sandbox":
        if args.manifest:
            payload = download_sandbox_from_manifest(
                manifest_path=args.manifest,
                output_dir=args.output_dir,
                accept=args.accept,
                max_file_size=args.max_file_size,
                max_redirects=args.max_redirects,
            )
        else:
            payload = download_sandbox(
                urls=args.url,
                output_dir=args.output_dir,
                accept=args.accept,
                max_file_size=args.max_file_size,
                max_redirects=args.max_redirects,
            )
        if args.output:
            write_json(args.output, payload)
        print(f"wrote {Path(args.output_dir) / 'download_preview.json'}")
        return 0

    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
