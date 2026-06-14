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
import cloversec_ctf_search as search


SCHEMA_PREFIX = "cloversec.ctf.workflow"
WORKFLOW_VERSION = "0.3.2"
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
