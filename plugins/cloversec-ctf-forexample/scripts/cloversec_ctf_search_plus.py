#!/usr/bin/env python3
"""Unified CTF search orchestration for MCP callers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import cloversec_ctf_browser_search as browser_search
import cloversec_ctf_search as search


DEFAULT_COMPACT_RESULTS = 8
DEFAULT_DIRECT_URL_PREVIEW_BYTES = 256 * 1024


def search_plus(
    query: str,
    *,
    years: list[int] | None = None,
    sources: list[str] | None = None,
    limit: int = 20,
    agent_results: Any | None = None,
    browser_visible_results: Any | None = None,
    direct_urls: list[str] | None = None,
    github_repos: list[Any] | None = None,
    output_path: str | Path | None = None,
    compact: bool = True,
    compact_results: int = DEFAULT_COMPACT_RESULTS,
    direct_url_preview_bytes: int = DEFAULT_DIRECT_URL_PREVIEW_BYTES,
) -> dict[str, Any]:
    years = years or []
    selected_sources = sources or search.DEFAULT_DISCOVER_SOURCES
    errors: list[dict[str, Any]] = []
    source_manifests: list[dict[str, Any]] = []
    raw_results: list[dict[str, Any]] = []

    base = search.discover(query, years=years, sources=selected_sources, limit=limit)
    source_manifests.append({"name": "default-free-sources", "summary": base.get("summary", {})})
    raw_results.extend(base.get("results", []))
    errors.extend(base.get("errors", []))

    if agent_results is not None:
        imported = search.import_agent_search_results(
            agent_results,
            query=query,
            provider="agent-web-search",
            limit=max(limit, compact_results),
        )
        source_manifests.append({"name": "agent-web-search", "summary": imported.get("summary", {})})
        raw_results.extend(imported.get("results", []))
        errors.extend(imported.get("errors", []))

    if browser_visible_results is not None:
        browser_payloads = normalize_browser_payloads(browser_visible_results)
        for browser_payload in browser_payloads:
            engine = str(browser_payload.get("engine") or "chrome")
            visible_payload = {
                "results": browser_payload.get("results", []),
                "blocked_by_captcha": bool(browser_payload.get("blocked_by_captcha", False)),
                "blocked_reason": str(browser_payload.get("blocked_reason", "")),
            }
            imported = browser_search.normalize_visible_results(visible_payload, query=query, engine=engine)
            source_manifests.append({"name": f"browser-{engine}", "summary": imported.get("summary", {})})
            raw_results.extend(imported.get("results", []))
            errors.extend(imported.get("errors", []))

    direct_preview = preview_direct_urls(direct_urls or [], max_bytes=direct_url_preview_bytes)
    raw_results.extend(direct_preview["results"])
    errors.extend(direct_preview["errors"])

    github_payload = collect_github_repo_sources(github_repos or [], limit=max(5, min(limit, 20)))
    raw_results.extend(github_payload["results"])
    errors.extend(github_payload["errors"])
    if github_payload["summary"]["repositories"]:
        source_manifests.append({"name": "explicit-github-repos", "summary": github_payload["summary"]})

    ranked = search.rank_results(search.enrich_results(search.dedupe_results(raw_results), query=query, years=years))
    payload = {
        "schema_version": "cloversec.ctf.search_plus.v1",
        "query": query,
        "years": years,
        "generated_at": search.utc_now(),
        "sources": selected_sources,
        "results": ranked,
        "source_manifests": source_manifests,
        "direct_url_preview": direct_preview["preview"],
        "recall_recovery": base.get("recall_recovery", {}),
        "summary": {
            "total_results": len(ranked),
            "provider_counts": search.provider_counts(ranked),
            "layer_counts": search.layer_counts(ranked),
            "errors": len(errors),
            "direct_urls_previewed": len(direct_preview["preview"]),
            "github_repositories_checked": github_payload["summary"]["repositories"],
        },
        "decision_required": build_decision_required(base, errors, direct_preview["preview"], ranked),
        "next_actions": build_next_actions(base, ranked, errors),
        "errors": errors,
    }

    written_path = ""
    if output_path:
        search.write_json(output_path, payload)
        written_path = Path(output_path).as_posix()
        payload["full_output_path"] = written_path

    if compact:
        compact_payload = compact_search_payload(payload, max_results=compact_results)
        if written_path:
            compact_payload["full_output_path"] = written_path
        return compact_payload
    return payload


def normalize_browser_payloads(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        if isinstance(value.get("pages"), list):
            return [item for item in value["pages"] if isinstance(item, dict)]
        return [value]
    return []


def preview_direct_urls(urls: list[str], *, max_bytes: int) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    preview: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    seen: set[str] = set()
    for url in urls:
        clean_url = str(url or "").strip()
        if not clean_url or clean_url in seen:
            continue
        seen.add(clean_url)
        parsed = urlparse(clean_url)
        title = Path(parsed.path).name or clean_url
        result = search.normalize_result(
            provider="direct-url",
            kind="direct_asset" if search.looks_direct_asset_url(clean_url) else "direct_url",
            title=title,
            url=clean_url,
            summary="Direct URL supplied by user, Agent search, or browser visible result.",
            source_type="direct_url",
            confidence="medium",
            metadata={"asset_hint": search.looks_direct_asset_url(clean_url)},
        )
        try:
            fetched = search.fetch_url(clean_url, max_bytes=max_bytes)
            challenge_metadata = search.parse_simple_challenge_metadata(fetched.get("text", ""), clean_url)
            if challenge_metadata:
                result["kind"] = "challenge_metadata"
                result["title"] = str(challenge_metadata.get("name") or title)
                result["summary"] = "Direct challenge metadata URL supplied by user, Agent search, or browser visible result."
                result["snippet"] = result["summary"]
            result["metadata"] = {
                **result["metadata"],
                "preview": {
                    "status": fetched.get("status"),
                    "content_type": fetched.get("content_type", ""),
                    "size": fetched.get("size", 0),
                    "truncated": fetched.get("truncated", False),
                    "sha256": fetched.get("sha256", ""),
                    "title": fetched.get("title", ""),
                },
            }
            if challenge_metadata:
                result["metadata"]["challenge_metadata"] = challenge_metadata
            preview.append(
                {
                    "url": clean_url,
                    "status": fetched.get("status"),
                    "content_type": fetched.get("content_type", ""),
                    "size": fetched.get("size", 0),
                    "truncated": fetched.get("truncated", False),
                    "sha256": fetched.get("sha256", ""),
                    "asset_hint": search.looks_direct_asset_url(clean_url),
                    "challenge_metadata": bool(challenge_metadata),
                }
            )
        except Exception as exc:  # noqa: BLE001 - return structured provider failure.
            errors.append({"provider": "direct-url", "status": "failed", "url": clean_url, "error": str(exc)})
            result["metadata"] = {**result["metadata"], "preview_error": str(exc)}
        results.append(result)
    return {"results": results, "preview": preview, "errors": errors}


def collect_github_repo_sources(repos: list[Any], *, limit: int) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    count = 0
    for item in repos:
        repo = normalize_github_repo_arg(item)
        if not repo:
            continue
        count += 1
        try:
            results.extend(search.github_release_assets(repo, limit=limit))
        except Exception as exc:  # noqa: BLE001
            errors.append(search.provider_issue("github-release", exc))
        if should_collect_github_tree(item):
            ref = str(item.get("ref") or "main") if isinstance(item, dict) else "main"
            path_prefix = github_repo_path_arg(item)
            try:
                tree_results = search.github_tree_files(repo, ref=ref, path_prefix=path_prefix, limit=limit)
                results.extend(enrich_github_tree_metadata(tree_results, max_bytes=DEFAULT_DIRECT_URL_PREVIEW_BYTES))
            except Exception as exc:  # noqa: BLE001
                errors.append(search.provider_issue("github-tree", exc))
    return {"results": results, "errors": errors, "summary": {"repositories": count}}


def normalize_github_repo_arg(item: Any) -> str:
    raw = item
    if isinstance(item, dict):
        raw = item.get("repo") or item.get("repository") or item.get("url") or item.get("html_url")
    value = str(raw or "").strip()
    if not value:
        return ""
    try:
        owner, repo = search.parse_github_repo(value)
    except ValueError:
        return value
    return f"{owner}/{repo}"


def github_repo_path_arg(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    return str(item.get("path_prefix") or item.get("path") or item.get("directory") or "").strip("/")


def should_collect_github_tree(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    return bool(item.get("tree") or item.get("path_prefix") or item.get("path") or item.get("directory"))


def enrich_github_tree_metadata(results: list[dict[str, Any]], *, max_bytes: int) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in results:
        current = dict(item)
        metadata = dict(current.get("metadata") or {})
        raw_url = str(metadata.get("raw_url") or "")
        if raw_url and search.is_challenge_metadata_path(str(current.get("url") or ""), metadata):
            try:
                fetched = search.fetch_url(raw_url, max_bytes=max_bytes)
                challenge_metadata = search.parse_simple_challenge_metadata(fetched.get("text", ""), raw_url)
            except Exception as exc:  # noqa: BLE001
                metadata["preview_error"] = str(exc)
            else:
                metadata["preview"] = {
                    "status": fetched.get("status"),
                    "content_type": fetched.get("content_type", ""),
                    "size": fetched.get("size", 0),
                    "truncated": fetched.get("truncated", False),
                    "sha256": fetched.get("sha256", ""),
                    "title": fetched.get("title", ""),
                }
                if challenge_metadata:
                    metadata["challenge_metadata"] = challenge_metadata
                    current["kind"] = "challenge_metadata"
                    current["title"] = str(challenge_metadata.get("name") or current.get("title") or "")
                    current["summary"] = "GitHub challenge metadata file from recursive tree."
                    current["snippet"] = current["summary"]
        current["metadata"] = metadata
        output.append(current)
    return output


def build_decision_required(
    base: dict[str, Any],
    errors: list[dict[str, Any]],
    direct_preview: list[dict[str, Any]],
    ranked: list[dict[str, Any]],
) -> list[dict[str, str]]:
    decisions: list[dict[str, str]] = []
    recovery = base.get("recall_recovery") if isinstance(base.get("recall_recovery"), dict) else {}
    if recovery.get("should_run") and search.candidate_count(ranked) < recovery.get("minimum_candidates", 3):
        decisions.append(
            {
                "type": "weak_recall",
                "message": "默认免费源召回仍弱，需要 Agent 联网搜索、Chrome 浏览器辅助搜索或人工提供入口。",
            }
        )
    if any(item.get("status") in {"blocked_by_captcha", "skipped", "failed"} for item in errors):
        decisions.append({"type": "provider_error", "message": "部分来源失败或被阻断，需要人工判断是否换来源。"})
    if any(int(item.get("status") or 0) >= 400 for item in direct_preview if str(item.get("status") or "").isdigit()):
        decisions.append({"type": "direct_url_failed", "message": "存在直接 URL 访问失败，不能当作已下载附件。"})
    if not any(item.get("layer") in {"confirmed_challenge", "attachment_candidate", "writeup_candidate"} for item in ranked):
        decisions.append({"type": "no_candidate", "message": "没有可用候选，需要扩大搜索或人工提供入口。"})
    return decisions


def build_next_actions(base: dict[str, Any], ranked: list[dict[str, Any]], errors: list[dict[str, Any]]) -> list[str]:
    actions: list[str] = []
    recovery = base.get("recall_recovery") if isinstance(base.get("recall_recovery"), dict) else {}
    if recovery.get("agent_web_search_queries"):
        actions.append("用当前 Agent 联网搜索工具查询 recall_recovery.agent_web_search_queries，并用 import_agent_web_results 导入。")
    if recovery.get("browser_search_queries"):
        actions.append("用 Chrome/Codex 浏览器打开 browser_search_queries，确认页面后导入可见结果。")
    if any(item.get("provider") == "direct-url" and item.get("layer") == "attachment_candidate" for item in ranked):
        actions.append("对 direct-url 附件候选执行人工确认后再下载，不要把预览当作已归档资源。")
    if errors:
        actions.append("查看 errors 字段，失败来源只作为待处理问题，不写成确认事实。")
    if not actions:
        actions.append("按 top_results 的 layer 和 evidence 进入资产收集或人工核验。")
    return actions


def compact_search_payload(payload: dict[str, Any], *, max_results: int = DEFAULT_COMPACT_RESULTS) -> dict[str, Any]:
    return {
        "schema_version": "cloversec.ctf.search_plus.compact.v1",
        "query": payload.get("query", ""),
        "years": payload.get("years", []),
        "generated_at": payload.get("generated_at", ""),
        "summary": payload.get("summary", {}),
        "decision_required": payload.get("decision_required", []),
        "next_actions": payload.get("next_actions", []),
        "recall_recovery": compact_recall_recovery(payload.get("recall_recovery", {})),
        "top_results": [compact_result(item) for item in payload.get("results", [])[: max(max_results, 0)]],
        "errors": payload.get("errors", [])[:5],
        "response_note": "短 JSON 默认返回。需要完整结果时传 output_path 或 compact=false。",
    }


def compact_recall_recovery(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        "status": value.get("status", ""),
        "reason": value.get("reason", ""),
        "initial_candidate_count": value.get("initial_candidate_count", 0),
        "minimum_candidates": value.get("minimum_candidates", 0),
        "agent_web_search_queries": value.get("agent_web_search_queries", [])[:4],
        "browser_search_queries": value.get("browser_search_queries", [])[:4],
    }


def compact_result(item: dict[str, Any]) -> dict[str, Any]:
    evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    preview = metadata.get("preview") if isinstance(metadata.get("preview"), dict) else {}
    return {
        "title": item.get("title", ""),
        "source_url": item.get("source_url") or item.get("url", ""),
        "provider": item.get("provider", ""),
        "kind": item.get("kind", ""),
        "layer": item.get("layer", ""),
        "confidence": item.get("confidence", ""),
        "score": item.get("score", 0),
        "lead_only": item.get("lead_only", False),
        "snippet": item.get("snippet") or item.get("summary", ""),
        "quality_issues": item.get("quality_issues", []),
        "evidence": {
            "provider": evidence.get("provider", item.get("provider", "")),
            "captured_at": evidence.get("captured_at", ""),
            "search_query": evidence.get("search_query", ""),
        },
        "preview": preview,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="CloverSec CTF unified search-plus helper")
    parser.add_argument("--query", required=True)
    parser.add_argument("--year", type=int, action="append", default=[])
    parser.add_argument("--source", action="append", choices=search.SEARCH_SOURCES)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--agent-results")
    parser.add_argument("--browser-visible-results")
    parser.add_argument("--direct-url", action="append", default=[])
    parser.add_argument("--github-repo", action="append", default=[])
    parser.add_argument("--output", required=True)
    parser.add_argument("--compact-output")
    args = parser.parse_args(argv)

    agent_payload = json.loads(Path(args.agent_results).read_text(encoding="utf-8")) if args.agent_results else None
    browser_payload = (
        json.loads(Path(args.browser_visible_results).read_text(encoding="utf-8"))
        if args.browser_visible_results
        else None
    )
    full_payload = search_plus(
        args.query,
        years=args.year,
        sources=args.source,
        limit=args.limit,
        agent_results=agent_payload,
        browser_visible_results=browser_payload,
        direct_urls=args.direct_url,
        github_repos=args.github_repo,
        output_path=args.output,
        compact=False,
    )
    if args.compact_output:
        search.write_json(args.compact_output, compact_search_payload(full_payload))
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
