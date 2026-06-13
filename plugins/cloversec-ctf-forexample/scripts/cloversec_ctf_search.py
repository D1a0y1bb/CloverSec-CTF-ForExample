#!/usr/bin/env python3
"""Public-source CTF search, fetch, and download helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import time
import zipfile
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlparse
from urllib.request import Request, urlopen


DEFAULT_TIMEOUT = 20
DEFAULT_MAX_BYTES = 50 * 1024 * 1024
USER_AGENT = "CloverSec-CTF-For-Example/0.2.1 (+https://github.com/D1a0y1bb/CloverSec-CTF-ForExample)"
ALLOWED_URL_SCHEMES = {"http", "https"}
GENERIC_EVENT_QUERY_TERMS = {
    "ctf",
    "writeup",
    "writeups",
    "challenge",
    "challenges",
    "archive",
    "archives",
    "web",
    "pwn",
    "misc",
    "crypto",
    "reverse",
    "rev",
    "forensics",
    "osint",
}

ARCHIVE_SEEDS = [
    {
        "provider": "seed",
        "kind": "challenge_archive",
        "title": "CTFs write-ups community",
        "url": "https://github.com/ctfs",
        "summary": "Community-maintained CTF write-up repositories by year.",
        "source_type": "github",
        "confidence": "high",
    },
    {
        "provider": "seed",
        "kind": "challenge_archive",
        "title": "sajjadium/ctf-archives",
        "url": "https://github.com/sajjadium/ctf-archives",
        "summary": "Collection of CTF challenges.",
        "source_type": "github",
        "confidence": "high",
    },
    {
        "provider": "seed",
        "kind": "challenge_archive",
        "title": "google/google-ctf",
        "url": "https://github.com/google/google-ctf",
        "summary": "Google CTF challenge archive and infrastructure.",
        "source_type": "github",
        "confidence": "high",
    },
    {
        "provider": "seed",
        "kind": "challenge_archive",
        "title": "uclaacm/lactf-archive",
        "url": "https://github.com/uclaacm/lactf-archive",
        "summary": "Past LA CTF challenges.",
        "source_type": "github",
        "confidence": "high",
    },
    {
        "provider": "seed",
        "kind": "challenge_archive",
        "title": "pwncollege/ctf-archive",
        "url": "https://github.com/pwncollege/ctf-archive",
        "summary": "Past CTF competition challenges with rehost details.",
        "source_type": "github",
        "confidence": "medium",
    },
]

CTF_PLATFORM_SEEDS = [
    {
        "provider": "ctf-platforms",
        "kind": "ctf_platform",
        "title": "CTFTime",
        "url": "https://ctftime.org/",
        "summary": "Global CTF event calendar, team rankings, writeups, and event metadata.",
        "source_type": "ctf_platform",
        "confidence": "high",
    },
    {
        "provider": "ctf-platforms",
        "kind": "ctf_platform",
        "title": "NSSCTF",
        "url": "https://www.nssctf.cn/",
        "summary": "Chinese CTF training and contest platform.",
        "source_type": "ctf_platform",
        "confidence": "medium",
    },
    {
        "provider": "ctf-platforms",
        "kind": "ctf_platform",
        "title": "CTFHub",
        "url": "https://www.ctfhub.com/",
        "summary": "Chinese CTF training platform and challenge environment.",
        "source_type": "ctf_platform",
        "confidence": "medium",
    },
    {
        "provider": "ctf-platforms",
        "kind": "ctf_platform",
        "title": "攻防世界 XCTF",
        "url": "https://adworld.xctf.org.cn/",
        "summary": "XCTF training and challenge platform.",
        "source_type": "ctf_platform",
        "confidence": "medium",
    },
    {
        "provider": "ctf-platforms",
        "kind": "ctf_platform",
        "title": "BUUOJ",
        "url": "https://buuoj.cn/",
        "summary": "CTF challenge training platform.",
        "source_type": "ctf_platform",
        "confidence": "medium",
    },
    {
        "provider": "ctf-platforms",
        "kind": "ctf_platform",
        "title": "picoCTF",
        "url": "https://picoctf.org/",
        "summary": "Public CTF competition and learning platform.",
        "source_type": "ctf_platform",
        "confidence": "medium",
    },
    {
        "provider": "ctf-platforms",
        "kind": "ctf_platform",
        "title": "pwn.college",
        "url": "https://pwn.college/",
        "summary": "Security education platform with public challenge modules.",
        "source_type": "ctf_platform",
        "confidence": "medium",
    },
    {
        "provider": "ctf-platforms",
        "kind": "ctf_platform",
        "title": "Root-Me",
        "url": "https://www.root-me.org/",
        "summary": "Security challenge and training platform.",
        "source_type": "ctf_platform",
        "confidence": "medium",
    },
]

SITE_SEARCH_PROFILES = {
    "csdn": [
        "site:blog.csdn.net {query}",
        "site:csdn.net {query} CTF writeup",
    ],
    "cnblogs": [
        "site:cnblogs.com {query} CTF writeup",
    ],
    "yuque": [
        "site:yuque.com {query} CTF writeup",
    ],
}

SEARCH_SOURCES = [
    "github",
    "github-code",
    "ctftime",
    "duckduckgo",
    "seeds",
    "ctf-platforms",
    "csdn",
    "cnblogs",
    "yuque",
]

DEFAULT_DISCOVER_SOURCES = [
    "github",
    "ctftime",
    "duckduckgo",
    "seeds",
    "ctf-platforms",
    "csdn",
    "cnblogs",
    "yuque",
]

RECALL_RECOVERY_SOURCES = {"duckduckgo", "csdn", "cnblogs", "yuque"}
MIN_RECALL_CANDIDATES = 3
MAX_RECOVERY_QUERIES = 6

RESULT_LAYERS = [
    "confirmed_challenge",
    "writeup_candidate",
    "attachment_candidate",
    "platform_lead",
    "noise",
]

LAYER_PRIORITY = {
    "confirmed_challenge": 0,
    "attachment_candidate": 1,
    "writeup_candidate": 2,
    "platform_lead": 3,
    "noise": 9,
}

SEARCH_ENGINE_DOMAINS = {
    "duckduckgo.com",
    "www.duckduckgo.com",
    "lite.duckduckgo.com",
    "html.duckduckgo.com",
    "google.com",
    "www.google.com",
    "baidu.com",
    "www.baidu.com",
}

LOGIN_OR_BLOCK_DOMAINS = {
    "accounts.google.com",
    "login.live.com",
    "passport.baidu.com",
    "github.com/login",
}

EVENT_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.-]*ctf[a-z0-9_.-]*", re.I)
CJK_EVENT_RE = re.compile(r"(?:[\u4e00-\u9fff]{1,12}(?:杯|赛)|[\u4e00-\u9fffA-Za-z0-9_.-]{1,30}(?:CTF|ctf))")
GENERIC_CJK_EVENT_TERMS = {
    "比赛",
    "大赛",
    "竞赛",
    "初赛",
    "复赛",
    "决赛",
    "总决赛",
    "线上赛",
    "线下赛",
    "资格赛",
    "网络安全大赛",
    "网络安全竞赛",
    "秋季招新赛",
    "秋季新生赛",
    "校外赛",
}
CATEGORY_TERMS = {"web", "pwn", "misc", "crypto", "reverse", "rev", "forensics", "osint", "mobile", "iot", "ai"}
WRITEUP_TERMS = {"writeup", "write-up", "wp", "题解", "复现"}
ATTACHMENT_TERMS = {"attachment", "attachments", "source", "源码", "附件", "release", "download", "challenge.zip"}
TUTORIAL_NOISE_TERMS = {"从零基础", "入门到竞赛", "学习路线", "保姆级", "看这一篇", "基础入门"}
ATTACHMENT_CANDIDATE_EXTENSIONS = {".zip", ".7z", ".rar", ".tar", ".tgz", ".gz", ".xz", ".bz2"}

DIRECT_ASSET_EXTENSIONS = {
    ".zip",
    ".7z",
    ".rar",
    ".tar",
    ".tgz",
    ".gz",
    ".xz",
    ".bz2",
    ".pdf",
    ".md",
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
}


def parse_github_repo(value: str) -> tuple[str, str]:
    cleaned = value.strip()
    if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", cleaned):
        owner, repo = cleaned.split("/", 1)
        return owner, repo.removesuffix(".git")
    parsed = urlparse(cleaned)
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise ValueError("GitHub repo must be owner/repo or a github.com URL")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        raise ValueError("GitHub URL must include owner and repo")
    return parts[0], parts[1].removesuffix(".git")


def github_blob_to_raw_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.netloc.lower() == "raw.githubusercontent.com":
        return url
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise ValueError("expected github.com or raw.githubusercontent.com URL")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 5 or parts[2] != "blob":
        raise ValueError("expected GitHub blob URL")
    owner, repo, _, ref = parts[:4]
    file_path = "/".join(quote(part) for part in parts[4:])
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{quote(ref)}/{file_path}"


def github_release_assets(repo: str, *, limit: int = 30) -> list[dict[str, Any]]:
    owner, repo_name = parse_github_repo(repo)
    payload = github_json(f"/repos/{owner}/{repo_name}/releases", params={"per_page": str(min(max(limit, 1), 100))})
    releases = payload if isinstance(payload, list) else []
    results = []
    for release in releases:
        if not isinstance(release, dict):
            continue
        tag = str(release.get("tag_name") or "")
        release_name = str(release.get("name") or tag)
        for asset in release.get("assets", []):
            if not isinstance(asset, dict):
                continue
            url = str(asset.get("browser_download_url") or "")
            name = str(asset.get("name") or Path(urlparse(url).path).name)
            if not url or not name:
                continue
            results.append(
                normalize_result(
                    provider="github-release",
                    kind="release_asset",
                    title=f"{owner}/{repo_name} {tag} {name}".strip(),
                    url=url,
                    summary=f"GitHub Release asset from {release_name}".strip(),
                    source_type="github",
                    confidence="high",
                    metadata={
                        "repository": f"{owner}/{repo_name}",
                        "release": release_name,
                        "tag": tag,
                        "asset_name": name,
                        "size": asset.get("size", 0),
                        "content_type": asset.get("content_type", ""),
                        "download_count": asset.get("download_count", 0),
                    },
                )
            )
            if len(results) >= limit:
                return results
    return results


def download_github_release_assets(
    repo: str,
    output_dir: str | Path,
    *,
    max_files: int = 10,
    max_bytes: int = DEFAULT_MAX_BYTES,
    pattern: str = "",
) -> dict[str, Any]:
    downloads = []
    issues = []
    matcher = re.compile(pattern, flags=re.I) if pattern else None
    try:
        release_items = github_release_assets(repo, limit=max(max_files * 3, max_files))
    except Exception as exc:  # noqa: BLE001 - keep public collection runs usable under API limits.
        release_items = []
        issues.append(provider_issue("github-release", exc))
    for item in release_items:
        if len(downloads) >= max_files:
            break
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        name = str(metadata.get("asset_name") or Path(urlparse(str(item.get("url") or "")).path).name)
        if matcher and not matcher.search(name):
            continue
        try:
            record = download_url(str(item["url"]), output_dir, max_bytes=max_bytes, filename=name)
            record["github"] = metadata
            if record.get("error"):
                issues.append(record)
            else:
                downloads.append(record)
        except Exception as exc:  # noqa: BLE001
            issues.append({"url": str(item.get("url") or ""), "error": str(exc), "name": name})
    return {
        "generated_at": utc_now(),
        "repository": safe_normalize_repo_name(repo),
        "output_dir": Path(output_dir).as_posix(),
        "downloads": downloads,
        "issues": issues,
        "summary": {"downloaded": len(downloads), "issues": len(issues)},
    }


def github_tree_files(repo: str, *, ref: str = "main", path_prefix: str = "", limit: int = 200) -> list[dict[str, Any]]:
    owner, repo_name = parse_github_repo(repo)
    payload = github_json(f"/repos/{owner}/{repo_name}/git/trees/{quote(ref, safe='')}", params={"recursive": "1"})
    tree = payload.get("tree", []) if isinstance(payload, dict) else []
    prefix = path_prefix.strip("/")
    results = []
    for item in tree:
        if not isinstance(item, dict) or item.get("type") != "blob":
            continue
        file_path = str(item.get("path") or "")
        if prefix and file_path != prefix and not file_path.startswith(prefix + "/"):
            continue
        raw_url = github_raw_file_url(owner, repo_name, ref, file_path)
        results.append(
            normalize_result(
                provider="github-tree",
                kind="raw_file",
                title=f"{owner}/{repo_name}/{file_path}",
                url=f"https://github.com/{owner}/{repo_name}/blob/{quote(ref)}/{quote(file_path)}",
                summary="GitHub repository file from recursive tree",
                source_type="github",
                confidence="high",
                metadata={
                    "repository": f"{owner}/{repo_name}",
                    "ref": ref,
                    "path": file_path,
                    "raw_url": raw_url,
                    "size": item.get("size", 0),
                    "sha": item.get("sha", ""),
                },
            )
        )
        if len(results) >= limit:
            break
    return results


def download_github_tree(
    repo: str,
    output_dir: str | Path,
    *,
    ref: str = "main",
    path_prefix: str = "",
    max_files: int = 30,
    max_bytes: int = DEFAULT_MAX_BYTES,
    asset_only: bool = False,
) -> dict[str, Any]:
    downloads = []
    issues = []
    output = Path(output_dir)
    prefix = path_prefix.strip("/")
    candidates = github_tree_files(repo, ref=ref, path_prefix=prefix, limit=max_files * 3)
    for item in candidates:
        if len(downloads) >= max_files:
            break
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        file_path = str(metadata.get("path") or "")
        raw_url = str(metadata.get("raw_url") or "")
        if asset_only and not looks_direct_asset_url(raw_url):
            continue
        try:
            relative = relative_tree_output_path(file_path, prefix)
            target_dir = output / relative.parent
            record = download_url(raw_url, target_dir, max_bytes=max_bytes, filename=relative.name)
            record["github"] = metadata
            if record.get("error"):
                issues.append(record)
            else:
                downloads.append(record)
        except Exception as exc:  # noqa: BLE001
            issues.append({"url": raw_url, "path": file_path, "error": str(exc)})
    return {
        "generated_at": utc_now(),
        "repository": normalize_repo_name(repo),
        "ref": ref,
        "path_prefix": prefix,
        "output_dir": output.as_posix(),
        "downloads": downloads,
        "issues": issues,
        "summary": {"downloaded": len(downloads), "issues": len(issues)},
    }


def preview_archive(path: str | Path, *, max_entries: int = 200) -> dict[str, Any]:
    archive_path = Path(path)
    if not archive_path.exists():
        raise FileNotFoundError(archive_path)
    if not archive_path.is_file():
        raise ValueError(f"archive path is not a file: {archive_path}")
    entries: list[dict[str, Any]] = []
    issues: list[dict[str, str]] = []
    archive_type = "unknown"
    total_uncompressed = 0
    if zipfile.is_zipfile(archive_path):
        archive_type = "zip"
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist()[:max_entries]:
                entry = archive_entry_record(info.filename, info.file_size, info.is_dir())
                entries.append(entry)
                total_uncompressed += info.file_size
                if entry["unsafe_path"]:
                    issues.append({"path": info.filename, "error": "unsafe archive path"})
    elif tarfile.is_tarfile(archive_path):
        archive_type = "tar"
        with tarfile.open(archive_path) as archive:
            for member in archive.getmembers()[:max_entries]:
                entry = archive_entry_record(member.name, int(member.size or 0), member.isdir())
                entries.append(entry)
                total_uncompressed += int(member.size or 0)
                if entry["unsafe_path"]:
                    issues.append({"path": member.name, "error": "unsafe archive path"})
    else:
        suffix = archive_path.suffix.lower()
        if suffix in {".7z", ".rar"}:
            archive_type = suffix.lstrip(".")
            issues.append({"path": archive_path.name, "error": f"{archive_type} preview is not supported by stdlib"})
        else:
            issues.append({"path": archive_path.name, "error": "unsupported archive type"})
    return {
        "generated_at": utc_now(),
        "path": archive_path.as_posix(),
        "archive_type": archive_type,
        "size": archive_path.stat().st_size,
        "sha256": sha256_file(archive_path),
        "entries": entries,
        "issues": issues,
        "summary": {
            "entries": len(entries),
            "issues": len(issues),
            "total_uncompressed": total_uncompressed,
            "truncated": len(entries) >= max_entries,
        },
    }


def discover(
    query: str,
    *,
    years: list[int] | None = None,
    sources: list[str] | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    selected = sources or DEFAULT_DISCOVER_SOURCES
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for source in selected:
        try:
            if source == "github":
                results.extend(search_github_repositories(query, limit=limit))
                try:
                    results.extend(search_github_code(query, limit=min(limit, 10)))
                except SearchSkipped as exc:
                    errors.append({"provider": "github-code", "error": str(exc), "status": "skipped"})
            elif source == "github-code":
                results.extend(search_github_code(query, limit=min(limit, 10)))
            elif source == "ctftime":
                for year in years or []:
                    results.extend(search_ctftime_events(year=year, query=query, limit=limit))
                results.extend(search_ctftime_writeups(query=query, limit=limit))
            elif source == "duckduckgo":
                results.extend(search_duckduckgo(query, limit=limit))
            elif source == "seeds":
                results.extend(seed_results(query))
            elif source == "ctf-platforms":
                results.extend(platform_seed_results(query))
            elif source in SITE_SEARCH_PROFILES:
                results.extend(search_site_profile(source, query, limit=limit))
            else:
                errors.append({"provider": source, "error": "unsupported source"})
        except SearchSkipped as exc:
            errors.append({"provider": source, "error": str(exc), "status": "skipped"})
        except Exception as exc:  # noqa: BLE001 - command line tool must keep provider failures isolated.
            errors.append({"provider": source, "error": str(exc), "status": "failed"})

    recovery = create_recall_recovery_plan(query, years=years or [], sources=selected, initial_results=results)
    if recovery["should_run"]:
        for recovery_query in recovery["queries"]:
            results.extend(run_recovery_query(recovery_query, selected, limit=limit))

    deduped = rank_results(enrich_results(dedupe_results(results), query=query, years=years or []))
    recovery["after_recovery"] = {
        "candidate_count": candidate_count(deduped),
        "layer_counts": layer_counts(deduped),
    }
    return {
        "query": query,
        "years": years or [],
        "generated_at": utc_now(),
        "sources": selected,
        "results": deduped[: max(limit, 0) * max(len(selected), 1)],
        "recall_recovery": recovery,
        "summary": {
            "total_results": len(deduped),
            "provider_counts": provider_counts(deduped),
            "layer_counts": layer_counts(deduped),
            "errors": len(errors),
        },
        "errors": errors,
    }


def create_recall_recovery_plan(
    query: str,
    *,
    years: list[int],
    sources: list[str],
    initial_results: list[dict[str, Any]],
) -> dict[str, Any]:
    initial = rank_results(enrich_results(dedupe_results(initial_results), query=query, years=years))
    initial_candidate_count = candidate_count(initial)
    queries = build_recovery_queries(query)
    source_overlap = sorted(set(sources) & RECALL_RECOVERY_SOURCES)
    should_run = bool(queries and source_overlap and initial_candidate_count < MIN_RECALL_CANDIDATES)
    agent_queries = queries if should_run else []
    return {
        "status": "will_run" if should_run else "not_needed",
        "reason": "weak_recall" if should_run else "",
        "should_run": should_run,
        "initial_candidate_count": initial_candidate_count,
        "minimum_candidates": MIN_RECALL_CANDIDATES,
        "queries": queries if should_run else [],
        "source_overlap": source_overlap,
        "agent_web_search_queries": agent_queries,
        "browser_search_queries": [
            {"engine": engine, "query": candidate}
            for candidate in agent_queries[:3]
            for engine in ["google", "baidu"]
        ],
        "notes": [
            "Recovery queries relax exact year pressure and must remain marked as leads unless evidence confirms the requested year.",
            "Agent web-search or browser-assisted search results should be imported through cloversec_ctf_import_agent_web_results or cloversec_ctf_browser_search_import_visible.",
        ],
    }


def candidate_count(results: list[dict[str, Any]]) -> int:
    return sum(
        1
        for item in results
        if item.get("layer") in {"confirmed_challenge", "writeup_candidate", "attachment_candidate"}
        and not has_blocking_candidate_issue(item)
    )


def has_blocking_candidate_issue(item: dict[str, Any]) -> bool:
    issues = [str(issue) for issue in item.get("quality_issues", [])]
    return any(issue == "year missing" or issue.startswith("year mismatch") for issue in issues)


def run_recovery_query(query: str, sources: list[str], *, limit: int) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    per_query_limit = max(3, min(limit, 8))
    if "duckduckgo" in sources:
        output.extend(mark_recovery_results(search_duckduckgo(query, limit=per_query_limit), query))
    for source in ["csdn", "cnblogs", "yuque"]:
        if source in sources:
            output.extend(mark_recovery_results(search_site_profile(source, query, limit=per_query_limit), query))
    return output


def mark_recovery_results(results: list[dict[str, Any]], recovery_query: str) -> list[dict[str, Any]]:
    marked = []
    for item in results:
        current = dict(item)
        metadata = dict(current.get("metadata") or {})
        metadata.update({"recovery_query": recovery_query, "recovery_reason": "weak_recall", "year_relaxed": True})
        current["metadata"] = metadata
        current["recovery_query"] = recovery_query
        current["year_relaxed"] = True
        marked.append(current)
    return marked


def build_recovery_queries(query: str) -> list[str]:
    compact = re.sub(r"\s+", " ", query).strip()
    if not compact:
        return []
    lowered = compact.lower()
    without_year = re.sub(r"\b20\d{2}\b", "", compact).strip()
    without_year = re.sub(r"\s+", " ", without_year)
    event_tokens = extract_event_tokens(compact)
    categories = [token for token in re.findall(r"[a-z0-9_.-]+", lowered) if token in CATEGORY_TERMS]
    category = categories[0] if categories else ""
    variants = []
    if without_year and without_year != compact:
        variants.append(without_year)
    for event in event_tokens:
        event_text = event
        if category:
            variants.extend(
                [
                    f"{event_text} {category} writeup",
                    f"{event_text} {category} wp",
                    f"{event_text} 网络安全大赛 {category} WriteUp",
                ]
            )
        variants.extend([f"{event_text} writeup", f"{event_text} WP"])
    if "writeup" not in lowered and "wp" not in lowered:
        variants.append(f"{compact} writeup")
    output = []
    seen = {normalize_query_key(compact)}
    for item in variants:
        normalized = re.sub(r"\s+", " ", item).strip()
        key = normalize_query_key(normalized)
        if not normalized or key in seen:
            continue
        seen.add(key)
        output.append(normalized)
        if len(output) >= MAX_RECOVERY_QUERIES:
            break
    return output


def normalize_query_key(query: str) -> str:
    return re.sub(r"\s+", " ", query.strip().lower())


def search_github_repositories(query: str, *, limit: int = 20) -> list[dict[str, Any]]:
    params = {
        "q": f"{query} ctf",
        "sort": "stars",
        "order": "desc",
        "per_page": str(min(max(limit, 1), 50)),
    }
    payload = github_json("/search/repositories", params=params)
    items = payload.get("items", []) if isinstance(payload, dict) else []
    results = []
    for item in items:
        if not isinstance(item, dict):
            continue
        results.append(
            normalize_result(
                provider="github",
                kind="repository",
                title=item.get("full_name") or item.get("name") or "",
                url=item.get("html_url") or "",
                summary=item.get("description") or "",
                source_type="github",
                confidence="medium",
                metadata={
                    "stars": item.get("stargazers_count", 0),
                    "updated_at": item.get("updated_at", ""),
                    "language": item.get("language", ""),
                },
            )
        )
    return results


def search_github_code(query: str, *, limit: int = 10) -> list[dict[str, Any]]:
    token = github_token()
    if not token:
        raise SearchSkipped("GITHUB_TOKEN/GH_TOKEN not set; GitHub code search skipped")
    params = {
        "q": f"{query} ctf filename:README OR filename:writeup OR filename:wp",
        "per_page": str(min(max(limit, 1), 50)),
    }
    payload = github_json("/search/code", params=params)
    items = payload.get("items", []) if isinstance(payload, dict) else []
    results = []
    for item in items:
        if not isinstance(item, dict):
            continue
        repo = item.get("repository") if isinstance(item.get("repository"), dict) else {}
        results.append(
            normalize_result(
                provider="github-code",
                kind="code",
                title=f"{repo.get('full_name', '')}/{item.get('path', '')}".strip("/"),
                url=item.get("html_url") or "",
                summary="GitHub code search match",
                source_type="github",
                confidence="medium",
                metadata={"repository": repo.get("full_name", ""), "path": item.get("path", "")},
            )
        )
    return results


def search_ctftime_events(*, year: int, query: str = "", limit: int = 100) -> list[dict[str, Any]]:
    start = int(datetime(year, 1, 1, tzinfo=timezone.utc).timestamp())
    finish = int(datetime(year + 1, 1, 1, tzinfo=timezone.utc).timestamp())
    url = "https://ctftime.org/api/v1/events/?" + urlencode(
        {"limit": min(max(limit, 1), 100), "start": start, "finish": finish}
    )
    payload = http_json(url)
    items = payload if isinstance(payload, list) else []
    query_terms = [
        term.lower()
        for term in re.findall(r"[\w.-]+", query)
        if len(term) > 1 and term.lower() not in GENERIC_EVENT_QUERY_TERMS
    ]
    results = []
    for item in items:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "")
        if query_terms and not any(term in title.lower() for term in query_terms):
            continue
        event_url = item.get("url") or item.get("ctftime_url") or ""
        results.append(
            normalize_result(
                provider="ctftime",
                kind="event",
                title=title,
                url=event_url,
                summary=f"{item.get('start', '')} - {item.get('finish', '')}".strip(" -"),
                source_type="ctftime",
                confidence="high",
                metadata={
                    "ctftime_url": item.get("ctftime_url", ""),
                    "format": item.get("format", ""),
                    "weight": item.get("weight", ""),
                    "onsite": item.get("onsite", ""),
                },
            )
        )
    return results


def search_ctftime_writeups(*, query: str, limit: int = 20) -> list[dict[str, Any]]:
    url = "https://ctftime.org/writeups"
    if query:
        url += "?" + urlencode({"q": query})
    fetched = fetch_url(url, max_bytes=2 * 1024 * 1024)
    return parse_ctftime_writeups(fetched.get("text", ""), source_url=url, limit=limit)


def parse_ctftime_writeups(html: str, *, source_url: str = "https://ctftime.org/writeups", limit: int = 20) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for match in re.finditer(r'href=["\'](?P<href>/writeup/\d+)["\'][^>]*>(?P<title>.*?)</a>', html, flags=re.I | re.S):
        title = clean_html(match.group("title"))
        href = match.group("href")
        results.append(
            normalize_result(
                provider="ctftime",
                kind="writeup",
                title=title,
                url="https://ctftime.org" + href,
                summary="CTFTime writeup page",
                source_type="ctftime",
                confidence="medium",
                metadata={"source_url": source_url},
            )
        )
        if len(results) >= limit:
            break
    return dedupe_results(results)


def search_duckduckgo(query: str, *, limit: int = 20) -> list[dict[str, Any]]:
    url = "https://lite.duckduckgo.com/lite/?" + urlencode({"q": query})
    fetched = fetch_url(url, max_bytes=2 * 1024 * 1024)
    html = fetched.get("text", "")
    results = []
    pattern = re.compile(r'<a[^>]+href=["\'](?P<href>[^"\']+)["\'][^>]*>(?P<title>.*?)</a>', re.I | re.S)
    for match in pattern.finditer(html):
        href = normalize_duckduckgo_href(unescape(match.group("href")))
        title = clean_html(match.group("title"))
        if not href.startswith(("http://", "https://")) or not title:
            continue
        results.append(
            normalize_result(
                provider="duckduckgo",
                kind="web",
                title=title,
                url=href,
                summary="DuckDuckGo HTML result",
                source_type="public_web",
                confidence="low",
            )
        )
        if len(results) >= limit:
            break
    return results


def normalize_duckduckgo_href(href: str) -> str:
    if href.startswith("//"):
        href = "https:" + href
    parsed = urlparse(href)
    if parsed.netloc.endswith("duckduckgo.com") and parsed.path.startswith("/l/"):
        target = parse_qs(parsed.query).get("uddg", [""])[0]
        return target or href
    return href


def seed_results(query: str = "") -> list[dict[str, Any]]:
    terms = [term.lower() for term in re.findall(r"[\w.-]+", query) if len(term) > 1]
    results = []
    for item in ARCHIVE_SEEDS:
        haystack = f"{item['title']} {item['summary']} {item['url']}".lower()
        if not terms or any(term in haystack for term in terms) or "ctf" in terms:
            results.append(normalize_result(**item))
    return results


def platform_seed_results(query: str = "") -> list[dict[str, Any]]:
    terms = [term.lower() for term in re.findall(r"[\w.-]+", query) if len(term) > 1]
    has_ctf = "ctf" in query.lower()
    results = []
    for item in CTF_PLATFORM_SEEDS:
        haystack = f"{item['title']} {item['summary']} {item['url']}".lower()
        if not terms or has_ctf or any(term in haystack for term in terms):
            results.append(normalize_result(**item))
    return results


def search_site_profile(profile: str, query: str, *, limit: int = 20) -> list[dict[str, Any]]:
    templates = SITE_SEARCH_PROFILES.get(profile)
    if not templates:
        raise ValueError(f"unsupported site search profile: {profile}")
    results: list[dict[str, Any]] = []
    per_query = max(3, min(limit, 10))
    for template in templates:
        profile_query = template.format(query=query)
        for item in search_duckduckgo(profile_query, limit=per_query):
            enriched = dict(item)
            enriched["provider"] = profile
            enriched["kind"] = "site_search"
            enriched["confidence"] = "medium" if profile in {"csdn", "cnblogs", "yuque"} else item.get("confidence", "low")
            metadata = dict(enriched.get("metadata") or {})
            metadata["search_provider"] = "duckduckgo"
            metadata["profile_query"] = profile_query
            enriched["metadata"] = metadata
            results.append(enriched)
            if len(results) >= limit:
                return dedupe_results(results)
    return dedupe_results(results)


def import_agent_search_results(
    payload: Any,
    *,
    query: str,
    provider: str = "agent-web-search",
    limit: int = 50,
) -> dict[str, Any]:
    rows = extract_agent_search_rows(payload)
    results = []
    for index, row in enumerate(rows[: max(limit, 0)], start=1):
        title = str(row.get("title") or row.get("name") or "").strip()
        url = str(row.get("url") or row.get("source_url") or row.get("link") or "").strip()
        snippet = str(row.get("snippet") or row.get("summary") or row.get("description") or "").strip()
        if not title or not url:
            continue
        results.append(
            normalize_result(
                provider=provider,
                kind="web",
                title=title,
                url=url,
                summary=snippet,
                source_type="agent_web_search",
                confidence=str(row.get("confidence") or "medium"),
                metadata={
                    "rank": row.get("rank", index),
                    "source_provider": row.get("provider") or provider,
                    "raw_provider": row.get("raw_provider", ""),
                },
            )
        )
    ranked = rank_results(enrich_results(dedupe_results(results), query=query, years=[]))
    return {
        "query": query,
        "generated_at": utc_now(),
        "sources": [provider],
        "results": ranked,
        "summary": {
            "total_results": len(ranked),
            "provider_counts": provider_counts(ranked),
            "layer_counts": layer_counts(ranked),
            "errors": 0,
        },
        "errors": [],
    }


def extract_agent_search_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ["results", "items", "web_results", "sources", "organic_results"]:
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    if {"title", "url"} & set(payload):
        return [payload]
    return []


def fetch_url(url: str, *, max_bytes: int = DEFAULT_MAX_BYTES, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    started = time.time()
    read_limit = max(max_bytes, 0) + 1
    response = http_request(url, timeout=timeout, read_limit=read_limit)
    status = response["status"]
    headers = response["headers"]
    body = response["body"][:max_bytes]
    truncated = len(response["body"]) > max_bytes
    text = ""
    content_type = headers.get("content-type", "")
    if is_text_content(content_type, url):
        text = decode_body(body, headers)
    return {
        "url": url,
        "status": status,
        "content_type": content_type,
        "size": len(body),
        "truncated": truncated,
        "sha256": sha256_bytes(body),
        "elapsed_ms": int((time.time() - started) * 1000),
        "text": text,
        "title": extract_title(text),
    }


def download_url(
    url: str,
    output_dir: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: int = DEFAULT_TIMEOUT,
    filename: str | None = None,
) -> dict[str, Any]:
    read_limit = max(max_bytes, 0) + 1
    response = http_request(url, timeout=timeout, read_limit=read_limit)
    body = response["body"][:max_bytes]
    truncated = len(response["body"]) > max_bytes
    status = response["status"]
    content_type = response["headers"].get("content-type", "")
    if status >= 400:
        return {
            "url": url,
            "status": status,
            "content_type": content_type,
            "size": len(body),
            "sha256": sha256_bytes(body),
            "truncated": truncated,
            "error": f"HTTP {status}",
        }
    parsed = urlparse(url)
    target_name = safe_filename(filename or Path(parsed.path).name or "download.bin")
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    path = output / target_name
    path.write_bytes(body)
    return {
        "url": url,
        "status": status,
        "content_type": content_type,
        "local_path": path.as_posix(),
        "name": path.name,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
        "truncated": truncated,
        "asset_type": classify_download(path, content_type),
    }


def download_from_manifest(
    manifest: dict[str, Any],
    output_dir: str | Path,
    *,
    max_files: int = 10,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict[str, Any]:
    downloads = []
    issues = []
    for result in manifest.get("results", []):
        if len(downloads) >= max_files:
            break
        if not isinstance(result, dict):
            continue
        url = str(result.get("url") or "")
        if not looks_direct_asset_url(url):
            continue
        try:
            record = download_url(url, output_dir, max_bytes=max_bytes)
            if record.get("error"):
                issues.append(record)
            else:
                downloads.append(record)
        except Exception as exc:  # noqa: BLE001
            issues.append({"url": url, "error": str(exc)})
    return {
        "generated_at": utc_now(),
        "output_dir": Path(output_dir).as_posix(),
        "downloads": downloads,
        "issues": issues,
        "summary": {"downloaded": len(downloads), "issues": len(issues)},
    }


def results_to_cases(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    cases = []
    for index, result in enumerate(manifest.get("results", []), start=1):
        if not isinstance(result, dict):
            continue
        if result.get("layer") in {"noise", "platform_lead"}:
            continue
        title = str(result.get("title") or "").strip()
        if not title:
            continue
        source_type = result.get("source_type") or "public_web"
        case_id = f"research-{index:06d}"
        cases.append(
            {
                "case_id": case_id,
                "source_files": [],
                "research": {"query": manifest.get("query", ""), "provider": result.get("provider", "")},
                "asset_collection": {},
                "metadata": {
                    "赛事来源": result.get("metadata", {}).get("event", "") if isinstance(result.get("metadata"), dict) else "",
                    "题目来源": title,
                    "名称": title,
                    "分类": "",
                    "题目类型": "未知",
                    "Flag类型": "未知",
                    "Flag": "",
                    "材料状态": "收集中",
                    "构建状态": "未开始",
                    "手册状态": "未开始",
                    "验证状态": "未验证",
                    "是否归档": "否",
                    "是否通过": "否",
                    "问题": "",
                },
                "flag": {"value": "", "type": "unknown", "sensitive": True},
                "environment": {},
                "docker_artifacts": {},
                "attachments": [],
                "writeup": {},
                "hub_fields": {},
                "review": {},
                "archive": {},
                "evidence": [
                    {
                        "source_url": result.get("url", ""),
                        "source_type": source_type,
                        "title": title,
                        "accessed_at": utc_date(),
                        "summary": result.get("summary", ""),
                        "confidence": result.get("confidence", "low"),
                        "layer": result.get("layer", ""),
                        "score": result.get("score", 0),
                        "quality_issues": result.get("quality_issues", []),
                        "status": "found",
                    }
                ],
                "confidence": result.get("confidence", "low"),
            }
        )
    return cases


def normalize_repo_name(repo: str) -> str:
    owner, repo_name = parse_github_repo(repo)
    return f"{owner}/{repo_name}"


def safe_normalize_repo_name(repo: str) -> str:
    try:
        return normalize_repo_name(repo)
    except Exception:  # noqa: BLE001 - report the original user input in structured errors.
        return str(repo).strip()


def provider_issue(provider: str, exc: Exception, *, status: str = "failed") -> dict[str, str]:
    return {"provider": provider, "status": status, "error": str(exc)}


def github_raw_file_url(owner: str, repo: str, ref: str, path: str) -> str:
    encoded_path = "/".join(quote(part) for part in path.split("/"))
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{quote(ref)}/{encoded_path}"


def relative_tree_output_path(file_path: str, prefix: str = "") -> Path:
    cleaned = file_path.strip("/")
    base = prefix.strip("/")
    if base and (cleaned == base or cleaned.startswith(base + "/")):
        cleaned = cleaned[len(base) :].strip("/")
    parts = [part for part in cleaned.split("/") if part]
    if not parts or any(part in {"..", "."} for part in parts):
        raise ValueError(f"unsafe GitHub tree path: {file_path}")
    return Path(*[safe_filename(part) for part in parts])


def archive_entry_record(name: str, size: int, is_dir: bool) -> dict[str, Any]:
    return {
        "path": name,
        "name": Path(name).name,
        "size": size,
        "is_dir": is_dir,
        "unsafe_path": is_unsafe_archive_path(name),
    }


def is_unsafe_archive_path(name: str) -> bool:
    path = Path(name)
    return path.is_absolute() or any(part in {"..", ""} for part in path.parts)


def github_json(path: str, *, params: dict[str, Any]) -> Any:
    url = "https://api.github.com" + path + "?" + urlencode(params)
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = http_json(url, headers=headers)
    if isinstance(payload, dict) and payload.get("message") and payload.get("documentation_url"):
        raise RuntimeError(f"GitHub API error: {payload.get('message')}")
    return payload


def github_token() -> str:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token
    if os.environ.get("CLOVERSEC_DISABLE_GH_AUTH_TOKEN") == "1":
        return ""
    try:
        result = subprocess.run(
            ["gh", "auth", "token"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def http_json(url: str, *, headers: dict[str, str] | None = None, timeout: int = DEFAULT_TIMEOUT) -> Any:
    response = http_request(url, headers=headers, timeout=timeout)
    return json.loads(decode_body(response["body"], response["headers"]))


def http_request(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    read_limit: int = DEFAULT_MAX_BYTES + 1,
) -> dict[str, Any]:
    validate_http_url(url)
    merged_headers = {"User-Agent": USER_AGENT}
    if headers:
        merged_headers.update(headers)
    request = Request(url, headers=merged_headers)
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - public-source fetch helper.
            body = response.read(read_limit)
            return {
                "status": getattr(response, "status", 200),
                "headers": {key.lower(): value for key, value in response.headers.items()},
                "body": body,
            }
    except HTTPError as exc:
        try:
            body = exc.read(read_limit)
            return {
                "status": exc.code,
                "headers": {key.lower(): value for key, value in exc.headers.items()},
                "body": body,
            }
        finally:
            exc.close()
    except URLError as exc:
        raise RuntimeError(f"failed to fetch {url}: {exc}") from exc


def validate_http_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES or not parsed.netloc:
        raise ValueError("only http and https URLs are supported")


def normalize_result(
    *,
    provider: str,
    kind: str,
    title: str,
    url: str,
    summary: str,
    source_type: str,
    confidence: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    clean_url = str(url or "").strip()
    clean_summary = str(summary or "").strip()
    return {
        "provider": provider,
        "kind": kind,
        "title": str(title or "").strip(),
        "url": clean_url,
        "source_url": clean_url,
        "summary": clean_summary,
        "snippet": clean_summary,
        "source_type": source_type,
        "confidence": confidence,
        "metadata": metadata or {},
    }


def enrich_results(results: list[dict[str, Any]], *, query: str, years: list[int] | None = None) -> list[dict[str, Any]]:
    profile = build_query_profile(query, years=years or [])
    enriched = []
    for item in results:
        current = dict(item)
        layer, score, reasons, issues = classify_result(current, profile)
        current["layer"] = layer
        current["score"] = score
        current["lead_only"] = layer == "platform_lead"
        current["ranking_reasons"] = reasons
        current["quality_issues"] = issues
        current["evidence"] = {
            "source_url": current.get("url", ""),
            "title": current.get("title", ""),
            "snippet": current.get("summary", ""),
            "provider": current.get("provider", ""),
            "captured_at": utc_now(),
            "search_query": query,
        }
        enriched.append(current)
    return enriched


def build_query_profile(query: str, *, years: list[int]) -> dict[str, Any]:
    lowered = query.lower()
    tokens = [token.lower() for token in re.findall(r"[a-z0-9_.-]+", lowered)]
    year_terms = {str(year) for year in years}
    year_terms.update(token for token in tokens if re.fullmatch(r"20\d{2}", token))
    event_terms = {
        token.strip("._-")
        for token in extract_event_tokens(lowered)
        if token.lower() not in GENERIC_EVENT_QUERY_TERMS
    }
    event_phrases = set()
    event_component_terms = set()
    for prefix in re.findall(r"\b([a-z0-9][a-z0-9_.-]*)\s+ctf\b", lowered):
        if prefix.lower() not in GENERIC_EVENT_QUERY_TERMS:
            cleaned = prefix.strip("._-").lower()
            event_terms.add(f"{cleaned}ctf")
            event_phrases.add(f"{cleaned} ctf")
            event_component_terms.add(cleaned)
    meaningful_terms = {
        token
        for token in tokens
        if len(token) > 1 and token not in GENERIC_EVENT_QUERY_TERMS and token not in year_terms
    }
    categories = {token for token in tokens if token in CATEGORY_TERMS}
    query_specific_terms = meaningful_terms - event_terms - event_component_terms
    return {
        "query": query,
        "tokens": tokens,
        "event_terms": event_terms,
        "event_phrases": event_phrases,
        "year_terms": year_terms,
        "meaningful_terms": meaningful_terms,
        "query_specific_terms": query_specific_terms,
        "categories": categories,
    }


def classify_result(result: dict[str, Any], profile: dict[str, Any]) -> tuple[str, int, list[str], list[str]]:
    title = str(result.get("title") or "")
    url = str(result.get("url") or "")
    summary = str(result.get("summary") or "")
    provider = str(result.get("provider") or "")
    kind = str(result.get("kind") or "")
    haystack = f"{title} {url} {summary}".lower()
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    score = 0
    reasons: list[str] = []
    issues: list[str] = []

    if provider == "ctf-platforms" or kind == "ctf_platform":
        return "platform_lead", 10, ["platform homepage lead"], ["platform homepage is not a confirmed challenge"]

    if is_search_or_login_noise(url):
        return "noise", -100, [], ["search engine, login, or blocked page"]

    if any(term in haystack for term in TUTORIAL_NOISE_TERMS):
        score -= 55
        issues.append("broad tutorial page")

    event_terms: set[str] = set(profile.get("event_terms") or set())
    event_phrases: set[str] = set(profile.get("event_phrases") or set())
    year_terms: set[str] = set(profile.get("year_terms") or set())
    categories: set[str] = set(profile.get("categories") or set())

    if event_terms:
        if event_name_matches(haystack, event_terms, event_phrases):
            score += 55
            reasons.append("event name matched")
        else:
            score -= 70
            issues.append("event name mismatch")

        foreign_events = {token.lower() for token in extract_event_tokens(haystack) if not is_same_event_token(token.lower(), event_terms)}
        if foreign_events:
            score -= 45
            issues.append(f"other event names found: {', '.join(sorted(foreign_events)[:5])}")

    if year_terms:
        found_years = set(re.findall(r"(?<!\d)20\d{2}(?!\d)", haystack))
        wrong_years = sorted(found_years - year_terms)
        if found_years & year_terms:
            score += 12
            reasons.append("year matched")
            if wrong_years:
                score -= 8
                issues.append(f"other years found: {', '.join(wrong_years[:5])}")
        elif wrong_years:
            score -= 55
            issues.append(f"year mismatch: {', '.join(wrong_years[:5])}")
        else:
            score -= 12
            issues.append("year missing")

    if categories and any(category in haystack for category in categories):
        score += 10
        reasons.append("category matched")

    if looks_attachment_candidate_url(url) or kind == "release_asset" or (kind == "raw_file" and any(term in haystack for term in ATTACHMENT_TERMS)):
        score += 30
        reasons.append("direct asset or release file")
        layer = "attachment_candidate"
    elif any(term in haystack for term in WRITEUP_TERMS) or kind in {"writeup", "code", "site_search"}:
        score += 18
        reasons.append("writeup or code clue")
        layer = "writeup_candidate"
    elif provider in {"github", "github-code", "github-release", "github-tree"}:
        score += 12
        reasons.append("github source")
        layer = "writeup_candidate"
    elif provider == "ctftime" and kind == "event":
        score += 10
        reasons.append("ctftime event lead")
        layer = "platform_lead"
    else:
        layer = "writeup_candidate"

    if any(term in haystack for term in ATTACHMENT_TERMS):
        score += 10
        reasons.append("attachment keyword")

    if domain.endswith("csdn.net") or domain.endswith("cnblogs.com") or domain.endswith("yuque.com"):
        score += 4
        reasons.append("targeted site profile")

    if score < 5 or "event name mismatch" in issues or any(issue.startswith("year mismatch") for issue in issues):
        layer = "noise"

    if (
        layer == "writeup_candidate"
        and score >= 85
        and event_terms
        and year_terms
        and has_challenge_specific_evidence(haystack, profile)
    ):
        layer = "confirmed_challenge"
        reasons.append("strong event/year/challenge evidence")

    return layer, score, reasons, issues


def has_challenge_specific_evidence(haystack: str, profile: dict[str, Any]) -> bool:
    terms: set[str] = set(profile.get("query_specific_terms") or set())
    return bool(terms) and all(term in haystack for term in terms)


def event_name_matches(haystack: str, event_terms: set[str], event_phrases: set[str]) -> bool:
    normalized = normalize_event_text(haystack)
    if any(normalize_event_text(term) in normalized for term in event_terms if normalize_event_text(term)):
        return True
    return any(phrase in haystack for phrase in event_phrases)


def is_same_event_token(token: str, event_terms: set[str]) -> bool:
    normalized = token.strip("._-").lower()
    condensed = normalize_event_text(normalized)
    for event in event_terms:
        event_name = event.strip("._-").lower()
        event_condensed = normalize_event_text(event_name)
        if normalized == event_name or condensed == event_condensed:
            return True
        if event_condensed and condensed.startswith(event_condensed):
            return True
        if event_condensed and condensed.endswith(event_condensed):
            prefix = condensed[: -len(event_condensed)]
            if re.fullmatch(r"(?:20\d{2}|wp|writeup|复现|题解|年)+", prefix):
                return True
            if contains_cjk(prefix) and len(prefix) <= 4:
                return True
        if event_condensed and event_condensed in condensed:
            prefix, suffix = condensed.split(event_condensed, 1)
            if is_generic_event_affix(prefix) and is_generic_event_affix(suffix):
                return True
        if event_condensed and contains_cjk(event_condensed) and event_condensed in condensed:
            return True
    return False


def extract_event_tokens(text: str) -> list[str]:
    tokens = EVENT_TOKEN_RE.findall(text)
    tokens.extend(CJK_EVENT_RE.findall(text))
    output = []
    seen = set()
    for token in tokens:
        cleaned = token.strip("._-").lower()
        if cleaned in GENERIC_CJK_EVENT_TERMS:
            continue
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        output.append(cleaned)
    return output


def normalize_event_text(text: str) -> str:
    return re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", text.lower())


def contains_cjk(text: str) -> bool:
    return bool(re.search(r"[\u4e00-\u9fff]", text))


def is_generic_event_affix(text: str) -> bool:
    if not text:
        return True
    stripped = text
    stripped = re.sub(r"20\d{2}", "", stripped)
    for term in [
        "official",
        "writeup",
        "writeups",
        "docker",
        "wp",
        "challenge",
        "challenges",
        "qual",
        "quals",
        "final",
        "复现",
        "题解",
        "个人",
        "官方",
        "上",
        "下",
        "年",
    ]:
        stripped = stripped.replace(term, "")
    if not stripped:
        return True
    return contains_cjk(stripped) and len(stripped) <= 4


def looks_attachment_candidate_url(url: str) -> bool:
    parsed = urlparse(str(url or ""))
    path = parsed.path.lower()
    suffixes = Path(path).suffixes
    suffix = suffixes[-1] if suffixes else ""
    if suffix in ATTACHMENT_CANDIDATE_EXTENSIONS:
        return True
    return "/releases/download/" in path or "challenge.zip" in path or "attachments" in path


def is_search_or_login_noise(url: str) -> bool:
    parsed = urlparse(str(url or ""))
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    if not domain:
        return True
    if domain in SEARCH_ENGINE_DOMAINS:
        if path in {"", "/", "/search", "/s", "/lite/"} or path.startswith(("/search", "/s", "/lite")):
            return True
    if domain in LOGIN_OR_BLOCK_DOMAINS or f"{domain}{path}" in LOGIN_OR_BLOCK_DOMAINS:
        return True
    if "captcha" in path or "verify" in path:
        return True
    return False


def rank_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        results,
        key=lambda item: (
            LAYER_PRIORITY.get(str(item.get("layer") or "noise"), 9),
            -int(item.get("score") or 0),
            str(item.get("provider") or ""),
            str(item.get("title") or "").lower(),
        ),
    )


def dedupe_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for item in results:
        url = str(item.get("url") or "").rstrip("/")
        title = str(item.get("title") or "")
        key = (url.lower(), title.lower())
        if not url or key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def provider_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in results:
        provider = str(item.get("provider") or "unknown")
        counts[provider] = counts.get(provider, 0) + 1
    return counts


def layer_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in results:
        layer = str(item.get("layer") or "unknown")
        counts[layer] = counts.get(layer, 0) + 1
    return counts


def clean_html(value: Any) -> str:
    text = re.sub(r"<[^>]+>", " ", str(value or ""))
    text = unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def extract_title(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.I | re.S)
    return clean_html(match.group(1)) if match else ""


def decode_body(body: bytes, headers: dict[str, str]) -> str:
    content_type = headers.get("content-type", "")
    match = re.search(r"charset=([^;\s]+)", content_type, flags=re.I)
    encodings = [match.group(1)] if match else []
    encodings.extend(["utf-8", "gb18030", "latin-1"])
    for encoding in encodings:
        try:
            return body.decode(encoding, errors="replace")
        except LookupError:
            continue
    return body.decode("utf-8", errors="replace")


def is_text_content(content_type: str, url: str) -> bool:
    lowered = content_type.lower()
    if any(marker in lowered for marker in ["text/", "json", "xml", "html", "markdown"]):
        return True
    return Path(urlparse(url).path).suffix.lower() in {".md", ".txt", ".json", ".html", ".htm", ".xml"}


def looks_direct_asset_url(url: str) -> bool:
    return Path(urlparse(url).path).suffix.lower() in DIRECT_ASSET_EXTENSIONS


def classify_download(path: Path, content_type: str) -> str:
    suffix = path.suffix.lower()
    if suffix in {".zip", ".7z", ".rar", ".tar", ".tgz", ".gz", ".xz", ".bz2"}:
        return "attachment"
    if suffix in {".md", ".txt", ".pdf"} or "pdf" in content_type:
        return "writeup"
    if suffix in {".png", ".jpg", ".jpeg", ".webp"}:
        return "screenshot"
    return "download"


def safe_filename(value: str) -> str:
    name = Path(value).name or "download.bin"
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip(".-")
    return cleaned[:120] or "download.bin"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def utc_date() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def write_json(path: str | Path, payload: Any) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: str | Path, rows: list[dict[str, Any]]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + ("\n" if rows else ""), encoding="utf-8")


class SearchSkipped(RuntimeError):
    """Raised when an optional provider lacks credentials."""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF public-source search utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover_parser = subparsers.add_parser("discover", help="search public sources and write a result manifest")
    discover_parser.add_argument("--query", required=True)
    discover_parser.add_argument("--year", type=int, action="append", default=[])
    discover_parser.add_argument(
        "--source",
        action="append",
        choices=SEARCH_SOURCES,
    )
    discover_parser.add_argument("--limit", type=int, default=20)
    discover_parser.add_argument("--output", required=True)
    discover_parser.add_argument("--cases-jsonl")

    events_parser = subparsers.add_parser("ctftime-events", help="fetch CTFTime events for one year")
    events_parser.add_argument("--year", type=int, required=True)
    events_parser.add_argument("--query", default="")
    events_parser.add_argument("--limit", type=int, default=100)
    events_parser.add_argument("--output", required=True)

    fetch_parser = subparsers.add_parser("fetch-url", help="fetch one URL and write metadata/text JSON")
    fetch_parser.add_argument("url")
    fetch_parser.add_argument("--max-bytes", type=int, default=2 * 1024 * 1024)
    fetch_parser.add_argument("--output", required=True)

    download_parser = subparsers.add_parser("download-url", help="download one URL and write file metadata")
    download_parser.add_argument("url")
    download_parser.add_argument("--output-dir", required=True)
    download_parser.add_argument("--filename")
    download_parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    download_parser.add_argument("--output", required=True)

    download_manifest_parser = subparsers.add_parser("download-from-manifest", help="download direct asset URLs from search results")
    download_manifest_parser.add_argument("--manifest", required=True)
    download_manifest_parser.add_argument("--output-dir", required=True)
    download_manifest_parser.add_argument("--max-files", type=int, default=10)
    download_manifest_parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    download_manifest_parser.add_argument("--output", required=True)

    release_assets_parser = subparsers.add_parser("github-release-assets", help="list GitHub release downloadable assets")
    release_assets_parser.add_argument("--repo", required=True, help="owner/repo or github.com URL")
    release_assets_parser.add_argument("--limit", type=int, default=30)
    release_assets_parser.add_argument("--output", required=True)

    download_release_parser = subparsers.add_parser("download-github-release-assets", help="download GitHub release assets")
    download_release_parser.add_argument("--repo", required=True, help="owner/repo or github.com URL")
    download_release_parser.add_argument("--output-dir", required=True)
    download_release_parser.add_argument("--max-files", type=int, default=10)
    download_release_parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    download_release_parser.add_argument("--pattern", default="")
    download_release_parser.add_argument("--output", required=True)

    raw_parser = subparsers.add_parser("download-github-raw", help="download one GitHub blob/raw URL")
    raw_parser.add_argument("url")
    raw_parser.add_argument("--output-dir", required=True)
    raw_parser.add_argument("--filename")
    raw_parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    raw_parser.add_argument("--output", required=True)

    tree_parser = subparsers.add_parser("download-github-tree", help="download files from a GitHub repository tree")
    tree_parser.add_argument("--repo", required=True, help="owner/repo or github.com URL")
    tree_parser.add_argument("--ref", default="main")
    tree_parser.add_argument("--path-prefix", default="")
    tree_parser.add_argument("--output-dir", required=True)
    tree_parser.add_argument("--max-files", type=int, default=30)
    tree_parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    tree_parser.add_argument("--asset-only", action="store_true")
    tree_parser.add_argument("--output", required=True)

    preview_parser = subparsers.add_parser("preview-archive", help="preview zip/tar archive entries without extraction")
    preview_parser.add_argument("archive")
    preview_parser.add_argument("--max-entries", type=int, default=200)
    preview_parser.add_argument("--output", required=True)

    cases_parser = subparsers.add_parser("results-to-cases", help="convert search results to ctf_cases.jsonl draft")
    cases_parser.add_argument("--manifest", required=True)
    cases_parser.add_argument("--output", required=True)

    agent_parser = subparsers.add_parser("import-agent-search", help="normalize Agent web search results into a scored search manifest")
    agent_parser.add_argument("--input", required=True, help="JSON list or object containing web search results")
    agent_parser.add_argument("--query", required=True)
    agent_parser.add_argument("--provider", default="agent-web-search")
    agent_parser.add_argument("--limit", type=int, default=50)
    agent_parser.add_argument("--output", required=True)

    args = parser.parse_args(argv)

    if args.command == "discover":
        payload = discover(args.query, years=args.year, sources=args.source, limit=args.limit)
        write_json(args.output, payload)
        if args.cases_jsonl:
            write_jsonl(args.cases_jsonl, results_to_cases(payload))
        print(f"wrote {args.output}")
        return 0

    if args.command == "ctftime-events":
        payload = {
            "year": args.year,
            "query": args.query,
            "generated_at": utc_now(),
            "results": search_ctftime_events(year=args.year, query=args.query, limit=args.limit),
        }
        payload["summary"] = {"total_results": len(payload["results"])}
        write_json(args.output, payload)
        print(f"wrote {args.output}")
        return 0

    if args.command == "fetch-url":
        write_json(args.output, fetch_url(args.url, max_bytes=args.max_bytes))
        print(f"wrote {args.output}")
        return 0

    if args.command == "download-url":
        payload = download_url(args.url, args.output_dir, max_bytes=args.max_bytes, filename=args.filename)
        write_json(args.output, payload)
        print(f"wrote {args.output}")
        return 0

    if args.command == "download-from-manifest":
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        payload = download_from_manifest(manifest, args.output_dir, max_files=args.max_files, max_bytes=args.max_bytes)
        write_json(args.output, payload)
        print(f"wrote {args.output}")
        return 0

    if args.command == "github-release-assets":
        errors: list[dict[str, str]] = []
        try:
            results = github_release_assets(args.repo, limit=args.limit)
        except Exception as exc:  # noqa: BLE001 - return machine-readable provider failure instead of traceback.
            results = []
            errors.append(provider_issue("github-release", exc))
        payload = {
            "repository": safe_normalize_repo_name(args.repo),
            "generated_at": utc_now(),
            "results": results,
            "errors": errors,
        }
        payload["summary"] = {"total_results": len(payload["results"]), "errors": len(errors)}
        write_json(args.output, payload)
        print(f"wrote {args.output}")
        return 0

    if args.command == "download-github-release-assets":
        payload = download_github_release_assets(
            args.repo,
            args.output_dir,
            max_files=args.max_files,
            max_bytes=args.max_bytes,
            pattern=args.pattern,
        )
        write_json(args.output, payload)
        print(f"wrote {args.output}")
        return 0

    if args.command == "download-github-raw":
        raw_url = github_blob_to_raw_url(args.url)
        payload = download_url(raw_url, args.output_dir, max_bytes=args.max_bytes, filename=args.filename)
        payload["source_url"] = args.url
        payload["raw_url"] = raw_url
        write_json(args.output, payload)
        print(f"wrote {args.output}")
        return 0

    if args.command == "download-github-tree":
        payload = download_github_tree(
            args.repo,
            args.output_dir,
            ref=args.ref,
            path_prefix=args.path_prefix,
            max_files=args.max_files,
            max_bytes=args.max_bytes,
            asset_only=args.asset_only,
        )
        write_json(args.output, payload)
        print(f"wrote {args.output}")
        return 0

    if args.command == "preview-archive":
        write_json(args.output, preview_archive(args.archive, max_entries=args.max_entries))
        print(f"wrote {args.output}")
        return 0

    if args.command == "results-to-cases":
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        write_jsonl(args.output, results_to_cases(manifest))
        print(f"wrote {args.output}")
        return 0

    if args.command == "import-agent-search":
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
        write_json(
            args.output,
            import_agent_search_results(payload, query=args.query, provider=args.provider, limit=args.limit),
        )
        print(f"wrote {args.output}")
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
