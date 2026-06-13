#!/usr/bin/env python3
"""Public-source CTF search, fetch, and download helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen


DEFAULT_TIMEOUT = 20
DEFAULT_MAX_BYTES = 50 * 1024 * 1024
USER_AGENT = "CloverSec-CTF-ForExample/0.1 (+https://github.com/D1a0y1bb/CloverSec-CTF-ForExample)"
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


def discover(
    query: str,
    *,
    years: list[int] | None = None,
    sources: list[str] | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    selected = sources or ["github", "ctftime", "duckduckgo", "brave", "bing", "seeds"]
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
            elif source == "brave":
                results.extend(search_brave(query, limit=limit))
            elif source == "bing":
                results.extend(search_bing(query, limit=limit))
            elif source == "seeds":
                results.extend(seed_results(query))
            else:
                errors.append({"provider": source, "error": "unsupported source"})
        except SearchSkipped as exc:
            errors.append({"provider": source, "error": str(exc), "status": "skipped"})
        except Exception as exc:  # noqa: BLE001 - command line tool must keep provider failures isolated.
            errors.append({"provider": source, "error": str(exc), "status": "failed"})

    deduped = dedupe_results(results)
    return {
        "query": query,
        "years": years or [],
        "generated_at": utc_now(),
        "sources": selected,
        "results": deduped[: max(limit, 0) * max(len(selected), 1)],
        "summary": {
            "total_results": len(deduped),
            "provider_counts": provider_counts(deduped),
            "errors": len(errors),
        },
        "errors": errors,
    }


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
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
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


def search_brave(query: str, *, limit: int = 20) -> list[dict[str, Any]]:
    key = os.environ.get("BRAVE_SEARCH_API_KEY") or os.environ.get("CLOVERSEC_BRAVE_API_KEY")
    if not key:
        raise SearchSkipped("BRAVE_SEARCH_API_KEY/CLOVERSEC_BRAVE_API_KEY not set")
    url = "https://api.search.brave.com/res/v1/web/search?" + urlencode({"q": query, "count": min(max(limit, 1), 20)})
    payload = http_json(url, headers={"X-Subscription-Token": key, "Accept": "application/json"})
    items = payload.get("web", {}).get("results", []) if isinstance(payload, dict) else []
    return [
        normalize_result(
            provider="brave",
            kind="web",
            title=item.get("title", ""),
            url=item.get("url", ""),
            summary=clean_html(item.get("description", "")),
            source_type="public_web",
            confidence="medium",
        )
        for item in items
        if isinstance(item, dict)
    ]


def search_bing(query: str, *, limit: int = 20) -> list[dict[str, Any]]:
    key = os.environ.get("BING_SEARCH_API_KEY") or os.environ.get("CLOVERSEC_BING_API_KEY")
    if not key:
        raise SearchSkipped("BING_SEARCH_API_KEY/CLOVERSEC_BING_API_KEY not set")
    url = "https://api.bing.microsoft.com/v7.0/search?" + urlencode({"q": query, "count": min(max(limit, 1), 50)})
    payload = http_json(url, headers={"Ocp-Apim-Subscription-Key": key})
    items = payload.get("webPages", {}).get("value", []) if isinstance(payload, dict) else []
    return [
        normalize_result(
            provider="bing",
            kind="web",
            title=item.get("name", ""),
            url=item.get("url", ""),
            summary=item.get("snippet", ""),
            source_type="public_web",
            confidence="medium",
        )
        for item in items
        if isinstance(item, dict)
    ]


def seed_results(query: str = "") -> list[dict[str, Any]]:
    terms = [term.lower() for term in re.findall(r"[\w.-]+", query) if len(term) > 1]
    results = []
    for item in ARCHIVE_SEEDS:
        haystack = f"{item['title']} {item['summary']} {item['url']}".lower()
        if not terms or any(term in haystack for term in terms) or "ctf" in terms:
            results.append(normalize_result(**item))
    return results


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
                        "status": "found",
                    }
                ],
                "confidence": result.get("confidence", "low"),
            }
        )
    return cases


def github_json(path: str, *, params: dict[str, Any]) -> Any:
    url = "https://api.github.com" + path + "?" + urlencode(params)
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return http_json(url, headers=headers)


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
    return {
        "provider": provider,
        "kind": kind,
        "title": str(title or "").strip(),
        "url": str(url or "").strip(),
        "summary": str(summary or "").strip(),
        "source_type": source_type,
        "confidence": confidence,
        "metadata": metadata or {},
    }


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
        choices=["github", "github-code", "ctftime", "duckduckgo", "brave", "bing", "seeds"],
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

    cases_parser = subparsers.add_parser("results-to-cases", help="convert search results to ctf_cases.jsonl draft")
    cases_parser.add_argument("--manifest", required=True)
    cases_parser.add_argument("--output", required=True)

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

    if args.command == "results-to-cases":
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        write_jsonl(args.output, results_to_cases(manifest))
        print(f"wrote {args.output}")
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
