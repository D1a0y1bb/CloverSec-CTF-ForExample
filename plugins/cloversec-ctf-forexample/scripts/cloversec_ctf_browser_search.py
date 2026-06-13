#!/usr/bin/env python3
"""Browser-assisted search planning and visible-result normalization."""

from __future__ import annotations

import argparse
import json
import platform
import re
import subprocess
from html import unescape
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse

import cloversec_ctf_search as search


BROWSER_SEARCH_ENGINES = {
    "google": {
        "display_name": "Google",
        "base_url": "https://www.google.com/search",
        "query_param": "q",
        "blocked_indicators": ["captcha", "unusual traffic", "sorry/index", "detected unusual"],
    },
    "baidu": {
        "display_name": "Baidu",
        "base_url": "https://www.baidu.com/s",
        "query_param": "wd",
        "blocked_indicators": ["verify", "wappass.baidu.com", "passport.baidu.com", "安全验证"],
    },
    "csdn": {
        "display_name": "CSDN",
        "base_url": "https://so.csdn.net/so/search",
        "query_param": "q",
        "blocked_indicators": ["passport.csdn.net", "登录", "验证码"],
    },
    "cnblogs": {
        "display_name": "Cnblogs",
        "base_url": "https://zzk.cnblogs.com/s/blogpost",
        "query_param": "Keywords",
        "blocked_indicators": ["验证码", "captcha"],
    },
    "yuque": {
        "display_name": "Yuque via Google site search",
        "base_url": "https://www.google.com/search",
        "query_param": "q",
        "prefix": "site:yuque.com ",
        "blocked_indicators": ["captcha", "unusual traffic", "sorry/index", "detected unusual"],
    },
}


def create_browser_search_plan(query: str, *, engine: str = "google", open_browser: bool = False) -> dict[str, Any]:
    if engine not in BROWSER_SEARCH_ENGINES:
        raise ValueError(f"unsupported browser search engine: {engine}")
    profile = BROWSER_SEARCH_ENGINES[engine]
    url = build_search_url(profile, query)
    opened = False
    open_error = ""
    if open_browser:
        opened, open_error = open_url(url)
    return {
        "query": query,
        "engine": engine,
        "display_name": profile["display_name"],
        "search_url": url,
        "opened": opened,
        "open_error": open_error,
        "privacy_boundary": [
            "只读取页面可见的标题、URL、摘要、排名和搜索词。",
            "不读取或保存 Cookie、token、localStorage、sessionStorage、密码或验证码。",
            "遇到验证码、登录墙、风控页时标记 blocked_by_captcha，不做绕过。",
        ],
        "visible_result_schema": {
            "results": [
                {
                    "rank": 1,
                    "title": "visible title",
                    "url": "https://example.com/result",
                    "snippet": "visible snippet",
                }
            ],
            "blocked_by_captcha": False,
            "blocked_reason": "",
        },
        "blocked_indicators": profile["blocked_indicators"],
    }


def build_search_url(profile: dict[str, Any], query: str) -> str:
    search_query = f"{profile.get('prefix', '')}{query}"
    return str(profile["base_url"]) + "?" + urlencode({str(profile["query_param"]): search_query})


def open_url(url: str) -> tuple[bool, str]:
    system = platform.system().lower()
    if system != "darwin":
        return False, "automatic browser opening is only implemented for macOS"
    try:
        result = subprocess.run(["open", url], capture_output=True, text=True, timeout=5, check=False)
    except Exception as exc:  # noqa: BLE001 - returned as structured error.
        return False, str(exc)
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or "open command failed").strip()
    return True, ""


def normalize_visible_results(payload: dict[str, Any], *, query: str, engine: str) -> dict[str, Any]:
    if bool(payload.get("blocked_by_captcha")):
        return {
            "query": query,
            "engine": engine,
            "generated_at": search.utc_now(),
            "results": [],
            "errors": [
                {
                    "provider": f"browser-{engine}",
                    "status": "blocked_by_captcha",
                    "error": str(payload.get("blocked_reason") or "browser search blocked by captcha or risk control"),
                }
            ],
            "summary": {"total_results": 0, "errors": 1, "layer_counts": {}},
        }
    rows = []
    for index, item in enumerate(payload.get("results", []), start=1):
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "rank": item.get("rank", index),
                "title": item.get("title", ""),
                "url": clean_visible_url(str(item.get("url") or "")),
                "snippet": item.get("snippet", item.get("summary", "")),
                "provider": f"browser-{engine}",
                "raw_provider": engine,
            }
        )
    return search.import_agent_search_results(rows, query=query, provider=f"browser-{engine}", limit=len(rows) or 50)


def dom_to_visible_results(
    payload: dict[str, Any],
    *,
    query: str,
    engine: str,
    page_url: str = "",
    limit: int = 50,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    profile = BROWSER_SEARCH_ENGINES.get(engine, {})
    text = collect_visible_text(payload)
    blocked_reason = detect_blocked_reason(text=text, page_url=page_url, indicators=profile.get("blocked_indicators", []))
    rows = []
    if not blocked_reason:
        rows = extract_visible_links(payload, limit=limit)
    visible = {
        "schema_version": "cloversec.ctf.visible_results.v1",
        "query": query,
        "engine": engine,
        "page_url": page_url,
        "generated_at": search.utc_now(),
        "results": rows,
        "blocked_by_captcha": bool(blocked_reason),
        "blocked_reason": blocked_reason,
        "privacy_boundary": [
            "只读取页面可见标题、URL、摘要、排名和搜索词。",
            "不读取或保存 Cookie、token、localStorage、sessionStorage、密码或验证码。",
            "用户确认页面后再导入；遇到验证码、登录墙或风控页时标记 blocked。",
        ],
    }
    if output_path:
        search.write_json(output_path, visible)
        visible["output_path"] = Path(output_path).as_posix()
    return visible


def dom_to_visible_bundle(
    payload: dict[str, Any],
    *,
    query: str,
    engine: str,
    page_url: str = "",
    limit: int = 50,
    output_path: str | Path | None = None,
    compact: bool = True,
) -> dict[str, Any]:
    visible = dom_to_visible_results(
        payload,
        query=query,
        engine=engine,
        page_url=page_url,
        limit=limit,
        output_path=output_path,
    )
    normalized = normalize_visible_results(visible, query=query, engine=engine)
    if compact:
        return {
            "query": query,
            "engine": engine,
            "page_url": page_url,
            "visible_results_path": visible.get("output_path", ""),
            "blocked_by_captcha": visible["blocked_by_captcha"],
            "blocked_reason": visible["blocked_reason"],
            "visible_count": len(visible["results"]),
            "summary": normalized.get("summary", {}),
            "top_results": [
                {
                    "rank": item.get("metadata", {}).get("rank", index),
                    "title": item.get("title", ""),
                    "source_url": item.get("source_url", ""),
                    "provider": item.get("provider", ""),
                    "layer": item.get("layer", ""),
                    "score": item.get("score", 0),
                    "quality_issues": item.get("quality_issues", []),
                }
                for index, item in enumerate(normalized.get("results", [])[:8], start=1)
            ],
            "errors": normalized.get("errors", []),
            "response_note": "短 JSON 默认返回。完整可见结果见 visible_results_path；需要完整评分结果时用 compact=false。",
        }
    return {"visible_results": visible, "normalized": normalized}


def collect_visible_text(payload: dict[str, Any]) -> str:
    chunks = [
        str(payload.get("visible_text") or ""),
        str(payload.get("text") or ""),
        str(payload.get("html") or ""),
        str(payload.get("page_url") or ""),
    ]
    for key in ["links", "anchors", "visible_links", "elements", "results"]:
        value = payload.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    chunks.extend(str(item.get(field) or "") for field in ["title", "text", "name", "url", "href", "snippet"])
    return "\n".join(part for part in chunks if part)


def detect_blocked_reason(*, text: str, page_url: str, indicators: list[str]) -> str:
    haystack = f"{page_url}\n{text}".lower()
    for indicator in indicators:
        if str(indicator).lower() in haystack:
            return f"blocked indicator found: {indicator}"
    if "captcha" in haystack or "验证码" in haystack or "安全验证" in haystack:
        return "captcha or risk-control text visible"
    return ""


def extract_visible_links(payload: dict[str, Any], *, limit: int = 50) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in ["results", "links", "anchors", "visible_links", "elements"]:
        value = payload.get(key)
        if isinstance(value, list):
            rows.extend(normalize_link_rows(value, start_rank=len(rows) + 1))
    html = str(payload.get("html") or "")
    if html:
        rows.extend(parse_html_links(html, start_rank=len(rows) + 1))
    visible_text = str(payload.get("visible_text") or payload.get("text") or "")
    if visible_text:
        rows.extend(parse_text_links(visible_text, start_rank=len(rows) + 1))
    deduped = []
    seen = set()
    for item in rows:
        url = clean_visible_url(str(item.get("url") or ""))
        title = str(item.get("title") or "").strip()
        if not url or not title:
            continue
        key = (url.rstrip("/").lower(), title.lower())
        if key in seen:
            continue
        seen.add(key)
        current = dict(item)
        current["url"] = url
        current["rank"] = len(deduped) + 1
        deduped.append(current)
        if len(deduped) >= limit:
            break
    return deduped


def normalize_link_rows(rows: list[Any], *, start_rank: int) -> list[dict[str, Any]]:
    output = []
    rank = start_rank
    for item in rows:
        if not isinstance(item, dict):
            continue
        url = item.get("url") or item.get("href") or item.get("link") or item.get("source_url")
        title = item.get("title") or item.get("text") or item.get("name") or item.get("label") or item.get("aria_label")
        snippet = item.get("snippet") or item.get("summary") or item.get("description") or item.get("body") or ""
        if not url or not title:
            continue
        output.append({"rank": item.get("rank", rank), "title": str(title).strip(), "url": str(url).strip(), "snippet": str(snippet).strip()})
        rank += 1
    return output


def parse_html_links(html: str, *, start_rank: int) -> list[dict[str, Any]]:
    output = []
    rank = start_rank
    for match in re.finditer(r'<a[^>]+href=["\'](?P<href>[^"\']+)["\'][^>]*>(?P<title>.*?)</a>', html, flags=re.I | re.S):
        href = unescape(match.group("href"))
        title = search.clean_html(match.group("title"))
        if not href or not title:
            continue
        output.append({"rank": rank, "title": title, "url": href, "snippet": ""})
        rank += 1
    return output


def parse_text_links(text: str, *, start_rank: int) -> list[dict[str, Any]]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    output = []
    rank = start_rank
    for index, line in enumerate(lines):
        match = re.search(r"https?://\\S+", line)
        if not match:
            continue
        url = match.group(0).rstrip(").,，。")
        title_candidates = [line[: match.start()].strip(" -—|") or "", lines[index - 1] if index > 0 else ""]
        title = next((candidate for candidate in title_candidates if candidate), url)
        snippet = lines[index + 1] if index + 1 < len(lines) and "http" not in lines[index + 1].lower() else ""
        output.append({"rank": rank, "title": title, "url": url, "snippet": snippet})
        rank += 1
    return output


def clean_visible_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme in {"http", "https"}:
        return url
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF browser-assisted search helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("plan", help="create a browser-assisted search plan")
    plan_parser.add_argument("--query", required=True)
    plan_parser.add_argument("--engine", choices=sorted(BROWSER_SEARCH_ENGINES), default="google")
    plan_parser.add_argument("--open-browser", action="store_true")
    plan_parser.add_argument("--output", required=True)

    import_parser = subparsers.add_parser("import-visible", help="normalize visible browser search results")
    import_parser.add_argument("--input", required=True)
    import_parser.add_argument("--query", required=True)
    import_parser.add_argument("--engine", choices=sorted(BROWSER_SEARCH_ENGINES), required=True)
    import_parser.add_argument("--output", required=True)

    dom_parser = subparsers.add_parser("dom-to-visible", help="convert Chrome/Codex visible DOM payload to visible_results.json")
    dom_parser.add_argument("--input", required=True)
    dom_parser.add_argument("--query", required=True)
    dom_parser.add_argument("--engine", choices=sorted(BROWSER_SEARCH_ENGINES), required=True)
    dom_parser.add_argument("--page-url", default="")
    dom_parser.add_argument("--limit", type=int, default=50)
    dom_parser.add_argument("--output", required=True)
    dom_parser.add_argument("--normalized-output")

    args = parser.parse_args(argv)
    if args.command == "plan":
        search.write_json(args.output, create_browser_search_plan(args.query, engine=args.engine, open_browser=args.open_browser))
        print(f"wrote {args.output}")
        return 0
    if args.command == "import-visible":
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
        search.write_json(args.output, normalize_visible_results(payload, query=args.query, engine=args.engine))
        print(f"wrote {args.output}")
        return 0
    if args.command == "dom-to-visible":
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
        visible = dom_to_visible_results(
            payload,
            query=args.query,
            engine=args.engine,
            page_url=args.page_url,
            limit=args.limit,
            output_path=args.output,
        )
        if args.normalized_output:
            search.write_json(args.normalized_output, normalize_visible_results(visible, query=args.query, engine=args.engine))
        print(f"wrote {args.output}")
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
