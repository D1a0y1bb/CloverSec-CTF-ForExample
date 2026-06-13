#!/usr/bin/env python3
"""Browser-assisted search planning and visible-result normalization."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
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
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
