#!/usr/bin/env python3
"""Evaluate CTF search recall by verified resource URL/repo hits."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
DEFAULT_BENCHMARK = ROOT / "plugins" / "cloversec-ctf-forexample" / "references" / "search-recall-benchmark.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Create CloverSec CTF search recall benchmark report")
    parser.add_argument("--benchmark", default=DEFAULT_BENCHMARK.as_posix())
    parser.add_argument("--input-dir", default="docs/validation/search-recall")
    parser.add_argument("--output", default="docs/validation/search-recall-benchmark-v0.8.0.md")
    parser.add_argument("--json-output", default="")
    parser.add_argument("--run-search", action="store_true", help="run search-plus for each benchmark case before evaluation")
    parser.add_argument("--source", action="append", default=[], help="override sources for every case")
    parser.add_argument("--limit", type=int, default=0, help="override search limit for every case")
    parser.add_argument("--cache-dir", default="", help="optional shared search cache directory")
    args = parser.parse_args()

    benchmark_path = Path(args.benchmark)
    input_dir = Path(args.input_dir)
    benchmark = json.loads(benchmark_path.read_text(encoding="utf-8"))
    cases = [item for item in benchmark.get("cases", []) if isinstance(item, dict)]
    if not cases:
        raise SystemExit(f"benchmark has no cases: {benchmark_path}")

    if args.run_search:
        run_search_cases(cases, input_dir=input_dir, source_override=args.source, limit_override=args.limit, cache_dir=args.cache_dir)

    report = build_report(benchmark, benchmark_path=benchmark_path, input_dir=input_dir, run_search=args.run_search)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report["markdown"], encoding="utf-8")
    if args.json_output:
        json_output = Path(args.json_output)
        json_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(json.dumps(report["payload"], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output}")
    return 0


def run_search_cases(
    cases: list[dict[str, Any]],
    *,
    input_dir: Path,
    source_override: list[str],
    limit_override: int,
    cache_dir: str,
) -> None:
    sys.path.insert(0, str(PLUGIN_SCRIPTS))
    import cloversec_ctf_search_plus as search_plus  # noqa: PLC0415

    input_dir.mkdir(parents=True, exist_ok=True)
    default_cache = input_dir / "cache"
    for case in cases:
        case_id = str(case.get("id") or "").strip()
        if not case_id:
            continue
        full_output = input_dir / f"{safe_filename(case_id)}.full.json"
        compact_output = input_dir / f"{safe_filename(case_id)}.compact.json"
        query = str(case.get("query") or "").strip()
        years = [int(item) for item in case.get("years", []) if str(item).isdigit()]
        sources = source_override or [str(item) for item in case.get("sources", []) if str(item).strip()] or None
        limit = limit_override or int(case.get("limit") or 20)
        payload = search_plus.search_plus(
            query,
            years=years,
            sources=sources,
            limit=limit,
            output_path=full_output,
            compact=True,
            compact_results=max(8, int(case.get("compact_results") or 12)),
            cache_dir=Path(cache_dir) if cache_dir else default_cache,
        )
        compact_output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def build_report(benchmark: dict[str, Any], *, benchmark_path: Path, input_dir: Path, run_search: bool) -> dict[str, Any]:
    rows = []
    details = []
    evaluations = []
    totals = {"cases": 0, "required": 0, "matched": 0, "missing": 0}
    for case in [item for item in benchmark.get("cases", []) if isinstance(item, dict)]:
        totals["cases"] += 1
        result_path = input_dir / str(case.get("result_file") or f"{safe_filename(str(case.get('id') or 'case'))}.compact.json")
        payload = read_json(result_path)
        evaluation = evaluate_case(case, payload, result_path=result_path)
        evaluations.append(evaluation)
        totals["required"] += evaluation["required_total"]
        totals["matched"] += evaluation["matched_required"]
        totals["missing"] += evaluation["missing_required"]
        rows.append(
            [
                evaluation["case_id"],
                evaluation["status"],
                f"{evaluation['matched_required']}/{evaluation['required_total']}",
                str(evaluation["top_result_count"]),
                short_counts(evaluation["provider_counts"]),
                short_counts(evaluation["layer_counts"]),
                "；".join(evaluation["missing_labels"]) or "无",
            ]
        )
        details.append(render_case_detail(evaluation))

    resource_recall = totals["matched"] / totals["required"] if totals["required"] else 0.0
    payload = {
        "schema_version": "cloversec.ctf.search_recall_benchmark.v2",
        "generated_at": utc_now(),
        "benchmark": benchmark_path.as_posix(),
        "input_dir": input_dir.as_posix(),
        "run_search": run_search,
        "summary": {
            "cases": totals["cases"],
            "required_resources": totals["required"],
            "matched_required_resources": totals["matched"],
            "missing_required_resources": totals["missing"],
            "resource_recall": round(resource_recall, 4),
        },
        "cases": evaluations,
    }
    markdown = render_markdown(payload, rows, details)
    return {"payload": payload, "markdown": markdown}


def evaluate_case(case: dict[str, Any], payload: dict[str, Any], *, result_path: Path) -> dict[str, Any]:
    expected = [item for item in case.get("expected_resources", []) if isinstance(item, dict)]
    required = [item for item in expected if item.get("required", True)]
    results = extract_results(payload)
    result_keys = [result_identity(item) for item in results]
    expected_results = []
    matched_required = 0
    missing_labels = []
    for item in expected:
        match = match_expected_resource(item, results, result_keys)
        required_flag = bool(item.get("required", True))
        if match and required_flag:
            matched_required += 1
        if not match and required_flag:
            missing_labels.append(str(item.get("label") or item.get("id") or item.get("value") or item.get("url") or "expected"))
        expected_results.append(
            {
                "id": item.get("id", ""),
                "label": item.get("label") or item.get("id") or item.get("value") or item.get("url") or "",
                "type": item.get("type", ""),
                "value": item.get("value", ""),
                "url": item.get("url", ""),
                "required": required_flag,
                "matched": bool(match),
                "matched_result": match or {},
            }
        )
    status = "pass" if required and matched_required == len(required) else "needs_review"
    if not payload:
        status = "missing_result"
    return {
        "case_id": str(case.get("id") or ""),
        "query": str(case.get("query") or ""),
        "years": case.get("years", []),
        "sources": case.get("sources", []),
        "result_file": result_path.as_posix(),
        "status": status,
        "required_total": len(required),
        "matched_required": matched_required,
        "missing_required": max(len(required) - matched_required, 0),
        "missing_labels": missing_labels,
        "top_result_count": len(results),
        "provider_counts": payload.get("summary", {}).get("provider_counts", {}) if isinstance(payload.get("summary"), dict) else {},
        "layer_counts": payload.get("summary", {}).get("layer_counts", {}) if isinstance(payload.get("summary"), dict) else {},
        "expected_results": expected_results,
        "top_results": [
            {
                "title": item.get("title", ""),
                "url": item.get("url") or item.get("source_url") or "",
                "provider": item.get("provider", ""),
                "layer": item.get("layer", ""),
                "score": item.get("score", 0),
            }
            for item in results[:8]
        ],
    }


def extract_results(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if not payload:
        return []
    for key in ["top_results", "results"]:
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def match_expected_resource(expected: dict[str, Any], results: list[dict[str, Any]], result_keys: list[dict[str, str]]) -> dict[str, Any] | None:
    expected_type = str(expected.get("type") or "exact_url")
    expected_value = str(expected.get("value") or expected.get("url") or "").strip()
    expected_url = str(expected.get("url") or expected_value).strip()
    for result, keys in zip(results, result_keys, strict=False):
        if expected_type == "github_repo":
            expected_repo = normalize_github_repo(expected_value or expected_url)
            if expected_repo and expected_repo == keys.get("github_repo"):
                return matched_result(result, keys)
            metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
            if expected_repo and normalize_github_repo(str(metadata.get("repository") or "")) == expected_repo:
                return matched_result(result, keys)
        elif expected_type == "url_prefix":
            if keys.get("canonical_url", "").startswith(canonical_url(expected_url)):
                return matched_result(result, keys)
        else:
            if keys.get("canonical_url") == canonical_url(expected_url):
                return matched_result(result, keys)
    return None


def matched_result(result: dict[str, Any], keys: dict[str, str]) -> dict[str, Any]:
    return {
        "title": result.get("title", ""),
        "url": result.get("url") or result.get("source_url") or "",
        "provider": result.get("provider", ""),
        "layer": result.get("layer", ""),
        "score": result.get("score", 0),
        "github_repo": keys.get("github_repo", ""),
        "canonical_url": keys.get("canonical_url", ""),
    }


def result_identity(result: dict[str, Any]) -> dict[str, str]:
    url = str(result.get("url") or result.get("source_url") or result.get("html_url") or "").strip()
    metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
    repo = normalize_github_repo(str(metadata.get("repository") or "")) or normalize_github_repo(url)
    return {"canonical_url": canonical_url(url), "github_repo": repo}


def normalize_github_repo(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "github.com" in text:
        parsed = urlparse(text)
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) >= 2:
            return f"{parts[0].lower()}/{parts[1].lower()}"
        return ""
    match = re.search(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", text)
    return match.group(1).lower() if match else ""


def canonical_url(value: str) -> str:
    parsed = urlparse(str(value or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return str(value or "").strip().rstrip("/")
    path = re.sub(r"/+", "/", parsed.path).rstrip("/")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def render_markdown(payload: dict[str, Any], rows: list[list[Any]], details: list[str]) -> str:
    summary = payload["summary"]
    lines = [
        "# CloverSec CTF 搜索召回真实基准",
        "",
        f"- generated_at: `{payload['generated_at']}`",
        f"- benchmark: `{payload['benchmark']}`",
        f"- input_dir: `{payload['input_dir']}`",
        f"- run_search: `{str(payload['run_search']).lower()}`",
        f"- evaluated_cases: `{summary['cases']}`",
        f"- required_resources: `{summary['required_resources']}`",
        f"- matched_required_resources: `{summary['matched_required_resources']}`",
        f"- missing_required_resources: `{summary['missing_required_resources']}`",
        f"- resource_recall: `{summary['resource_recall']:.2f}`",
        "",
        "| 样例 | 状态 | 真实资源命中 | Top 结果数 | 来源 | 分层 | 未命中资源 |",
        "|---|---:|---:|---:|---|---|---|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(escape_cell(value) for value in row) + " |")
    lines.extend(["", "## 逐项证据", ""])
    lines.extend(details or ["- 无样例。"])
    return "\n".join(lines) + "\n"


def render_case_detail(evaluation: dict[str, Any]) -> str:
    lines = [f"### {evaluation['case_id']}", ""]
    lines.append(f"- query: `{evaluation['query']}`")
    lines.append(f"- status: `{evaluation['status']}`")
    lines.append(f"- result_file: `{evaluation['result_file']}`")
    lines.append(f"- required_hit: `{evaluation['matched_required']}/{evaluation['required_total']}`")
    lines.append("- expected_resources:")
    for expected in evaluation["expected_results"]:
        mark = "命中" if expected["matched"] else "未命中"
        lines.append(f"  - {mark}: {expected['label']} ({expected['type']} `{expected['value'] or expected['url']}`)")
        if expected["matched"]:
            match = expected["matched_result"]
            lines.append(f"    - result: {match.get('title', '')} -> {match.get('url', '')}")
    if evaluation["top_results"]:
        lines.append("- top_results:")
        for item in evaluation["top_results"][:5]:
            lines.append(f"  - {item.get('provider', '')}/{item.get('layer', '')}: {item.get('title', '')} -> {item.get('url', '')}")
    lines.append("")
    return "\n".join(lines)


def short_counts(value: Any) -> str:
    if not isinstance(value, dict) or not value:
        return "{}"
    return ", ".join(f"{key}:{value[key]}" for key in sorted(value))


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip(".-") or "case"


def escape_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
