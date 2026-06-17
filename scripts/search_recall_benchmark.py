#!/usr/bin/env python3
"""Render a local search recall benchmark report from search-plus compact JSON files."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_CASES = [
    {
        "id": "irisctf-2025-web",
        "file": "search-irisctf-2025-web.compact.json",
        "expected_terms": ["irisctf", "2025"],
        "minimum_candidates": 3,
    },
    {
        "id": "lactf-2024-pwn",
        "file": "search-lactf-2024-pwn.compact.json",
        "expected_terms": ["la ctf", "2024"],
        "minimum_candidates": 3,
    },
    {
        "id": "xiangyunbei-2024-pwn",
        "file": "search-xiangyunbei-2024-pwn.compact.json",
        "expected_terms": ["祥云杯", "2024"],
        "minimum_candidates": 2,
    },
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Create CloverSec CTF search recall benchmark report")
    parser.add_argument("--input-dir", default="docs/validation")
    parser.add_argument("--output", default="docs/validation/search-recall-benchmark-v0.6.1.md")
    args = parser.parse_args()
    report = build_report(Path(args.input_dir), DEFAULT_CASES)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"wrote {output}")
    return 0


def build_report(input_dir: Path, cases: list[dict[str, Any]]) -> str:
    rows = []
    details = []
    passed = 0
    evaluated = 0
    for case in cases:
        path = input_dir / str(case["file"])
        evaluated += 1
        if not path.exists():
            rows.append([case["id"], "missing_file", "0", "0", "缺少结果文件", "0.00"])
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        result = evaluate_payload(payload, case)
        if result["status"] == "pass":
            passed += 1
        rows.append(
            [
                case["id"],
                result["status"],
                str(result["candidate_count"]),
                str(result["noise_count"]),
                "; ".join(result["issues"]),
                f"{result['precision']:.2f}",
            ]
        )
        details.append(render_case_detail(case, payload, result))
    recall_rate = passed / evaluated if evaluated else 0
    lines = [
        "# CloverSec CTF 搜索召回基准",
        "",
        f"- generated_at: `{datetime.now(timezone.utc).replace(microsecond=0).isoformat()}`",
        f"- evaluated_cases: `{evaluated}`",
        f"- passed_cases: `{passed}`",
        f"- recall_rate: `{recall_rate:.2f}`",
        "",
        "| 样例 | 状态 | 候选数 | 噪声数 | 问题 | 粗略准确率 |",
        "|---|---:|---:|---:|---|---:|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(escape_cell(value) for value in row) + " |")
    lines.extend(["", "## 明显误报与弱召回", ""])
    lines.extend(details or ["- 无样例。"])
    return "\n".join(lines) + "\n"


def evaluate_payload(payload: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    layer_counts = payload.get("summary", {}).get("layer_counts", {})
    candidate_count = sum(int(layer_counts.get(key, 0) or 0) for key in ["confirmed_challenge", "writeup_candidate", "attachment_candidate"])
    noise_count = int(layer_counts.get("noise", 0) or 0)
    minimum = int(case.get("minimum_candidates") or 1)
    issues: list[str] = []
    if candidate_count < minimum:
        issues.append(f"候选不足：{candidate_count} < {minimum}")
    for item in payload.get("decision_required", []):
        if isinstance(item, dict) and item.get("type"):
            issues.append(str(item.get("type")))
    false_positive_titles = obvious_false_positives(payload, [str(item).lower() for item in case.get("expected_terms", [])])
    if false_positive_titles:
        issues.append("明显误报：" + "；".join(false_positive_titles[:3]))
    precision = candidate_count / max(candidate_count + noise_count, 1)
    return {
        "status": "pass" if not issues else "needs_review",
        "candidate_count": candidate_count,
        "noise_count": noise_count,
        "issues": issues or ["无"],
        "precision": precision,
        "false_positive_titles": false_positive_titles,
    }


def obvious_false_positives(payload: dict[str, Any], expected_terms: list[str]) -> list[str]:
    titles = []
    for item in payload.get("top_results", []):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "")
        layer = str(item.get("layer") or "")
        haystack = f"{title} {item.get('url', '')}".lower()
        if layer == "noise" and expected_terms and not all(term in haystack for term in expected_terms):
            titles.append(title or str(item.get("url") or "untitled"))
    return titles


def render_case_detail(case: dict[str, Any], payload: dict[str, Any], result: dict[str, Any]) -> str:
    lines = [f"### {case['id']}", ""]
    lines.append(f"- query: `{payload.get('query', '')}`")
    lines.append(f"- status: `{result['status']}`")
    lines.append(f"- provider_counts: `{json.dumps(payload.get('summary', {}).get('provider_counts', {}), ensure_ascii=False)}`")
    lines.append(f"- layer_counts: `{json.dumps(payload.get('summary', {}).get('layer_counts', {}), ensure_ascii=False)}`")
    lines.append(f"- issues: {'；'.join(result['issues'])}")
    if result["false_positive_titles"]:
        lines.append("- false_positive_examples:")
        lines.extend(f"  - {title}" for title in result["false_positive_titles"][:5])
    lines.append("")
    return "\n".join(lines)


def escape_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


if __name__ == "__main__":
    raise SystemExit(main())
