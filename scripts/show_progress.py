#!/usr/bin/env python3
"""Render a compact progress table from workflow_state.json."""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Show CloverSec CTF workflow progress")
    parser.add_argument("workflow_state")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--watch", action="store_true", help="refresh progress until interrupted")
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--iterations", type=int, default=0, help="testing aid; 0 means run until interrupted")
    args = parser.parse_args()
    iterations = 0
    while True:
        state = json.loads(Path(args.workflow_state).read_text(encoding="utf-8"))
        payload = progress_payload(state)
        output = json.dumps(payload, ensure_ascii=False, indent=2) if args.json else render_progress(payload)
        if args.watch and not args.json:
            os.system("clear")
        print(output)
        if not args.watch:
            break
        iterations += 1
        if args.iterations and iterations >= args.iterations:
            break
        time.sleep(max(args.interval, 0.2))
    return 0


def progress_payload(state: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for case in state.get("cases", []) if isinstance(state.get("cases"), list) else []:
        stages = case.get("stages") if isinstance(case.get("stages"), dict) else {}
        row = {"case_id": str(case.get("case_id") or "")}
        missing = []
        for stage in STAGES:
            status = str(stages.get(stage, {}).get("status") or "pending")
            row[stage] = status
            if status in {"blocked", "incomplete", "pending_user"}:
                missing.append(stage)
        row["needs_attention"] = ",".join(missing)
        rows.append(row)
    summary = {stage: {} for stage in STAGES}
    for row in rows:
        for stage in STAGES:
            status = row.get(stage, "pending")
            summary[stage][status] = summary[stage].get(status, 0) + 1
    return {
        "schema_version": "cloversec.ctf.progress.v1",
        "run_id": state.get("run_id", ""),
        "status": state.get("status", ""),
        "updated_at": state.get("updated_at", ""),
        "totals": {
            "cases": len(rows),
            "needs_attention": sum(1 for row in rows if row.get("needs_attention")),
        },
        "summary": summary,
        "rows": rows,
    }


def render_progress(payload: dict[str, Any]) -> str:
    lines = [
        f"Run: {payload.get('run_id', '')}",
        f"Status: {payload.get('status', '')}",
        f"Updated: {payload.get('updated_at', '')}",
        f"Cases: {payload.get('totals', {}).get('cases', 0)}",
        f"Needs attention: {payload.get('totals', {}).get('needs_attention', 0)}",
        "",
    ]
    if not payload["rows"]:
        lines.append("没有 case 状态。")
        return "\n".join(lines)
    header = ["case_id", *STAGES, "needs_attention"]
    widths = {key: max(len(key), *(len(str(row.get(key, ""))) for row in payload["rows"])) for key in header}
    lines.append(" | ".join(key.ljust(widths[key]) for key in header))
    lines.append("-+-".join("-" * widths[key] for key in header))
    for row in payload["rows"]:
        lines.append(" | ".join(str(row.get(key, "")).ljust(widths[key]) for key in header))
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
