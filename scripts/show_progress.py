#!/usr/bin/env python3
"""Render workflow_state.json as a human-readable progress report."""

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

STAGE_LABELS = {
    "research": "搜索采集",
    "collect": "资源整理",
    "dedupe": "去重合并",
    "download_preview": "下载预览",
    "download_accept": "下载确认",
    "archive": "归档打包",
    "quality": "质量检查",
    "hub_prepare": "Hub 准备",
    "final_report": "最终交付",
}

STATUS_LABELS = {
    "completed": "已完成",
    "partial": "部分完成",
    "pending": "未开始",
    "pending_user": "等人工确认",
    "blocked": "已阻塞",
    "incomplete": "未完成",
    "failed": "失败",
    "running": "处理中",
}

ATTENTION_STATUSES = {"blocked", "incomplete", "pending_user", "failed"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Show CloverSec CTF workflow progress")
    parser.add_argument("workflow_state")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--table", action="store_true", help="render the old compact debug table")
    parser.add_argument("--watch", action="store_true", help="refresh progress until interrupted")
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--iterations", type=int, default=0, help="testing aid; 0 means run until interrupted")
    args = parser.parse_args()
    iterations = 0
    while True:
        state = json.loads(Path(args.workflow_state).read_text(encoding="utf-8"))
        payload = progress_payload(state)
        if args.json:
            output = json.dumps(payload, ensure_ascii=False, indent=2)
        elif args.table:
            output = render_table_progress(payload)
        else:
            output = render_human_progress(payload)
        if args.watch and not args.json:
            clear_screen()
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
            if status in ATTENTION_STATUSES:
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


def render_human_progress(payload: dict[str, Any]) -> str:
    totals = payload.get("totals", {})
    lines = [
        "# 当前批次进度",
        "",
        f"- 运行 ID：{payload.get('run_id') or '未记录'}",
        f"- 总状态：{status_label(payload.get('status') or 'pending')}",
        f"- 更新时间：{payload.get('updated_at') or '未记录'}",
        f"- 题目数量：{totals.get('cases', 0)}",
        f"- 需要处理：{totals.get('needs_attention', 0)}",
        "",
        "## 阶段概览",
        "",
    ]
    for stage in STAGES:
        counts = payload.get("summary", {}).get(stage, {})
        if not counts:
            lines.append(f"- {stage_label(stage)}：暂无记录")
            continue
        parts = [f"{status_label(status)} {count}" for status, count in sorted(counts.items())]
        lines.append(f"- {stage_label(stage)}：" + "，".join(parts))
    attention_rows = [row for row in payload.get("rows", []) if row.get("needs_attention")]
    lines.extend(["", "## 需要处理", ""])
    if not attention_rows:
        lines.append("- 暂无需要人工处理的题目。")
    else:
        for row in attention_rows:
            stages = []
            for stage in row.get("needs_attention", "").split(","):
                stage = stage.strip()
                if stage:
                    stages.append(f"{stage_label(stage)}={status_label(row.get(stage, ''))}")
            lines.append(f"- {row.get('case_id') or '未命名题目'}：" + "，".join(stages))
    if not payload.get("rows"):
        lines.extend(["", "还没有题目状态。"])
    return "\n".join(lines)


def render_table_progress(payload: dict[str, Any]) -> str:
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


def stage_label(stage: str) -> str:
    return STAGE_LABELS.get(str(stage), str(stage))


def status_label(status: str) -> str:
    return STATUS_LABELS.get(str(status), str(status) or "未记录")


def clear_screen() -> None:
    if os.getenv("TERM"):
        os.system("clear")


if __name__ == "__main__":
    raise SystemExit(main())
