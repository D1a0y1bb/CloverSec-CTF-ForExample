#!/usr/bin/env python3
"""Migrate old CloverSec CTF workflow_state.json files to the current schema."""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "cloversec.ctf.workflow.state.v1"
WORKFLOW_VERSION = "0.6.1"
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
    parser = argparse.ArgumentParser(description="Migrate CloverSec CTF workflow_state.json")
    parser.add_argument("workflow_state")
    parser.add_argument("--output")
    parser.add_argument("--backup", action="store_true")
    args = parser.parse_args()
    path = Path(args.workflow_state)
    state = json.loads(path.read_text(encoding="utf-8"))
    migrated = migrate_state(state, path.parent)
    output = Path(args.output) if args.output else path
    if args.backup and output == path:
        shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
    output.write_text(json.dumps(migrated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output}")
    return 0


def migrate_state(state: dict[str, Any], workdir: Path) -> dict[str, Any]:
    schema = str(state.get("schema_version") or "")
    if schema == SCHEMA_VERSION:
        return ensure_current_shape(state, workdir)
    if schema and not schema.startswith("cloversec.ctf.workflow"):
        raise SystemExit(f"unsupported workflow_state schema_version: {schema}")
    return ensure_current_shape(state, workdir)


def ensure_current_shape(state: dict[str, Any], workdir: Path) -> dict[str, Any]:
    output = dict(state)
    output["schema_version"] = SCHEMA_VERSION
    output.setdefault("workflow_version", WORKFLOW_VERSION)
    output.setdefault("run_id", workdir.name)
    output.setdefault("status", "initialized")
    output.setdefault("created_at", utc_now())
    output["updated_at"] = utc_now()
    output.setdefault("workdir", workdir.as_posix())
    output.setdefault("request", {"event": "", "years": [], "categories": [], "limit": 0})
    stages = output.get("stages") if isinstance(output.get("stages"), dict) else {}
    output["stages"] = {stage: normalize_stage(stages.get(stage)) for stage in STAGES}
    cases = output.get("cases") if isinstance(output.get("cases"), list) else []
    output["cases"] = [normalize_case(case, index) for index, case in enumerate(cases, start=1) if isinstance(case, dict)]
    output.setdefault("resume", {"last_stage": "", "last_case_id": "", "can_resume": True})
    return output


def normalize_stage(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        value = {}
    return {
        "status": str(value.get("status") or "pending"),
        "started_at": str(value.get("started_at") or ""),
        "finished_at": str(value.get("finished_at") or ""),
        "summary": value.get("summary") if isinstance(value.get("summary"), dict) else {},
        "errors": value.get("errors") if isinstance(value.get("errors"), list) else [],
    }


def normalize_case(case: dict[str, Any], index: int) -> dict[str, Any]:
    stages = case.get("stages") if isinstance(case.get("stages"), dict) else {}
    return {
        "case_id": str(case.get("case_id") or f"case-{index:06d}"),
        "stages": {stage: normalize_case_stage(stages.get(stage)) for stage in STAGES if stage in stages},
    }


def normalize_case_stage(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        value = {}
    return {
        "status": str(value.get("status") or "pending"),
        "started_at": str(value.get("started_at") or value.get("planned_at") or ""),
        "finished_at": str(value.get("finished_at") or ""),
        "evidence_path": str(value.get("evidence_path") or ""),
        "errors": value.get("errors") if isinstance(value.get("errors"), list) else [],
        "forced": bool(value.get("forced", False)),
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
