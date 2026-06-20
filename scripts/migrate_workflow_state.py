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
WORKFLOW_VERSION = "1.0.9"
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
    parser.add_argument("--cases")
    parser.add_argument("--cases-output")
    parser.add_argument("--backup", action="store_true")
    args = parser.parse_args()
    path = Path(args.workflow_state)
    state = json.loads(path.read_text(encoding="utf-8"))
    migrated = migrate_state(state, path.parent)
    output = Path(args.output) if args.output else path
    if args.backup and output == path:
        shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
    output.write_text(json.dumps(migrated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.cases:
        cases_path = Path(args.cases)
        cases_output = Path(args.cases_output) if args.cases_output else cases_path
        if args.backup and cases_output == cases_path:
            shutil.copy2(cases_path, cases_path.with_suffix(cases_path.suffix + ".bak"))
        migrated_cases = migrate_cases(cases_path)
        cases_output.write_text("".join(json.dumps(case, ensure_ascii=False) + "\n" for case in migrated_cases), encoding="utf-8")
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


def migrate_cases(path: Path) -> list[dict[str, Any]]:
    migrated = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        raw = json.loads(line)
        if not isinstance(raw, dict):
            raise SystemExit(f"{path}:{index}: case must be a JSON object")
        migrated.append(normalize_ctf_case(raw, index))
    return migrated


def normalize_ctf_case(case: dict[str, Any], index: int) -> dict[str, Any]:
    output = dict(case)
    output.setdefault("schema_version", "cloversec.ctf.case.v1")
    output.setdefault("case_id", f"case-{index:06d}")
    for key in ["metadata", "research", "asset_collection", "flag", "environment", "docker_artifacts", "writeup", "hub_fields", "review", "archive"]:
        if not isinstance(output.get(key), dict):
            output[key] = {}
    for key in ["source_files", "attachments", "evidence"]:
        if not isinstance(output.get(key), list):
            output[key] = []
    metadata = output["metadata"]
    if "title" in output and not metadata.get("名称"):
        metadata["名称"] = str(output.get("title") or "")
    if "category" in output and not metadata.get("分类"):
        metadata["分类"] = str(output.get("category") or "")
    if "event" in output and not metadata.get("赛事来源"):
        metadata["赛事来源"] = str(output.get("event") or "")
    if "source_url" in output and not output["evidence"]:
        output["evidence"] = [{"source_url": str(output.get("source_url") or ""), "title": metadata.get("名称", "")}]
    return output


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
