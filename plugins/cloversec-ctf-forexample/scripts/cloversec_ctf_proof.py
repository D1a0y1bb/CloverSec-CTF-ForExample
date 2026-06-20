#!/usr/bin/env python3
"""Proof package builder for CloverSec CTF quality evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "cloversec.ctf.proof_pack.v1"
VERSION = "1.0.2"
MAX_COPY_BYTES = 2 * 1024 * 1024


def create_proof_package(
    *,
    output_dir: str | Path,
    case: dict[str, Any] | None = None,
    case_json: str | Path = "",
    resource_classification_path: str | Path = "",
    container_inference_path: str | Path = "",
    docker_evidence_path: str | Path = "",
    quality_review_path: str | Path = "",
    extra_files: list[str | Path] | None = None,
    notes: str = "",
) -> dict[str, Any]:
    case_payload = dict(case or {})
    if case_json and not case_payload:
        case_payload = read_json(case_json)

    proof_dir = Path(output_dir)
    evidence_dir = proof_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    skipped = []
    input_paths = {
        "case_json": str(case_json or ""),
        "resource_classification": str(resource_classification_path or ""),
        "container_inference": str(container_inference_path or ""),
        "docker_evidence": str(docker_evidence_path or ""),
        "quality_review": str(quality_review_path or ""),
    }
    for label, value in input_paths.items():
        if value:
            result = copy_evidence(Path(value), evidence_dir, label)
            copied.extend(result["copied"])
            skipped.extend(result["skipped"])
    for index, value in enumerate(extra_files or [], start=1):
        result = copy_evidence(Path(value), evidence_dir, f"extra_{index}")
        copied.extend(result["copied"])
        skipped.extend(result["skipped"])

    resource_classification = read_json(resource_classification_path) if resource_classification_path else {}
    container_inference = read_json(container_inference_path) if container_inference_path else {}
    docker_evidence = read_json(docker_evidence_path) if docker_evidence_path else {}
    quality_review = read_json(quality_review_path) if quality_review_path else {}

    summary = build_summary(
        case_payload=case_payload,
        resource_classification=resource_classification,
        container_inference=container_inference,
        docker_evidence=docker_evidence,
        quality_review=quality_review,
        skipped=skipped,
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "version": VERSION,
        "created_at": utc_now(),
        "case_id": str(case_payload.get("case_id") or summary.get("case_id") or ""),
        "output_dir": proof_dir.as_posix(),
        "notes": notes,
        "inputs": input_paths,
        "copied_evidence": copied,
        "skipped_evidence": skipped,
        "summary": summary,
        "hashes": [],
        "review_rules": [
            "Proof package records evidence for review; it does not click Hub final submit.",
            "Unknown solver scripts are not executed by this package builder.",
            "Full Flag remains in structured case/xlsx fields; proof summary only records whether a value exists.",
        ],
    }
    manifest_path = proof_dir / "proof_manifest.json"
    report_path = proof_dir / "proof_report.md"
    hashes_path = proof_dir / "hashes.json"
    manifest["paths"] = {
        "manifest": manifest_path.as_posix(),
        "report": report_path.as_posix(),
        "hashes": hashes_path.as_posix(),
    }
    report_path.write_text(render_proof_report(manifest), encoding="utf-8")
    manifest["hashes"] = build_hashes(proof_dir)
    hashes_path.write_text(json.dumps(manifest["hashes"], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def copy_evidence(path: Path, evidence_dir: Path, label: str) -> dict[str, list[dict[str, Any]]]:
    if not path.exists() or not path.is_file():
        return {"copied": [], "skipped": [{"label": label, "path": path.as_posix(), "reason": "missing"}]}
    if path.stat().st_size > MAX_COPY_BYTES:
        return {
            "copied": [],
            "skipped": [{"label": label, "path": path.as_posix(), "reason": f"larger than {MAX_COPY_BYTES} bytes"}],
        }
    target = evidence_dir / f"{safe_name(label)}-{path.name}"
    shutil.copy2(path, target)
    return {
        "copied": [
            {
                "label": label,
                "source": path.as_posix(),
                "path": target.as_posix(),
                "size": target.stat().st_size,
                "sha256": sha256_file(target),
            }
        ],
        "skipped": [],
    }


def build_summary(
    *,
    case_payload: dict[str, Any],
    resource_classification: dict[str, Any],
    container_inference: dict[str, Any],
    docker_evidence: dict[str, Any],
    quality_review: dict[str, Any],
    skipped: list[dict[str, Any]],
) -> dict[str, Any]:
    metadata = case_payload.get("metadata") if isinstance(case_payload.get("metadata"), dict) else {}
    flag = case_payload.get("flag") if isinstance(case_payload.get("flag"), dict) else {}
    resource_summary = resource_classification.get("root_classification", {})
    container_summary = container_inference.get("summary", {})
    docker_summary = docker_evidence.get("summary", {})
    quality_summary = quality_review.get("summary", {})
    issues: list[str] = []
    issues.extend(str(item.get("message") or item) for item in quality_review.get("checks", []) if item.get("status") != "pass")
    issues.extend(f"skipped evidence: {item.get('label')} {item.get('reason')}" for item in skipped)
    if docker_summary.get("status") == "fail":
        issues.extend(str(item) for item in docker_summary.get("issues", []))
    ready = not any(text for text in issues if text)
    return {
        "case_id": str(case_payload.get("case_id") or quality_review.get("case_id") or ""),
        "title": str(metadata.get("名称") or ""),
        "category": str(metadata.get("分类") or ""),
        "resource_project_type": resource_summary.get("project_type", ""),
        "container_project_type": container_summary.get("project_type", ""),
        "docker_status": docker_summary.get("status", ""),
        "docker_validation_level": docker_summary.get("validation_level", ""),
        "docker_run_verified": docker_summary.get("run_verified", False),
        "quality_status": quality_summary.get("status", ""),
        "flag_present": bool(str(flag.get("value") or "").strip()),
        "ready_for_review": ready,
        "issues": dedupe([text for text in issues if text]),
    }


def build_hashes(root: Path) -> list[dict[str, Any]]:
    hashes = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if path.name in {"hashes.json", "proof_manifest.json"}:
            continue
        hashes.append({"path": path.relative_to(root).as_posix(), "size": path.stat().st_size, "sha256": sha256_file(path)})
    return hashes


def render_proof_report(manifest: dict[str, Any]) -> str:
    summary = manifest.get("summary", {})
    lines = [
        "# CloverSec CTF Proof Package",
        "",
        f"- 题目 ID：{summary.get('case_id', '')}",
        f"- 题名：{summary.get('title', '')}",
        f"- 分类：{summary.get('category', '')}",
        f"- 资源类型：{summary.get('resource_project_type', '')}",
        f"- 容器类型：{summary.get('container_project_type', '')}",
        f"- Docker 状态：{summary.get('docker_status', '')}",
        f"- Docker 验证等级：{summary.get('docker_validation_level', '')}",
        f"- Docker run_verified：{summary.get('docker_run_verified', False)}",
        f"- 质量状态：{summary.get('quality_status', '')}",
        f"- Flag 字段存在：{summary.get('flag_present', False)}",
        f"- 可进入人工复核：{summary.get('ready_for_review', False)}",
        "",
        "## Evidence Files",
        "",
    ]
    if manifest.get("copied_evidence"):
        for item in manifest["copied_evidence"]:
            lines.append(f"- {item.get('label', '')}: {item.get('path', '')} sha256={item.get('sha256', '')}")
    else:
        lines.append("- none")
    if manifest.get("skipped_evidence"):
        lines.extend(["", "## Skipped Evidence", ""])
        for item in manifest["skipped_evidence"]:
            lines.append(f"- {item.get('label', '')}: {item.get('path', '')} ({item.get('reason', '')})")
    if summary.get("issues"):
        lines.extend(["", "## Issues", ""])
        for item in summary["issues"]:
            lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def read_json(path: str | Path) -> dict[str, Any]:
    if not str(path or "").strip():
        return {}
    source = Path(path)
    if not source.is_file():
        return {}
    return json.loads(source.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_name(value: str) -> str:
    output = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in value).strip(".-")
    return output[:64] or "evidence"


def dedupe(items: list[str]) -> list[str]:
    output = []
    seen = set()
    for item in items:
        text = str(item or "").strip()
        if text and text not in seen:
            seen.add(text)
            output.append(text)
    return output


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def compact_proof_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "cloversec.ctf.proof_pack.compact.v1",
        "case_id": payload.get("case_id", ""),
        "summary": payload.get("summary", {}),
        "paths": payload.get("paths", {}),
        "copied_evidence_count": len(payload.get("copied_evidence", [])),
        "skipped_evidence_count": len(payload.get("skipped_evidence", [])),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create CloverSec CTF proof package")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--case-json", default="")
    parser.add_argument("--resource-classification", default="")
    parser.add_argument("--container-inference", default="")
    parser.add_argument("--docker-evidence", default="")
    parser.add_argument("--quality-review", default="")
    parser.add_argument("--extra-file", action="append", default=[])
    parser.add_argument("--notes", default="")
    parser.add_argument("--compact-output", default="")
    args = parser.parse_args(argv)
    payload = create_proof_package(
        output_dir=args.output_dir,
        case_json=args.case_json,
        resource_classification_path=args.resource_classification,
        container_inference_path=args.container_inference,
        docker_evidence_path=args.docker_evidence,
        quality_review_path=args.quality_review,
        extra_files=args.extra_file,
        notes=args.notes,
    )
    if args.compact_output:
        path = Path(args.compact_output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(compact_proof_payload(payload), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {payload['paths']['manifest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
