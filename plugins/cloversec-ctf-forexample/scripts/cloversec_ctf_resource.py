#!/usr/bin/env python3
"""Local resource classification for CloverSec CTF workflows."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import cloversec_ctf_search as search


SCHEMA_VERSION = "cloversec.ctf.resource_classification.v1"
VERSION = "0.7.2"

TEXT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".java",
    ".js",
    ".json",
    ".jsp",
    ".md",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".sage",
    ".sagemath",
    ".sh",
    ".sql",
    ".toml",
    ".ts",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsp",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".sage",
    ".sagemath",
    ".sh",
    ".sol",
    ".ts",
}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".tar.gz", ".tar.xz", ".tar.bz2", ".tgz", ".gz", ".xz", ".bz2", ".7z", ".rar"}
SCREENSHOT_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
WRITEUP_EXTENSIONS = {".md", ".txt", ".pdf"}
PCAP_EXTENSIONS = {".pcap", ".pcapng"}
BINARY_EXTENSIONS = {".bin", ".elf", ".exe", ".so", ".dll", ".dylib"}
DATABASE_EXTENSIONS = {".sql", ".db", ".sqlite", ".sqlite3", ".dump"}
VM_EXTENSIONS = {".qcow2", ".vmdk", ".ova", ".img", ".ext4", ".iso"}
PACKAGE_FILES = {
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "go.mod",
    "cargo.toml",
    "pom.xml",
    "composer.json",
    "gemfile",
    "makefile",
}
COMPOSE_FILES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
DOCKER_HELPERS = {"start.sh", "changeflag.sh", "check.sh", ".dockerignore"}
CTF_MANIFEST_FILES = {"challenge.yaml", "challenge.yml", "challenge.json", "ctfd.yaml", "ctfd.yml"}
FLAG_FILES = {"flag", "flag.txt", "flag.md"}
IGNORED_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}
SOLVER_HINTS = {"solve", "solver", "solution", "exp", "exploit", "writeup", "wp", "题解", "解题"}
SERVICE_HINTS = {
    "app",
    "server",
    "service",
    "main",
    "index",
    "src",
    "routes",
    "views",
    "templates",
    "static",
    "run",
    "start",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def classify_resource_root(
    root: str | Path,
    *,
    output_path: str | Path | None = None,
    max_files: int = 2000,
    max_text_bytes: int = 65536,
    archive_preview_entries: int = 200,
) -> dict[str, Any]:
    base = Path(root)
    if not base.exists():
        raise FileNotFoundError(base)
    if not base.is_dir():
        raise ValueError(f"resource root is not a directory: {base}")

    files = list(iter_files(base, max_files=max_files))
    resources = [
        classify_file(path, base, max_text_bytes=max_text_bytes, archive_preview_entries=archive_preview_entries)
        for path in files
    ]
    root_classification = classify_root(resources)
    summary = summarize(resources, root_classification)
    platform_delivery = root_classification.get("platform_delivery", {}) if isinstance(root_classification, dict) else {}
    payload = {
        "schema_version": SCHEMA_VERSION,
        "version": VERSION,
        "generated_at": utc_now(),
        "root": base.as_posix(),
        "platform_delivery": platform_delivery,
        "platform_contract_required": bool(platform_delivery.get("requires_cloversec_contract")),
        "must_use_dockerizer": bool(platform_delivery.get("must_use_dockerizer")),
        "existing_docker_is_reference_only": bool(platform_delivery.get("existing_docker_is_reference_only")),
        "final_delivery_skill": str(platform_delivery.get("final_delivery_skill") or ""),
        "root_classification": root_classification,
        "resources": resources,
        "summary": summary,
        "recommendations": build_recommendations(root_classification, resources),
        "warnings": build_warnings(resources, len(files), max_files),
    }
    if output_path:
        write_json(output_path, payload)
    return payload


def iter_files(root: Path, *, max_files: int) -> list[Path]:
    files: list[Path] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if any(part in IGNORED_DIRS for part in path.relative_to(root).parts):
            continue
        files.append(path)
        if len(files) >= max_files:
            break
    return files


def classify_file(path: Path, root: Path, *, max_text_bytes: int, archive_preview_entries: int) -> dict[str, Any]:
    relative = path.relative_to(root).as_posix()
    lower_name = path.name.lower()
    suffix = normalized_suffix(path)
    evidence: list[str] = []
    resource_type = "unknown"
    confidence = "low"
    next_skill = "cloversec-ctf-asset-collector"
    archive_preview: dict[str, Any] = {}

    file_size = path.stat().st_size
    head = read_head(path, max_bytes=min(max_text_bytes, 4096))
    text_sample = read_text_sample(path, max_bytes=max_text_bytes) if should_read_text(path, head) else ""

    if lower_name == "dockerfile":
        resource_type, confidence, next_skill = "dockerfile", "high", "cloversec-ctf-build-dockerizer"
        evidence.append("filename Dockerfile")
    elif lower_name in COMPOSE_FILES:
        resource_type, confidence, next_skill = "compose_file", "high", "cloversec-ctf-build-dockerizer"
        evidence.append("docker compose filename")
    elif lower_name in DOCKER_HELPERS:
        resource_type, confidence, next_skill = "docker_helper", "medium", "cloversec-ctf-build-dockerizer"
        evidence.append("known docker helper filename")
    elif lower_name in CTF_MANIFEST_FILES:
        resource_type, confidence, next_skill = "ctf_manifest", "high", "cloversec-ctf-asset-collector"
        evidence.append("known CTF challenge metadata manifest")
    elif lower_name in FLAG_FILES:
        resource_type, confidence, next_skill = "flag_file", "high", "cloversec-ctf-writeup-scaffold"
        evidence.append("known flag filename")
    elif is_docker_image_tar(path, archive_preview_entries):
        resource_type, confidence, next_skill = "docker_image_tar", "high", "cloversec-ctf-build-dockerizer"
        evidence.append("tar archive contains docker image manifest/layers")
        archive_preview = safe_archive_preview(path, archive_preview_entries)
    elif suffix in ARCHIVE_EXTENSIONS:
        archive_preview = safe_archive_preview(path, archive_preview_entries)
        archive_type, archive_evidence, archive_next = classify_archive_preview(archive_preview)
        resource_type = archive_type
        confidence = "medium" if archive_type == "attachment_archive" else "high"
        next_skill = archive_next
        evidence.extend(archive_evidence or [f"archive extension {suffix}"])
    elif lower_name in PACKAGE_FILES:
        resource_type, confidence, next_skill = "source_manifest", "high", "cloversec-ctf-build-dockerizer"
        evidence.append("known source/package manifest")
    elif suffix in SOURCE_EXTENSIONS and looks_solver_source(path, root, text_sample):
        resource_type, confidence, next_skill = "solver_file", "high", "cloversec-ctf-writeup-scaffold"
        evidence.append(f"solver/writeup source file {suffix}")
    elif suffix in SOURCE_EXTENSIONS:
        resource_type, confidence, next_skill = "source_file", "medium", "cloversec-ctf-build-dockerizer"
        evidence.append(f"source extension {suffix}")
    elif suffix in PCAP_EXTENSIONS or has_pcap_magic(head):
        resource_type, confidence, next_skill = "pcap", "high", "cloversec-ctf-attachment-packager"
        evidence.append("pcap extension or magic")
    elif suffix in DATABASE_EXTENSIONS or has_sqlite_magic(head):
        resource_type, confidence, next_skill = "database_dump", "high", "cloversec-ctf-attachment-packager"
        evidence.append("database extension or sqlite magic")
    elif suffix in VM_EXTENSIONS:
        resource_type, confidence, next_skill = "vm_image", "medium", "cloversec-ctf-attachment-packager"
        evidence.append(f"vm/image extension {suffix}")
    elif suffix in SCREENSHOT_EXTENSIONS:
        resource_type, confidence, next_skill = "screenshot", "high", "cloversec-ctf-writeup-scaffold"
        evidence.append(f"screenshot extension {suffix}")
    elif looks_writeup(path, text_sample):
        resource_type, confidence, next_skill = "writeup", "high", "cloversec-ctf-writeup-scaffold"
        evidence.append("writeup filename or solution keywords")
    elif suffix in BINARY_EXTENSIONS or has_binary_magic(head):
        resource_type, confidence, next_skill = "binary", "high", "cloversec-ctf-attachment-packager"
        evidence.append("binary extension or executable magic")
    elif suffix in WRITEUP_EXTENSIONS:
        resource_type, confidence, next_skill = "note", "medium", "cloversec-ctf-writeup-scaffold"
        evidence.append(f"text/writeup-capable extension {suffix}")
    elif is_binary_blob(head):
        resource_type, confidence, next_skill = "binary", "medium", "cloversec-ctf-attachment-packager"
        evidence.append("non-text bytes detected")

    return {
        "relative_path": relative,
        "name": path.name,
        "size": file_size,
        "sha256": search.sha256_file(path),
        "resource_type": resource_type,
        "confidence": confidence,
        "recommended_next_skill": next_skill,
        "evidence": evidence,
        "archive_preview": compact_archive_preview(archive_preview),
    }


def classify_root(resources: list[dict[str, Any]]) -> dict[str, Any]:
    types = Counter(str(item.get("resource_type") or "unknown") for item in resources)
    evidence: list[str] = []
    project_type = "mixed_resource_bundle"
    confidence = "low"
    next_skill = "cloversec-ctf-asset-collector"

    if types.get("compose_file"):
        project_type, confidence, next_skill = "compose_project", "high", "cloversec-ctf-build-dockerizer"
        evidence.append("compose file found")
    elif types.get("dockerfile"):
        project_type, confidence, next_skill = "container_project", "high", "cloversec-ctf-build-dockerizer"
        evidence.append("Dockerfile found")
    elif types.get("docker_image_tar"):
        project_type, confidence, next_skill = "docker_image_delivery", "high", "cloversec-ctf-build-dockerizer"
        evidence.append("docker image tar found")
    elif types.get("source_archive"):
        project_type, confidence, next_skill = "source_archive_bundle", "high", "cloversec-ctf-build-dockerizer"
        evidence.append("source archive found")
    elif types.get("source_manifest") or has_service_source_bundle(resources, types):
        project_type, confidence, next_skill = "source_project", "medium", "cloversec-ctf-build-dockerizer"
        evidence.append("source files or package manifests found")
    elif types.get("ctf_manifest") and only_metadata_solver_or_notes(types):
        project_type, confidence, next_skill = "challenge_metadata_bundle", "medium", "cloversec-ctf-asset-collector"
        evidence.append("CTF metadata manifest found without service source or attachment")
    elif types.get("solver_file") and only_metadata_solver_or_notes(types):
        project_type, confidence, next_skill = "solver_or_writeup_bundle", "medium", "cloversec-ctf-writeup-scaffold"
        evidence.append("solver/writeup material found without original challenge resources")
    elif types.get("metadata_archive") and only_metadata_solver_or_notes(types):
        project_type, confidence, next_skill = "challenge_metadata_bundle", "medium", "cloversec-ctf-asset-collector"
        evidence.append("CTF metadata archive found without service source or attachment")
    elif types.get("writeup_archive") and only_metadata_solver_or_notes(types):
        project_type, confidence, next_skill = "solver_or_writeup_bundle", "medium", "cloversec-ctf-writeup-scaffold"
        evidence.append("writeup or solver archive found without original challenge resources")
    elif types.get("attachment_archive") or types.get("binary") or types.get("pcap") or types.get("database_dump"):
        project_type, confidence, next_skill = "attachment_challenge", "medium", "cloversec-ctf-attachment-packager"
        evidence.append("attachment-oriented resources found")
    elif types.get("writeup") and len(resources) <= max(3, types.get("writeup", 0) + types.get("screenshot", 0)):
        project_type, confidence, next_skill = "writeup_only", "medium", "cloversec-ctf-writeup-scaffold"
        evidence.append("writeup material dominates directory")
    elif not resources:
        project_type, confidence, next_skill = "empty", "low", "manual_review"
        evidence.append("no files found")

    return {
        "project_type": project_type,
        "confidence": confidence,
        "recommended_next_skill": next_skill,
        "platform_delivery": build_platform_delivery_policy(project_type),
        "evidence": evidence,
    }


def summarize(resources: list[dict[str, Any]], root_classification: dict[str, Any]) -> dict[str, Any]:
    return {
        "total_resources": len(resources),
        "by_resource_type": dict(Counter(str(item.get("resource_type") or "unknown") for item in resources)),
        "by_recommended_next_skill": dict(Counter(str(item.get("recommended_next_skill") or "manual_review") for item in resources)),
        "by_confidence": dict(Counter(str(item.get("confidence") or "low") for item in resources)),
        "project_type": root_classification.get("project_type", ""),
        "project_confidence": root_classification.get("confidence", ""),
        "recommended_next_skill": root_classification.get("recommended_next_skill", ""),
    }


def build_recommendations(root_classification: dict[str, Any], resources: list[dict[str, Any]]) -> list[dict[str, str]]:
    recommendations = [
        {
            "type": "next_skill",
            "skill": str(root_classification.get("recommended_next_skill") or "manual_review"),
            "reason": "; ".join(str(item) for item in root_classification.get("evidence", [])),
        }
    ]
    low_confidence = [item.get("relative_path", "") for item in resources if item.get("confidence") == "low"]
    if low_confidence:
        recommendations.append(
            {
                "type": "manual_review",
                "skill": "manual_review",
                "reason": f"{len(low_confidence)} low-confidence file(s) need review",
            }
        )
    if any(item.get("resource_type") == "docker_image_tar" for item in resources):
        recommendations.append(
            {
                "type": "platform_conversion",
                "skill": "cloversec-ctf-build-dockerizer",
                "reason": "docker image tar is migration input; Docker inspection is evidence only and final delivery still needs Dockerizer conversion",
            }
        )
    platform_delivery = (
        root_classification.get("platform_delivery")
        if isinstance(root_classification.get("platform_delivery"), dict)
        else {}
    )
    if platform_delivery.get("must_use_dockerizer"):
        recommendations.append(
            {
                "type": "platform_conversion",
                "skill": "cloversec-ctf-build-dockerizer",
                "reason": "container/source resources must be converted to the CloverSec platform contract before final delivery",
            }
        )
    elif root_classification.get("project_type") in {"empty", "writeup_only", "challenge_metadata_bundle", "solver_or_writeup_bundle"}:
        recommendations.append(
            {
                "type": "missing_material",
                "skill": "manual_review",
                "reason": "original source, official attachment, or deployable resource is required before this can be treated as a reproducible challenge",
            }
        )
    return recommendations


def build_platform_delivery_policy(project_type: str) -> dict[str, Any]:
    must_use_dockerizer = project_type in {
        "compose_project",
        "container_project",
        "docker_image_delivery",
        "source_archive_bundle",
        "source_project",
    }
    requires_contract = must_use_dockerizer
    return {
        "requires_cloversec_contract": requires_contract,
        "must_use_dockerizer": must_use_dockerizer,
        "existing_docker_is_reference_only": project_type in {"compose_project", "container_project", "docker_image_delivery"},
        "final_delivery_skill": "cloversec-ctf-build-dockerizer" if must_use_dockerizer else "",
        "requires_user_confirmation": must_use_dockerizer,
        "confirmation_action": "dockerizer" if must_use_dockerizer else "",
        "blocking_until_confirmed": must_use_dockerizer,
        "attachment_only": project_type == "attachment_challenge",
        "writeup_only": project_type == "writeup_only",
        "status": platform_delivery_status(project_type),
    }


def platform_delivery_status(project_type: str) -> str:
    if project_type in {"compose_project", "container_project"}:
        return "docker_reference_needs_platform_conversion"
    if project_type in {"source_archive_bundle", "source_project"}:
        return "source_needs_platform_conversion"
    if project_type == "docker_image_delivery":
        return "image_tar_needs_platform_conversion"
    if project_type == "attachment_challenge":
        return "attachment_packaging"
    if project_type in {"empty", "writeup_only", "challenge_metadata_bundle", "solver_or_writeup_bundle"}:
        return "needs_user_material"
    return "manual_review"


def build_warnings(resources: list[dict[str, Any]], file_count: int, max_files: int) -> list[str]:
    warnings = []
    if file_count >= max_files:
        warnings.append(f"file scan truncated at max_files={max_files}")
    if any(item.get("archive_preview", {}).get("issues", 0) for item in resources):
        warnings.append("one or more archive previews reported issues")
    if any(item.get("resource_type") == "unknown" for item in resources):
        warnings.append("unknown resources remain and need manual review")
    return warnings


def looks_solver_source(path: Path, root: Path, text_sample: str) -> bool:
    relative_parts = [part.lower() for part in path.relative_to(root).parts]
    stem = path.stem.lower()
    name = path.name.lower()
    if any(hint in part for part in relative_parts for hint in SOLVER_HINTS):
        return True
    if any(hint in stem or hint in name for hint in SOLVER_HINTS):
        return True
    lowered = text_sample.lower()
    return any(marker in lowered for marker in ["flag{", "ctf{", "solve(", "pwn.remote", "pwntools", "sage"])


def path_has_solver_hint(path: str) -> bool:
    lowered_parts = [part.lower() for part in Path(path).parts]
    return any(hint in part for part in lowered_parts for hint in SOLVER_HINTS)


def has_service_source_bundle(resources: list[dict[str, Any]], types: Counter[str]) -> bool:
    service_like = [
        item
        for item in resources
        if item.get("resource_type") == "source_file"
        and any(hint in str(item.get("relative_path", "")).lower() for hint in SERVICE_HINTS)
    ]
    return bool(service_like) or types.get("source_file", 0) >= 4


def only_metadata_solver_or_notes(types: Counter[str]) -> bool:
    allowed = {
        "ctf_manifest",
        "metadata_archive",
        "solver_file",
        "writeup",
        "writeup_archive",
        "note",
        "screenshot",
        "flag_file",
        "unknown",
    }
    active = {resource_type for resource_type, count in types.items() if count > 0}
    return bool(active) and active <= allowed


def classify_archive_preview(preview: dict[str, Any]) -> tuple[str, list[str], str]:
    entries = preview.get("entries", []) if isinstance(preview.get("entries"), list) else []
    paths = [str(item.get("path") or "").lower() for item in entries if isinstance(item, dict)]
    evidence = []
    if any(path.endswith("/dockerfile") or path == "dockerfile" or path.endswith("dockerfile") for path in paths):
        evidence.append("archive contains Dockerfile")
        return "source_archive", evidence, "cloversec-ctf-build-dockerizer"
    if any(Path(path).name in COMPOSE_FILES for path in paths):
        evidence.append("archive contains compose file")
        return "source_archive", evidence, "cloversec-ctf-build-dockerizer"
    if any(Path(path).name in PACKAGE_FILES for path in paths):
        evidence.append("archive contains package manifest")
        return "source_archive", evidence, "cloversec-ctf-build-dockerizer"
    if any(Path(path).suffix in SOURCE_EXTENSIONS and not path_has_solver_hint(path) for path in paths):
        evidence.append("archive contains source files")
        return "source_archive", evidence, "cloversec-ctf-build-dockerizer"
    if any(Path(path).name in CTF_MANIFEST_FILES for path in paths):
        evidence.append("archive contains CTF metadata manifest")
        return "metadata_archive", evidence, "cloversec-ctf-asset-collector"
    if any(Path(path).suffix in SOURCE_EXTENSIONS and path_has_solver_hint(path) for path in paths):
        evidence.append("archive contains solver/writeup source")
        return "writeup_archive", evidence, "cloversec-ctf-writeup-scaffold"
    if any("writeup" in path or Path(path).name in {"wp.md", "writeup.md"} for path in paths):
        evidence.append("archive contains writeup material")
        return "writeup_archive", evidence, "cloversec-ctf-writeup-scaffold"
    return "attachment_archive", evidence, "cloversec-ctf-attachment-packager"


def is_docker_image_tar(path: Path, archive_preview_entries: int) -> bool:
    suffixes = "".join(path.suffixes).lower()
    if not (suffixes.endswith(".tar") or suffixes.endswith(".tar.gz") or suffixes.endswith(".tgz")):
        return False
    preview = safe_archive_preview(path, archive_preview_entries)
    entries = preview.get("entries", []) if isinstance(preview.get("entries"), list) else []
    paths = [str(item.get("path") or "").lower() for item in entries if isinstance(item, dict)]
    return "manifest.json" in paths and ("repositories" in paths or any(path.endswith("/layer.tar") for path in paths))


def safe_archive_preview(path: Path, archive_preview_entries: int) -> dict[str, Any]:
    try:
        return search.preview_archive(path, max_entries=archive_preview_entries)
    except Exception as exc:  # noqa: BLE001
        return {"path": path.as_posix(), "entries": [], "issues": [{"path": path.name, "error": str(exc)}], "summary": {"issues": 1}}


def compact_archive_preview(preview: dict[str, Any]) -> dict[str, Any]:
    if not preview:
        return {}
    summary = preview.get("summary") if isinstance(preview.get("summary"), dict) else {}
    return {
        "archive_type": preview.get("archive_type", ""),
        "entries": summary.get("entries", len(preview.get("entries", [])) if isinstance(preview.get("entries"), list) else 0),
        "issues": summary.get("issues", len(preview.get("issues", [])) if isinstance(preview.get("issues"), list) else 0),
        "total_uncompressed": summary.get("total_uncompressed", 0),
        "truncated": summary.get("truncated", False),
    }


def normalized_suffix(path: Path) -> str:
    suffixes = [item.lower() for item in path.suffixes]
    if len(suffixes) >= 2 and "".join(suffixes[-2:]) in {".tar.gz", ".tar.xz", ".tar.bz2"}:
        return "".join(suffixes[-2:])
    return path.suffix.lower()


def read_head(path: Path, *, max_bytes: int) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(max_bytes)
    except OSError:
        return b""


def should_read_text(path: Path, head: bytes) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS or path.name.lower() in PACKAGE_FILES or path.name.lower() in COMPOSE_FILES:
        return not is_binary_blob(head)
    return False


def read_text_sample(path: Path, *, max_bytes: int) -> str:
    try:
        data = path.read_bytes()[:max_bytes]
    except OSError:
        return ""
    if is_binary_blob(data):
        return ""
    for encoding in ["utf-8", "gb18030", "latin-1"]:
        try:
            return data.decode(encoding, errors="replace")
        except LookupError:
            continue
    return data.decode("utf-8", errors="replace")


def looks_writeup(path: Path, text_sample: str) -> bool:
    lower_name = path.name.lower()
    if "writeup" in lower_name or lower_name in {"wp.md", "wp.txt", "solution.md", "solve.md"}:
        return True
    if path.suffix.lower() not in WRITEUP_EXTENSIONS:
        return False
    lowered = text_sample.lower()
    return any(marker in lowered for marker in ["writeup", "solution", "solve", "flag{", "解题", "题解", "wp"])


def has_binary_magic(head: bytes) -> bool:
    return head.startswith(b"\x7fELF") or head.startswith(b"MZ") or head.startswith(b"\xca\xfe\xba\xbe")


def has_pcap_magic(head: bytes) -> bool:
    return head.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"))


def has_sqlite_magic(head: bytes) -> bool:
    return head.startswith(b"SQLite format 3")


def is_binary_blob(head: bytes) -> bool:
    if not head:
        return False
    if b"\x00" in head[:1024]:
        return True
    control = sum(1 for byte in head[:1024] if byte < 9 or (13 < byte < 32))
    return control > max(10, len(head[:1024]) // 20)


def write_json(path: str | Path, payload: Any) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Classify CloverSec CTF local resource directories")
    subparsers = parser.add_subparsers(dest="command", required=True)

    classify_parser = subparsers.add_parser("classify", help="classify a local resource directory")
    classify_parser.add_argument("root")
    classify_parser.add_argument("--output", required=True)
    classify_parser.add_argument("--max-files", type=int, default=2000)
    classify_parser.add_argument("--max-text-bytes", type=int, default=65536)
    classify_parser.add_argument("--archive-preview-entries", type=int, default=200)

    args = parser.parse_args(argv)
    if args.command == "classify":
        payload = classify_resource_root(
            args.root,
            output_path=args.output,
            max_files=args.max_files,
            max_text_bytes=args.max_text_bytes,
            archive_preview_entries=args.archive_preview_entries,
        )
        print(json.dumps({"output": args.output, "project_type": payload["summary"]["project_type"]}, ensure_ascii=False))
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
