#!/usr/bin/env python3
"""Container challenge inference for CloverSec CTF workflows."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "cloversec.ctf.container_inference.v1"
VERSION = "0.8.1"
TEXT_LIMIT = 65536
COMPOSE_FILES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
HELPER_FILES = {"start.sh", "changeflag.sh", "check.sh"}
MANIFEST_FILES = {"challenge.yaml", "challenge.yml", "challenge.json", "ctfd.yaml", "ctfd.yml"}
README_NAMES = {"readme", "readme.md", "readme.txt", "wp.md", "writeup.md", "solution.md"}


def infer_container_project(
    project_dir: str | Path,
    *,
    resource_classification: dict[str, Any] | str | Path | None = None,
    output_path: str | Path | None = None,
    max_text_bytes: int = TEXT_LIMIT,
) -> dict[str, Any]:
    root = Path(project_dir)
    if not root.exists():
        raise FileNotFoundError(root)
    if not root.is_dir():
        raise ValueError(f"project_dir is not a directory: {root}")

    classification = load_resource_classification(resource_classification)
    dockerfiles = sorted(path for path in root.rglob("*") if path.is_file() and path.name.lower() == "dockerfile")
    compose_files = sorted(path for path in root.rglob("*") if path.is_file() and path.name.lower() in COMPOSE_FILES)
    helpers = collect_helpers(root)
    readme_hints = collect_readme_hints(root, max_text_bytes=max_text_bytes)
    challenge_manifest = collect_challenge_manifest(root, max_text_bytes=max_text_bytes)
    dockerfile_payload = parse_dockerfile(dockerfiles[0], root, max_text_bytes=max_text_bytes) if dockerfiles else {}
    compose_payload = parse_compose_files(compose_files, root, max_text_bytes=max_text_bytes)
    classification_summary = summarize_classification(classification)

    ports = merge_ports(
        dockerfile_payload.get("exposed_ports", []),
        compose_payload.get("ports", []),
        readme_hints.get("ports", []),
        challenge_manifest.get("ports", []),
    )
    project_type, confidence, evidence = infer_project_type(
        has_dockerfile=bool(dockerfiles),
        has_compose=bool(compose_files),
        classification_summary=classification_summary,
        readme_hints=readme_hints,
        challenge_manifest=challenge_manifest,
    )
    warnings = build_warnings(project_type, dockerfile_payload, compose_payload, classification_summary)
    validation_level = recommend_validation_level(
        project_type=project_type,
        has_dockerfile=bool(dockerfiles),
        has_compose=bool(compose_files),
        has_image_tar=classification_summary.get("docker_image_tar", 0) > 0,
        ports=ports,
        warnings=warnings,
    )
    platform_delivery = build_platform_delivery_policy(project_type)
    image_name = suggest_image_name(challenge_manifest, root)
    runtime = {
        "image_name": image_name,
        "build_context": root.as_posix() if dockerfiles or compose_files else "",
        "dockerfile": dockerfile_payload.get("relative_path", ""),
        "ports": ports,
        "container_command": readme_hints.get("container_command", ""),
        "dockerfile_cmd": dockerfile_payload.get("cmd", ""),
        "dockerfile_entrypoint": dockerfile_payload.get("entrypoint", ""),
        "probe_urls": probe_urls_from_ports(ports),
        "validation_level": validation_level,
    }
    payload = {
        "schema_version": SCHEMA_VERSION,
        "version": VERSION,
        "generated_at": utc_now(),
        "project_dir": root.as_posix(),
        "platform_contract_required": platform_delivery["requires_cloversec_contract"],
        "must_use_dockerizer": platform_delivery["must_use_dockerizer"],
        "existing_docker_is_reference_only": platform_delivery["existing_docker_is_reference_only"],
        "final_delivery_skill": platform_delivery["final_delivery_skill"],
        "summary": {
            "project_type": project_type,
            "confidence": confidence,
            "service_count": len(compose_payload.get("services", [])) or (1 if dockerfiles else 0),
            "ports": ports,
            "dockerfile": dockerfile_payload.get("relative_path", ""),
            "compose_files": [item.get("relative_path", "") for item in compose_payload.get("files", [])],
            "recommended_validation_level": validation_level,
            "platform_contract_required": platform_delivery["requires_cloversec_contract"],
            "must_use_dockerizer": platform_delivery["must_use_dockerizer"],
            "requires_manual_review": bool(warnings) or confidence != "high",
        },
        "platform_delivery": platform_delivery,
        "dockerfile": dockerfile_payload,
        "compose": compose_payload,
        "runtime": runtime,
        "helpers": helpers,
        "readme_hints": readme_hints,
        "challenge_manifest": challenge_manifest,
        "resource_classification": classification_summary,
        "evidence": evidence,
        "warnings": warnings,
        "next_actions": build_next_actions(validation_level, project_type, warnings),
    }
    if output_path:
        write_json(output_path, payload)
    return payload


def load_resource_classification(value: dict[str, Any] | str | Path | None) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if value:
        path = Path(value)
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    return {}


def summarize_classification(classification: dict[str, Any]) -> dict[str, Any]:
    resources = classification.get("resources") if isinstance(classification.get("resources"), list) else []
    counts: dict[str, int] = {}
    for item in resources:
        if not isinstance(item, dict):
            continue
        resource_type = str(item.get("resource_type") or "unknown")
        counts[resource_type] = counts.get(resource_type, 0) + 1
    root_classification = classification.get("root_classification") if isinstance(classification.get("root_classification"), dict) else {}
    return {
        "project_type": root_classification.get("project_type", ""),
        "confidence": root_classification.get("confidence", ""),
        "recommended_next_skill": root_classification.get("recommended_next_skill", ""),
        **counts,
    }


def parse_dockerfile(path: Path, root: Path, *, max_text_bytes: int) -> dict[str, Any]:
    lines = read_text(path, max_text_bytes=max_text_bytes).splitlines()
    base_images: list[str] = []
    exposed_ports: list[str] = []
    env: dict[str, str] = {}
    workdir = ""
    cmd = ""
    entrypoint = ""
    evidence: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        instruction, _, rest = line.partition(" ")
        key = instruction.upper()
        value = rest.strip()
        if key == "FROM" and value:
            base = value.split(" AS ", 1)[0].split(" as ", 1)[0].strip()
            base_images.append(base)
            evidence.append(f"FROM {base}")
        elif key == "EXPOSE":
            for port in re.findall(r"\b\d{2,5}(?:/(?:tcp|udp))?\b", value):
                exposed_ports.append(normalize_container_port(port))
        elif key == "ENV":
            env.update(parse_env(value))
        elif key == "WORKDIR":
            workdir = value
        elif key == "CMD":
            cmd = value
        elif key == "ENTRYPOINT":
            entrypoint = value
    return {
        "relative_path": path.relative_to(root).as_posix(),
        "base_images": dedupe(base_images),
        "exposed_ports": dedupe(exposed_ports),
        "env": env,
        "workdir": workdir,
        "cmd": cmd,
        "entrypoint": entrypoint,
        "evidence": evidence,
    }


def parse_compose_files(paths: list[Path], root: Path, *, max_text_bytes: int) -> dict[str, Any]:
    files = []
    services: list[dict[str, Any]] = []
    all_ports: list[str] = []
    for path in paths:
        text = read_text(path, max_text_bytes=max_text_bytes)
        parsed = parse_compose_text(text)
        files.append({"relative_path": path.relative_to(root).as_posix(), "service_count": len(parsed["services"])})
        services.extend(parsed["services"])
        all_ports.extend(parsed["ports"])
    return {
        "files": files,
        "services": services,
        "ports": dedupe(all_ports),
    }


def parse_compose_text(text: str) -> dict[str, Any]:
    services: list[dict[str, Any]] = []
    ports: list[str] = []
    in_services = False
    current: dict[str, Any] | None = None
    current_indent = 0
    in_ports = False
    in_environment = False
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip().strip("'\"")
        if re.match(r"^services\s*:\s*$", stripped):
            in_services = True
            current = None
            continue
        if not in_services:
            ports.extend(extract_port_mappings(stripped))
            continue
        service_match = re.match(r"^([A-Za-z0-9_.-]+)\s*:\s*$", stripped)
        if service_match and (current is None or indent <= current_indent):
            current = {"name": service_match.group(1), "build": "", "image": "", "command": "", "ports": [], "environment": {}}
            current_indent = indent
            services.append(current)
            in_ports = False
            in_environment = False
            continue
        if current is None:
            continue
        if indent <= current_indent:
            current = None
            in_ports = False
            in_environment = False
            continue
        if stripped.startswith("ports:"):
            in_ports = True
            in_environment = False
            continue
        if stripped.startswith("environment:"):
            in_environment = True
            in_ports = False
            continue
        if stripped.startswith("build:"):
            current["build"] = value_after_colon(stripped)
        elif stripped.startswith("image:"):
            current["image"] = value_after_colon(stripped)
        elif stripped.startswith("command:"):
            current["command"] = value_after_colon(stripped)
        elif in_ports:
            found = extract_port_mappings(stripped)
            current["ports"].extend(found)
            ports.extend(found)
        elif in_environment:
            env_key, env_value = parse_compose_env_line(stripped)
            if env_key:
                current["environment"][env_key] = env_value
    for service in services:
        service["ports"] = dedupe(service.get("ports", []))
    return {"services": services, "ports": dedupe(ports)}


def collect_helpers(root: Path) -> list[dict[str, Any]]:
    output = []
    for path in sorted(item for item in root.rglob("*") if item.is_file() and item.name.lower() in HELPER_FILES):
        output.append({"relative_path": path.relative_to(root).as_posix(), "name": path.name, "size": path.stat().st_size})
    return output


def collect_readme_hints(root: Path, *, max_text_bytes: int) -> dict[str, Any]:
    hints: list[str] = []
    ports: list[str] = []
    commands: list[str] = []
    container_command = ""
    for path in sorted(item for item in root.rglob("*") if item.is_file() and item.name.lower() in README_NAMES):
        text = read_text(path, max_text_bytes=max_text_bytes)
        for line in text.splitlines():
            stripped = line.strip()
            lower = stripped.lower()
            if "docker build" in lower or "docker run" in lower or "docker compose" in lower:
                commands.append(stripped[:300])
                hints.append(f"{path.relative_to(root).as_posix()}: {stripped[:160]}")
            ports.extend(extract_port_mappings(stripped))
            for item in re.findall(r"(?:port|端口)\D{0,12}(\d{2,5})", stripped, flags=re.IGNORECASE):
                ports.append(f"{item}:{item}")
            if not container_command and ("cmd:" in lower or "command:" in lower):
                container_command = value_after_colon(stripped)
    return {
        "commands": dedupe(commands),
        "ports": dedupe(ports),
        "container_command": container_command,
        "evidence": dedupe(hints),
    }


def collect_challenge_manifest(root: Path, *, max_text_bytes: int) -> dict[str, Any]:
    for path in sorted(item for item in root.rglob("*") if item.is_file() and item.name.lower() in MANIFEST_FILES):
        text = read_text(path, max_text_bytes=max_text_bytes)
        data = parse_simple_manifest(text)
        data["relative_path"] = path.relative_to(root).as_posix()
        data["ports"] = extract_manifest_ports(text)
        return data
    return {}


def parse_simple_manifest(text: str) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key in ["name", "category", "value", "type", "description", "connection_info"]:
        match = re.search(rf"(?im)^\s*{re.escape(key)}\s*:\s*(.+?)\s*$", text)
        if match:
            output[key] = match.group(1).strip().strip("'\"")
    return output


def extract_manifest_ports(text: str) -> list[str]:
    ports = extract_port_mappings(text)
    for item in re.findall(r"\b(?:port|ports|开放端口)\s*[:=]\s*(\d{2,5})\b", text, flags=re.IGNORECASE):
        ports.append(f"{item}:{item}")
    return dedupe(ports)


def infer_project_type(
    *,
    has_dockerfile: bool,
    has_compose: bool,
    classification_summary: dict[str, Any],
    readme_hints: dict[str, Any],
    challenge_manifest: dict[str, Any],
) -> tuple[str, str, list[str]]:
    evidence: list[str] = []
    if has_compose:
        evidence.append("compose file found")
        return "compose_project", "high", evidence
    if has_dockerfile:
        evidence.append("Dockerfile found")
        return "container_project", "high", evidence
    if classification_summary.get("docker_image_tar", 0) > 0:
        evidence.append("docker image tar found")
        return "docker_image_delivery", "high", evidence
    if readme_hints.get("commands"):
        evidence.extend(readme_hints["evidence"])
        return "container_instructions", "medium", evidence
    if challenge_manifest.get("connection_info") or challenge_manifest.get("ports"):
        evidence.append("challenge manifest has connection or port hints")
        return "remote_service_challenge", "medium", evidence
    if classification_summary.get("project_type"):
        evidence.append(f"resource_classification={classification_summary['project_type']}")
    return "non_container_or_unknown", "low", evidence


def recommend_validation_level(
    *,
    project_type: str,
    has_dockerfile: bool,
    has_compose: bool,
    has_image_tar: bool,
    ports: list[str],
    warnings: list[str],
) -> str:
    if project_type == "non_container_or_unknown":
        return "static_only"
    if has_image_tar and not has_dockerfile and not has_compose:
        return "inspect_only"
    if has_compose:
        return "run_probe" if ports else "build_only"
    if has_dockerfile:
        return "run_probe" if ports else "build_only"
    if warnings:
        return "static_only"
    return "inspect_only"


def build_warnings(
    project_type: str,
    dockerfile_payload: dict[str, Any],
    compose_payload: dict[str, Any],
    classification_summary: dict[str, Any],
) -> list[str]:
    warnings: list[str] = []
    if project_type == "container_project" and not dockerfile_payload.get("base_images"):
        warnings.append("Dockerfile has no FROM line")
    if project_type == "compose_project" and not compose_payload.get("services"):
        warnings.append("compose file detected but no services parsed")
    if project_type in {"container_project", "compose_project"}:
        warnings.append("existing Dockerfile/compose is migration input only; run cloversec-ctf-build-dockerizer before final delivery")
    if project_type == "non_container_or_unknown":
        warnings.append("no Dockerfile, compose file, image tar, or runtime instruction was found")
    if classification_summary.get("project_type") == "attachment_challenge" and project_type != "non_container_or_unknown":
        warnings.append("resource classifier also found attachment-oriented evidence")
    return dedupe(warnings)


def build_next_actions(validation_level: str, project_type: str, warnings: list[str]) -> list[str]:
    actions = []
    if warnings:
        actions.append("review container_inference.warnings before running Docker")
    if validation_level == "static_only":
        actions.append("keep this as a static resource review unless the user provides Docker evidence")
    elif validation_level == "inspect_only":
        actions.append("load or inspect the image and record linux/amd64 evidence")
    elif validation_level == "build_only":
        actions.append("build for linux/amd64 and inspect the image before archive")
    elif validation_level == "run_probe":
        actions.append("build/inspect/run/logs/stop and record probe results")
    elif validation_level == "solve_verify":
        actions.append("only run solver verification after explicit user approval")
    if project_type in {"container_project", "compose_project", "docker_image_delivery"}:
        actions.append("send runtime fields to cloversec-ctf-build-dockerizer for CloverSec platform contract conversion")
        actions.append("use cloversec-ctf-docker only for approved build/run evidence, not as final delivery conversion")
    return dedupe(actions)


def build_platform_delivery_policy(project_type: str) -> dict[str, Any]:
    must_use_dockerizer = project_type in {
        "container_project",
        "compose_project",
        "container_instructions",
        "remote_service_challenge",
        "docker_image_delivery",
    }
    requires_contract = must_use_dockerizer
    return {
        "status": platform_delivery_status(project_type),
        "requires_cloversec_contract": requires_contract,
        "must_use_dockerizer": must_use_dockerizer,
        "existing_docker_is_reference_only": project_type in {"container_project", "compose_project", "docker_image_delivery"},
        "final_delivery_skill": "cloversec-ctf-build-dockerizer" if must_use_dockerizer else "",
        "requires_user_confirmation": must_use_dockerizer,
        "confirmation_action": "dockerizer" if must_use_dockerizer else "",
        "blocking_until_confirmed": must_use_dockerizer,
        "docker_validation_is_evidence_only": project_type in {"container_project", "compose_project", "docker_image_delivery"},
    }


def platform_delivery_status(project_type: str) -> str:
    if project_type in {"container_project", "compose_project"}:
        return "requires_cloversec_contract"
    if project_type in {"container_instructions", "remote_service_challenge"}:
        return "needs_platform_delivery_plan"
    if project_type == "docker_image_delivery":
        return "image_tar_needs_platform_conversion"
    return "not_container_delivery"


def extract_port_mappings(text: str) -> list[str]:
    output: list[str] = []
    for host, container in re.findall(r"(?<![\d.])(\d{2,5})\s*:\s*(\d{2,5})(?:/(?:tcp|udp))?\b", text):
        output.append(f"{host}:{container}")
    for container in re.findall(r"\bEXPOSE\s+(\d{2,5})(?:/(?:tcp|udp))?\b", text, flags=re.IGNORECASE):
        output.append(f"{container}:{container}")
    return dedupe(output)


def normalize_container_port(port: str) -> str:
    clean = port.split("/", 1)[0]
    return f"{clean}:{clean}"


def merge_ports(*groups: list[str]) -> list[str]:
    merged = []
    for group in groups:
        for item in group or []:
            text = str(item or "").strip().strip("'\"")
            if not text:
                continue
            if ":" not in text and text.isdigit():
                text = f"{text}:{text}"
            merged.append(text)
    return dedupe(merged)


def probe_urls_from_ports(ports: list[str]) -> list[str]:
    urls = []
    for mapping in ports:
        host = mapping.rsplit(":", 1)[0]
        if ":" in host:
            host = host.rsplit(":", 1)[1]
        if host.isdigit():
            urls.append(f"http://127.0.0.1:{host}/")
    return dedupe(urls)


def parse_env(value: str) -> dict[str, str]:
    output: dict[str, str] = {}
    parts = re.findall(r"(?:[^\s\"']+|\"[^\"]*\"|'[^']*')+", value)
    for part in parts:
        if "=" in part:
            key, env_value = part.split("=", 1)
            output[key] = env_value.strip("'\"")
    return output


def parse_compose_env_line(value: str) -> tuple[str, str]:
    text = value.lstrip("- ").strip().strip("'\"")
    if ":" in text:
        key, raw_value = text.split(":", 1)
        return key.strip(), raw_value.strip().strip("'\"")
    if "=" in text:
        key, raw_value = text.split("=", 1)
        return key.strip(), raw_value.strip().strip("'\"")
    return "", ""


def value_after_colon(value: str) -> str:
    return value.split(":", 1)[1].strip().strip("'\"") if ":" in value else ""


def suggest_image_name(challenge_manifest: dict[str, Any], root: Path) -> str:
    raw = str(challenge_manifest.get("name") or root.name or "challenge")
    token = re.sub(r"[^a-zA-Z0-9_.-]+", "-", raw.strip().lower()).strip(".-")
    return f"cloversec/{token or 'challenge'}:local"


def read_text(path: Path, *, max_text_bytes: int) -> str:
    data = path.read_bytes()[:max_text_bytes]
    return data.decode("utf-8", errors="replace")


def write_json(path: str | Path, payload: dict[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


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


def compact_inference(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "cloversec.ctf.container_inference.compact.v1",
        "version": payload.get("version", ""),
        "project_dir": payload.get("project_dir", ""),
        "summary": payload.get("summary", {}),
        "runtime": payload.get("runtime", {}),
        "warnings": payload.get("warnings", []),
        "next_actions": payload.get("next_actions", []),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Infer CloverSec CTF container challenge runtime")
    subparsers = parser.add_subparsers(dest="command", required=True)
    infer_parser = subparsers.add_parser("infer", help="write container_inference.json")
    infer_parser.add_argument("project_dir")
    infer_parser.add_argument("--resource-classification", default="")
    infer_parser.add_argument("--output", required=True)
    infer_parser.add_argument("--compact-output", default="")
    args = parser.parse_args(argv)
    if args.command == "infer":
        payload = infer_container_project(
            args.project_dir,
            resource_classification=args.resource_classification or None,
            output_path=args.output,
        )
        if args.compact_output:
            write_json(args.compact_output, compact_inference(payload))
        print(f"wrote {args.output}")
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
