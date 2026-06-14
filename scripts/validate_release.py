#!/usr/bin/env python3
"""Validate the repo marketplace and plugin metadata before release."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "cloversec-ctf-forexample"
MARKETPLACE = ROOT / ".agents" / "plugins" / "marketplace.json"
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
PLACEHOLDER_PHRASES = {
    "CloverSec CTF workflow skill",
    "Use this CloverSec CTF skill.",
    "[TODO:",
}


def main() -> int:
    errors: list[str] = []
    validate_marketplace(errors)
    validate_plugin_manifest(errors)
    validate_skills(errors)
    validate_mcp(errors)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("release validation passed")
    return 0


def validate_marketplace(errors: list[str]) -> None:
    data = read_json(MARKETPLACE, errors)
    if not isinstance(data, dict):
        return
    if data.get("name") != "cloversec-ctf":
        errors.append("marketplace name must be cloversec-ctf")
    plugins = data.get("plugins")
    if not isinstance(plugins, list) or not plugins:
        errors.append("marketplace plugins[] is required")
        return
    match = next((item for item in plugins if item.get("name") == "cloversec-ctf-forexample"), None)
    if not isinstance(match, dict):
        errors.append("marketplace must include cloversec-ctf-forexample")
        return
    source = match.get("source") if isinstance(match.get("source"), dict) else {}
    if source.get("source") != "local" or source.get("path") != "./plugins/cloversec-ctf-forexample":
        errors.append("marketplace source must point to ./plugins/cloversec-ctf-forexample")
    policy = match.get("policy") if isinstance(match.get("policy"), dict) else {}
    if policy.get("installation") != "AVAILABLE" or policy.get("authentication") != "ON_INSTALL":
        errors.append("marketplace policy must be AVAILABLE / ON_INSTALL")
    if not match.get("category"):
        errors.append("marketplace plugin category is required")


def validate_plugin_manifest(errors: list[str]) -> None:
    manifest_path = PLUGIN / ".codex-plugin" / "plugin.json"
    data = read_json(manifest_path, errors)
    if not isinstance(data, dict):
        return
    required = ["name", "version", "description", "author", "skills", "mcpServers", "interface"]
    for field in required:
        if not data.get(field):
            errors.append(f"plugin.json missing {field}")
    if data.get("name") != "cloversec-ctf-forexample":
        errors.append("plugin.json name mismatch")
    version = str(data.get("version") or "")
    if not SEMVER_RE.match(version):
        errors.append(f"plugin version is not semver: {version}")
    tag = os.environ.get("GITHUB_REF_NAME", "")
    if tag.startswith("v") and tag != f"v{version}":
        errors.append(f"git tag {tag} does not match plugin version {version}")
    for path_field in ["skills", "mcpServers"]:
        value = str(data.get(path_field) or "")
        if not value.startswith("./"):
            errors.append(f"{path_field} must use ./ relative path")
        if value and not (PLUGIN / value).resolve().exists():
            errors.append(f"{path_field} path does not exist: {value}")
    interface = data.get("interface") if isinstance(data.get("interface"), dict) else {}
    for field in ["displayName", "shortDescription", "longDescription", "developerName", "category"]:
        if not interface.get(field):
            errors.append(f"plugin interface missing {field}")
    if interface.get("websiteURL") and not str(interface["websiteURL"]).startswith("https://"):
        errors.append("websiteURL must be https")
    for phrase in PLACEHOLDER_PHRASES:
        if phrase in json.dumps(data, ensure_ascii=False):
            errors.append(f"plugin manifest still contains placeholder: {phrase}")


def validate_skills(errors: list[str]) -> None:
    skills_dir = PLUGIN / "skills"
    skill_dirs = sorted(path for path in skills_dir.iterdir() if path.is_dir())
    if len(skill_dirs) != 13:
        errors.append(f"expected 13 skills, found {len(skill_dirs)}")
    for skill_dir in skill_dirs:
        skill_md = skill_dir / "SKILL.md"
        openai_yaml = skill_dir / "agents" / "openai.yaml"
        if not skill_md.exists():
            errors.append(f"missing SKILL.md: {skill_dir.name}")
            continue
        text = skill_md.read_text(encoding="utf-8")
        name = frontmatter_value(text, "name")
        description = frontmatter_value(text, "description")
        if name != skill_dir.name:
            errors.append(f"{skill_dir.name}: frontmatter name mismatch")
        if not description or len(description) < 30:
            errors.append(f"{skill_dir.name}: description is too short")
        if not openai_yaml.exists():
            errors.append(f"{skill_dir.name}: missing agents/openai.yaml")
            continue
        yaml_text = openai_yaml.read_text(encoding="utf-8")
        for phrase in PLACEHOLDER_PHRASES:
            if phrase in yaml_text:
                errors.append(f"{skill_dir.name}: placeholder in openai.yaml")
        if f"${skill_dir.name}" not in yaml_text:
            errors.append(f"{skill_dir.name}: default_prompt must mention ${skill_dir.name}")
        if "short_description:" not in yaml_text:
            errors.append(f"{skill_dir.name}: short_description is required")


def validate_mcp(errors: list[str]) -> None:
    data = read_json(PLUGIN / ".mcp.json", errors)
    if not isinstance(data, dict):
        return
    servers = data.get("mcpServers") if isinstance(data.get("mcpServers"), dict) else {}
    for name in [
        "cloversec-ctf-search",
        "cloversec-ctf-browser-search",
        "cloversec-ctf-search-plus",
        "cloversec-ctf-docker",
        "cloversec-ctf-archive",
        "cloversec-ctf-quality-runner",
        "cloversec-ctf-hub-assistant",
        "cloversec-ctf-workflow",
    ]:
        if name not in servers:
            errors.append(f".mcp.json missing {name}")


def frontmatter_value(text: str, key: str) -> str:
    if not text.startswith("---"):
        return ""
    end = text.find("\n---", 3)
    if end == -1:
        return ""
    for line in text[3:end].splitlines():
        if line.startswith(f"{key}:"):
            return line.split(":", 1)[1].strip().strip('"')
    return ""


def read_json(path: Path, errors: list[str]) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"failed to read JSON {path}: {exc}")
        return None


if __name__ == "__main__":
    raise SystemExit(main())
