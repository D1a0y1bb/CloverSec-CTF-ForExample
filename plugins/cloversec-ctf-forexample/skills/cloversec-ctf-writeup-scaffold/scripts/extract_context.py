#!/usr/bin/env python3
"""Extract structured, evidence-backed context for the writeup scaffold skill."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
DATA_DIR = SKILL_DIR / "data"
GENERATED_OUTPUTS = {
    "题目解题手册.md",
    "writeup_context.json",
    "writeup_proposal.md",
    "hub_fields.json",
    "xlsx_fields.json",
}
GENERATED_SUFFIXES = (".expected.md",)
STRUCTURED_JSON_FILES = {
    "hub_fields.json",
    "xlsx_fields.json",
    "docker_artifacts.json",
    "environment.json",
    "container_inference.json",
}


def load_yaml_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    if yaml is None:
        return parse_simple_yaml_mapping(path.read_text(encoding="utf-8", errors="ignore"))
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def parse_simple_yaml_mapping(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current_key = ""
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped.startswith("-") and current_key:
            value = stripped[1:].strip().strip("'\"")
            data.setdefault(current_key, [])
            if isinstance(data[current_key], list) and value:
                data[current_key].append(value)
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*:\s*(.*)$", stripped)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        current_key = key
        if value == "":
            data[key] = []
        elif value.startswith("[") and value.endswith("]"):
            data[key] = [item.strip().strip("'\"") for item in value[1:-1].split(",") if item.strip()]
        else:
            data[key] = value.strip("'\"")
    return data


def load_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


RULES = {
    "categories": load_yaml_file(DATA_DIR / "categories.yaml"),
    "difficulty": load_yaml_file(DATA_DIR / "difficulty_rules.yaml"),
    "sources": load_yaml_file(DATA_DIR / "source_patterns.yaml"),
    "defaults": load_yaml_file(DATA_DIR / "template_defaults.yaml"),
}


def rule_value(*keys: str, default: Any = None) -> Any:
    current: Any = RULES
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def dict_rule(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def list_rule(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


DEFAULT_CATEGORY_RULES = {
    "Web": {"aliases": ["web", "web题", "php", "node", "flask", "django", "fastapi", "spring", "apache", "nginx"]},
    "Pwn": {"aliases": ["pwn", "heap", "rop", "fmt", "uaf", "ret2libc", "xinetd", "socat"]},
    "Crypto": {"aliases": ["crypto", "rsa", "aes", "ecc", "hash", "lattice", "padding", "签名"]},
    "Misc": {"aliases": ["misc", "stego", "forensics", "traffic", "pcap", "ai", "osint"]},
    "Reverse": {"aliases": ["reverse", "rev", "ida", "ghidra", "apk", "逆向"]},
    "Mobile": {"aliases": ["mobile", "android", "ios", "apk", "ipa", "frida", "xposed"]},
    "IoT": {"aliases": ["iot", "firmware", "mips", "arm", "路由器", "固件"]},
}
CATEGORY_RULES = dict_rule(rule_value("categories", "categories", default={})) or DEFAULT_CATEGORY_RULES
DIFFICULTY_ALIASES = dict_rule(rule_value("difficulty", "difficulty", "aliases", default={}))
DIFFICULTY_KEYWORDS = dict_rule(rule_value("difficulty", "difficulty", "keywords", default={}))
STARS_MAP = dict_rule(rule_value("difficulty", "difficulty", "stars", default={}))
PLACEHOLDERS = dict_rule(rule_value("defaults", "placeholders", default={}))
DEFAULT_NOTES = dict_rule(rule_value("defaults", "notes", default={}))
MANUAL_DEFAULTS = dict_rule(rule_value("defaults", "manual", default={}))
EXCLUDED_DIRS = set(list_rule(rule_value("sources", "collection", "excluded_dirs", default=[])))
TEXT_EXTENSIONS = set(list_rule(rule_value("sources", "collection", "allowed_extensions", default=[])))
PREFERRED_FILES = {str(name).lower() for name in list_rule(rule_value("sources", "collection", "preferred_files", default=[]))}
if not TEXT_EXTENSIONS:
    TEXT_EXTENSIONS = {".md", ".txt", ".yaml", ".yml", ".json", ".py", ".js", ".ts", ".php", ".sh", ".conf", ".ini", ".env", ".dockerfile"}
if not PREFERRED_FILES:
    PREFERRED_FILES = {
        "meta.yaml",
        "meta.yml",
        "challenge.yaml",
        "challenge.yml",
        "hub_fields.json",
        "xlsx_fields.json",
        "docker_artifacts.json",
        "environment.json",
        "container_inference.json",
        "readme.md",
    }
MAX_DEPTH_VALUE = rule_value("sources", "collection", "max_depth", default=4)
MAX_DEPTH = int(MAX_DEPTH_VALUE) if str(MAX_DEPTH_VALUE).isdigit() else 4

ALLOWED_DIFFICULTIES = ["简单", "中等", "困难"]
ALLOWED_CATEGORIES = list(CATEGORY_RULES.keys()) if CATEGORY_RULES else ["Web", "Pwn", "Crypto", "Misc", "Reverse", "Mobile", "IoT"]
ALLOWED_FLAG_TYPES = ["静态Flag", "动态Flag"]
ALLOWED_SOURCES = ["原创", "搬运"]
ALLOWED_TYPES = ["环境型", "附件型"]
ALLOWED_RESOURCE_LEVELS = ["8", "4"]


def sanitize_text(value: str) -> str:
    value = re.sub(r"<[^>]+>", "", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")


def relative_to(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def evidence(path: Path | str, reason: str) -> dict[str, str]:
    return {"path": str(path), "reason": reason}


def make_field(
    value: Any,
    status: str = "placeholder",
    confidence: str = "low",
    evidence_items: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return {
        "value": value,
        "status": status,
        "confidence": confidence,
        "evidence": evidence_items or [],
    }


def merge_field(
    fields: dict[str, dict[str, Any]],
    key: str,
    value: Any,
    status: str,
    confidence: str,
    evidence_items: list[dict[str, str]] | None = None,
) -> None:
    if value in (None, "", [], {}):
        return
    if key == "flag_value" and is_placeholder_flag(str(value)):
        return
    current = fields.get(key)
    status_rank = {"placeholder": 0, "inferred": 1, "explicit": 2, "structured": 3}
    confidence_rank = {"low": 0, "medium": 1, "high": 2}
    candidate_rank = (status_rank.get(status, 0), confidence_rank.get(confidence, 0))
    current_rank = (-1, -1)
    if current is not None:
        current_rank = (
            status_rank.get(str(current.get("status", "placeholder")), 0),
            confidence_rank.get(str(current.get("confidence", "low")), 0),
        )
    if current is None or candidate_rank > current_rank:
        fields[key] = make_field(value, status, confidence, evidence_items)
    elif current is not None and evidence_items:
        seen = {(item.get("path"), item.get("reason")) for item in current.get("evidence", [])}
        for item in evidence_items:
            marker = (item.get("path"), item.get("reason"))
            if marker not in seen:
                current.setdefault("evidence", []).append(item)


def is_text_candidate(path: Path) -> bool:
    lowered = path.name.lower()
    return lowered in PREFERRED_FILES or lowered == "dockerfile" or path.suffix.lower() in TEXT_EXTENSIONS


def file_priority(path: Path) -> int:
    name = path.name.lower()
    if name in {"meta.yaml", "meta.yml", "challenge.yaml", "challenge.yml", "hub_fields.json", "xlsx_fields.json"}:
        return 120
    if name in {"dockerfile", "start.sh", "changeflag.sh", "check.sh"}:
        return 110
    if "writeup" in name or name.startswith("wp"):
        return 100
    if "手册" in path.name or "题目" in path.name:
        return 90
    if name.startswith("readme"):
        return 80
    if name.startswith("skill"):
        return 10
    return 50


def collect_files(project_dir: Path, extra_paths: Iterable[Path]) -> list[Path]:
    files: list[Path] = []
    project_root = project_dir.resolve()
    for current_root, dirs, filenames in os.walk(project_dir):
        root_path = Path(current_root)
        try:
            depth = len(root_path.relative_to(project_dir).parts)
        except ValueError:
            depth = 0
        dirs[:] = [item for item in dirs if item not in EXCLUDED_DIRS and not item.startswith(".")]
        if depth > MAX_DEPTH:
            dirs[:] = []
            continue
        for filename in filenames:
            path = root_path / filename
            if filename in GENERATED_OUTPUTS or filename.startswith(".") or filename.endswith(GENERATED_SUFFIXES):
                continue
            try:
                if path.stat().st_size > 512 * 1024:
                    continue
            except OSError:
                continue
            if is_text_candidate(path):
                files.append(path)
    for extra in extra_paths:
        extra = extra.resolve()
        if extra == project_root:
            continue
        if not extra.exists():
            continue
        try:
            extra.relative_to(project_root)
            inside_project = True
        except ValueError:
            inside_project = False
        if extra.is_file() and is_text_candidate(extra):
            files.append(extra)
            continue
        if extra.is_dir():
            for current_root, dirs, filenames in os.walk(extra):
                root_path = Path(current_root)
                if not inside_project:
                    try:
                        depth = len(root_path.relative_to(extra).parts)
                    except ValueError:
                        depth = 0
                    if depth > MAX_DEPTH:
                        dirs[:] = []
                        continue
                dirs[:] = [item for item in dirs if item not in EXCLUDED_DIRS and not item.startswith(".")]
                for filename in filenames:
                    path = root_path / filename
                    if filename in GENERATED_OUTPUTS or filename.startswith(".") or filename.endswith(GENERATED_SUFFIXES):
                        continue
                    try:
                        if path.stat().st_size > 512 * 1024:
                            continue
                    except OSError:
                        continue
                    if is_text_candidate(path):
                        files.append(path)
    deduped: list[Path] = []
    seen: set[Path] = set()
    for path in sorted(files, key=lambda item: (-file_priority(item), str(item))):
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(path)
    return deduped


def nested_get(data: dict[str, Any], *keys: str) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def markdown_block(text: str, heading: str) -> str:
    pattern = re.compile(rf"^#+\s+.*?{re.escape(heading)}.*?$\n(?P<body>.*?)(?=^#+\s|\Z)", re.MULTILINE | re.DOTALL)
    match = pattern.search(text)
    return match.group("body") if match else ""


def clean_lines(lines: list[str]) -> list[str]:
    skip_markers = [
        "修改为自己",
        "[Detailed",
        "[Numbered list",
        "[Strictly use",
        "[Content]",
        "[Description]",
        "HUB 录题字段候选",
    ]
    cleaned: list[str] = []
    for line in lines:
        normalized = sanitize_text(line)
        if not normalized or normalized.startswith("```"):
            continue
        if any(marker in normalized for marker in skip_markers):
            continue
        cleaned.append(normalized)
    return cleaned


def extract_section_list(text: str, heading: str) -> list[str]:
    block = markdown_block(text, heading)
    if not block:
        return []
    return clean_lines(re.split(r"\n+|(?<=。)", block))


def extract_heading_text(text: str, heading: str) -> str:
    items = extract_section_list(text, heading)
    return sanitize_text(" ".join(items)) if items else ""


def extract_first_title(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return sanitize_text(line[2:])
    return ""


def extract_first_paragraph(text: str) -> str:
    paragraphs: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("```"):
            continue
        if not stripped:
            if current:
                paragraphs.append(sanitize_text(" ".join(current)))
                current = []
            continue
        current.append(stripped)
    if current:
        paragraphs.append(sanitize_text(" ".join(current)))
    for paragraph in paragraphs:
        if len(paragraph) >= 10:
            return paragraph
    return ""


def search_flag_literal(text: str) -> str:
    patterns = [r"\b[A-Za-z0-9_]*(?:flag|ctf)\{[^\n\r\t}]{1,200}\}"]
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            value = match.group(0)
            if not is_placeholder_flag(value):
                return value
    return ""


def is_placeholder_flag(value: str) -> bool:
    text = str(value or "").strip()
    lower_text = text.lower()
    if any(token in lower_text for token in ["dynamic_flag_placeholder", "placeholder_flag", "test_flag", "dummy_flag"]):
        return True
    match = re.match(r"^[A-Za-z0-9_]*(?:flag|ctf)\{(.+)\}$", text, re.IGNORECASE)
    if not match:
        return False
    body = match.group(1).strip().lower()
    normalized = re.sub(r"[^a-z0-9]+", "", body)
    placeholder_values = {
        "demo",
        "test",
        "example",
        "placeholder",
        "dummy",
        "fake",
        "flag",
        "changeme",
        "yourflag",
        "thisisatestflag",
        "pleasechangeme",
        "dynamicflagplaceholder",
        "dynamicplaceholder",
        "placeholderdynamicflag",
        "testflag",
        "testingflag",
    }
    if normalized in placeholder_values:
        return True
    return normalized.startswith(("demo", "test", "example", "placeholder", "dummy", "fake"))


def extract_ports_from_text(text: str) -> list[str]:
    results: list[str] = []
    patterns = [
        r"\bEXPOSE\s+(\d{2,5})\b",
        r"-p\s*(\d{2,5}):(\d{2,5})",
        r"listen\s+(\d{2,5})",
        r"port\s*[=:]\s*(\d{2,5})",
        r"0\.0\.0\.0:(\d{2,5})",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            groups = [group for group in match.groups() if group]
            for group in groups:
                if group not in results:
                    results.append(group)
    return results[:8]


def normalize_difficulty(value: str) -> str:
    raw = sanitize_text(value)
    if raw in DIFFICULTY_ALIASES:
        return str(DIFFICULTY_ALIASES[raw])
    lowered = raw.lower()
    if lowered in DIFFICULTY_ALIASES:
        return str(DIFFICULTY_ALIASES[lowered])
    stars = raw.count("★")
    if stars <= 2 and stars > 0:
        return "简单"
    if stars == 3:
        return "中等"
    if stars >= 4:
        return "困难"
    return ""


def normalize_difficulty_level(value: Any) -> str:
    raw = sanitize_text(str(value))
    match = re.search(r"\b(10|[1-9])\b", raw)
    return match.group(1) if match else ""


def normalize_flag_type(value: Any) -> str:
    raw = sanitize_text(str(value or "")).lower()
    if not raw:
        return ""
    if raw in {"静态flag", "静态", "static", "staticflag", "fixed", "固定flag", "固定"}:
        return "静态Flag"
    if raw in {"动态flag", "动态", "dynamic", "dynamicflag", "changeflag", "runtime"}:
        return "动态Flag"
    if "dynamic" in raw or "动态" in raw or "changeflag" in raw:
        return "动态Flag"
    if "static" in raw or "静态" in raw or "固定" in raw:
        return "静态Flag"
    return ""


def infer_difficulty_from_text(texts: list[str]) -> tuple[str, list[dict[str, str]], str]:
    for level, keywords in DIFFICULTY_KEYWORDS.items():
        for text in texts:
            lowered = text.lower()
            for keyword in keywords:
                if str(keyword).lower() in lowered:
                    return str(level), [evidence("text-scan", f"difficulty keyword: {keyword}")], "medium"
    return "", [], "low"


def normalize_category(value: str) -> str:
    raw = sanitize_text(value).lower()
    for category, spec in CATEGORY_RULES.items():
        aliases = [str(item).lower() for item in spec.get("aliases", [])]
        if raw == str(category).lower() or raw in aliases:
            return str(category)
    return ""


def infer_category_from_texts(texts: list[str]) -> tuple[str, list[dict[str, str]], str]:
    for category, spec in CATEGORY_RULES.items():
        aliases = [str(alias) for alias in spec.get("aliases", [])]
        for alias in aliases:
            alias_lower = alias.lower()
            for text in texts:
                if alias_lower in text.lower():
                    return str(category), [evidence("text-scan", f"category alias: {alias}")], "medium"
    return "", [], "low"


def describe_entry(name: str) -> str:
    lowered = name.lower()
    mapping = {
        "dockerfile": "容器构建文件",
        "start.sh": "服务启动脚本",
        "changeflag.sh": "动态 Flag 写入脚本",
        "check.sh": "题目连通性检查脚本",
        "challenge.yaml": "题目结构化配置",
        "challenge.yml": "题目结构化配置",
        "wp.md": "Writeup 或人工草稿",
        "writeup.md": "Writeup 或人工草稿",
        "readme.md": "说明文档",
    }
    if lowered in mapping:
        return mapping[lowered]
    if lowered.endswith((".php", ".py", ".js", ".ts", ".go", ".c", ".cpp", ".java", ".html")):
        return "题目源码或服务逻辑文件"
    if lowered.endswith((".txt", ".md", ".yaml", ".yml")):
        return "题目说明或配置文件"
    if lowered.endswith((".png", ".jpg", ".jpeg", ".gif", ".pcap", ".zip", ".tar", ".gz")):
        return "题目附件或分析材料"
    if lowered.endswith("/"):
        return "题目目录"
    return "题目相关文件"


def build_attachment_tree(project_dir: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for path in sorted(project_dir.iterdir(), key=lambda item: item.name.lower()):
        if path.name.startswith(".") or path.name in EXCLUDED_DIRS or path.name in GENERATED_OUTPUTS or path.name.endswith(GENERATED_SUFFIXES):
            continue
        node: dict[str, Any] = {
            "path": path.name + ("/" if path.is_dir() else ""),
            "description": describe_entry(path.name + ("/" if path.is_dir() else "")),
            "children": [],
        }
        if path.is_dir():
            child_count = 0
            for child in sorted(path.iterdir(), key=lambda item: item.name.lower()):
                if child.name.startswith(".") or child.name in EXCLUDED_DIRS:
                    continue
                node["children"].append(
                    {
                        "path": f"{path.name}/{child.name}" + ("/" if child.is_dir() else ""),
                        "description": describe_entry(child.name + ("/" if child.is_dir() else "")),
                    }
                )
                child_count += 1
                if child_count >= 6:
                    break
        items.append(node)
    return items


def infer_from_yaml(data: dict[str, Any], rel_path: str) -> dict[str, dict[str, Any]]:
    challenge = nested_get(data, "challenge") if isinstance(data, dict) else None
    target = challenge if isinstance(challenge, dict) else data
    out: dict[str, dict[str, Any]] = {}

    name = target.get("name") if isinstance(target, dict) else None
    if isinstance(name, str) and name.strip():
        out["title"] = make_field(name.strip(), "structured", "high", [evidence(rel_path, "challenge.name")])

    description = target.get("description") if isinstance(target, dict) else None
    if isinstance(description, str) and description.strip():
        out["description"] = make_field(description.strip(), "structured", "high", [evidence(rel_path, "challenge.description")])

    stack = target.get("stack") if isinstance(target, dict) else None
    category_text = target.get("category") if isinstance(target, dict) else None
    category_source = "challenge.category"
    if not isinstance(category_text, str) or not category_text.strip():
        category_text = stack
        category_source = "challenge.stack"
    if isinstance(category_text, str):
        category = normalize_category(category_text)
        if category:
            out["category"] = make_field(category, "structured", "high", [evidence(rel_path, category_source)])

    expose_ports = target.get("expose_ports") if isinstance(target, dict) else None
    if isinstance(expose_ports, list) and expose_ports:
        out["ports"] = make_field([str(item) for item in expose_ports], "structured", "high", [evidence(rel_path, "challenge.expose_ports")])

    difficulty = target.get("difficulty") if isinstance(target, dict) else None
    if isinstance(difficulty, str):
        normalized = normalize_difficulty(difficulty)
        if normalized:
            out["difficulty"] = make_field(normalized, "structured", "high", [evidence(rel_path, "challenge.difficulty")])
        level = normalize_difficulty_level(difficulty)
        if level:
            out["difficulty_level"] = make_field(level, "structured", "high", [evidence(rel_path, "challenge.difficulty")])

    for level_key in ["difficulty_level", "difficulty_level_10", "level"]:
        level_value = target.get(level_key) if isinstance(target, dict) else None
        level = normalize_difficulty_level(level_value)
        if level:
            out["difficulty_level"] = make_field(level, "structured", "high", [evidence(rel_path, f"challenge.{level_key}")])
            break

    flag_path = nested_get(target, "flag", "path")
    if isinstance(flag_path, str) and flag_path:
        out["flag_path"] = make_field(flag_path, "structured", "high", [evidence(rel_path, "challenge.flag.path")])

    flag_value = target.get("flag") if isinstance(target, dict) else None
    if isinstance(flag_value, str) and flag_value.strip() and not is_placeholder_flag(flag_value.strip()):
        out["flag_value"] = make_field(flag_value.strip(), "structured", "high", [evidence(rel_path, "challenge.flag")])

    flag_type = target.get("flag_type") if isinstance(target, dict) else None
    if not isinstance(flag_type, str) or not flag_type.strip():
        nested_flag_type = nested_get(target, "flag", "type")
        flag_type = nested_flag_type if isinstance(nested_flag_type, str) else ""
    normalized_flag_type = normalize_flag_type(flag_type)
    if normalized_flag_type:
        out["flag_type"] = make_field(normalized_flag_type, "structured", "high", [evidence(rel_path, "challenge.flag_type")])

    permission = nested_get(target, "flag", "permission")
    if permission is not None:
        out["flag_permission"] = make_field(str(permission), "structured", "high", [evidence(rel_path, "challenge.flag.permission")])

    entrypoint = nested_get(target, "platform", "entrypoint")
    if isinstance(entrypoint, str) and entrypoint:
        out["entrypoint"] = make_field(entrypoint, "structured", "high", [evidence(rel_path, "challenge.platform.entrypoint")])

    start_cmd = nested_get(target, "start", "cmd")
    if isinstance(start_cmd, str) and start_cmd:
        out["start_cmd"] = make_field(start_cmd, "structured", "high", [evidence(rel_path, "challenge.start.cmd")])

    source = target.get("source") if isinstance(target, dict) else None
    if isinstance(source, str):
        normalized_source = "原创" if "原创" in source else "搬运" if "搬运" in source else ""
        if normalized_source:
            out["source"] = make_field(normalized_source, "structured", "high", [evidence(rel_path, "challenge.source")])

    score = target.get("score") if isinstance(target, dict) else None
    if score is not None and str(score).strip():
        out["score"] = make_field(str(score).strip(), "structured", "high", [evidence(rel_path, "challenge.score")])

    return out


def infer_from_structured_json(data: dict[str, Any], rel_path: str) -> dict[str, dict[str, Any]]:
    source = data.get("hub_fields") if isinstance(data.get("hub_fields"), dict) else data
    if isinstance(source.get("xlsx_fields"), dict):
        source = source["xlsx_fields"]
    out: dict[str, dict[str, Any]] = {}

    def first_value(*keys: str) -> Any:
        for key in keys:
            value = source.get(key) if isinstance(source, dict) else None
            if value not in (None, "", [], {}):
                return value
        return None

    def add_text(field: str, reason: str, *keys: str) -> None:
        value = first_value(*keys)
        if isinstance(value, list):
            cleaned = [str(item).strip() for item in value if str(item).strip()]
            if cleaned:
                out[field] = make_field(cleaned, "structured", "high", [evidence(rel_path, reason)])
            return
        if value is not None and str(value).strip():
            out[field] = make_field(str(value).strip(), "structured", "high", [evidence(rel_path, reason)])

    add_text("title", "structured title", "题目标题", "名称", "title", "challenge_name", "name")
    add_text("description", "structured description", "题目内容", "description", "desc")
    add_text("score", "structured score", "题目分值", "分值", "score")
    add_text("source", "structured source", "题目来源", "来源", "source")
    add_text("question_type", "structured question type", "题目类型", "question_type")
    add_text("resource_level", "structured resource level", "资源等级", "resource_level")
    add_text("note", "structured note", "备注", "note")
    add_text("keywords", "structured keywords", "添加关键字", "关键字", "keywords")
    add_text("tools", "structured tools", "解题工具", "tools")

    category = first_value("题目分类", "分类", "category")
    normalized_category = normalize_category(str(category or ""))
    if normalized_category:
        out["category"] = make_field(normalized_category, "structured", "high", [evidence(rel_path, "structured category")])

    difficulty = first_value("题目难度", "难度", "difficulty")
    normalized_difficulty = normalize_difficulty(str(difficulty or ""))
    if normalized_difficulty:
        out["difficulty"] = make_field(normalized_difficulty, "structured", "high", [evidence(rel_path, "structured difficulty")])
    level = normalize_difficulty_level(first_value("题目等级", "难度编号", "星级", "difficulty_level"))
    if level:
        out["difficulty_level"] = make_field(level, "structured", "high", [evidence(rel_path, "structured difficulty level")])

    flag_type = str(first_value("Flag类型", "flag_type") or "").strip()
    if flag_type in ALLOWED_FLAG_TYPES:
        out["flag_type"] = make_field(flag_type, "structured", "high", [evidence(rel_path, "structured flag type")])
    flag_value = str(first_value("题目Flag", "Flag", "flag", "flag_value") or "").strip()
    if flag_value and not is_placeholder_flag(flag_value):
        out["flag_value"] = make_field(flag_value, "structured", "high", [evidence(rel_path, "structured flag")])

    ports = first_value("开放端口", "ports", "port", "expose_ports")
    port_values: list[str] = []
    if isinstance(ports, list):
        port_values = [str(item).strip() for item in ports if str(item).strip()]
    elif ports is not None and str(ports).strip():
        port_values = extract_ports_from_text(str(ports)) or [str(ports).strip()]
    if port_values:
        out["ports"] = make_field(port_values, "structured", "high", [evidence(rel_path, "structured ports")])

    return out


def parse_markdown_sources(markdown_files: list[Path], root: Path) -> dict[str, dict[str, Any]]:
    fields: dict[str, dict[str, Any]] = {}
    preferred = [path for path in markdown_files if not path.name.lower().startswith("skill")]
    if preferred:
        markdown_files = preferred

    for path in markdown_files:
        rel = relative_to(path, root)
        text = read_text(path)
        title = extract_first_title(text)
        if title and "title" not in fields:
            fields["title"] = make_field(title, "explicit", "high", [evidence(rel, "markdown title")])

        description = (
            extract_heading_text(text, "1.2 题目描述")
            or extract_heading_text(text, "2.2 题目内容")
            or extract_heading_text(text, "题目描述")
            or extract_first_paragraph(text)
        )
        if description and "description" not in fields:
            fields["description"] = make_field(description, "explicit", "high", [evidence(rel, "description section")])

        difficulty = extract_heading_text(text, "1.3 题目难度") or extract_heading_text(text, "题目难度")
        normalized_difficulty = normalize_difficulty(difficulty)
        if normalized_difficulty and "difficulty" not in fields:
            fields["difficulty"] = make_field(normalized_difficulty, "explicit", "high", [evidence(rel, "difficulty section")])
        difficulty_level = normalize_difficulty_level(difficulty)
        if difficulty_level and "difficulty_level" not in fields:
            fields["difficulty_level"] = make_field(difficulty_level, "explicit", "high", [evidence(rel, "difficulty section")])

        score = extract_heading_text(text, "2.7 题目分值") or extract_heading_text(text, "题目分值")
        score_match = re.search(r"\d+", score)
        if score_match and "score" not in fields:
            fields["score"] = make_field(score_match.group(0), "explicit", "high", [evidence(rel, "score section")])

        source = extract_heading_text(text, "2.5 题目来源")
        normalized_source = "原创" if "原创" in source else "搬运" if "搬运" in source else ""
        if normalized_source and "source" not in fields:
            fields["source"] = make_field(normalized_source, "explicit", "high", [evidence(rel, "source section")])

        category = extract_heading_text(text, "2.6 题目分类") or extract_heading_text(text, "题目分类")
        normalized_category = normalize_category(category)
        if normalized_category and "category" not in fields:
            fields["category"] = make_field(normalized_category, "explicit", "high", [evidence(rel, "category section")])

        flag_type = extract_heading_text(text, "2.3 Flag类型") or extract_heading_text(text, "Flag类型")
        if flag_type in ALLOWED_FLAG_TYPES and "flag_type" not in fields:
            fields["flag_type"] = make_field(flag_type, "explicit", "high", [evidence(rel, "flag type section")])

        goal = extract_heading_text(text, "题目目标")
        if goal and "goal" not in fields:
            fields["goal"] = make_field(goal, "explicit", "high", [evidence(rel, "goal section")])

        step_info = extract_heading_text(text, "第一步：题目信息")
        if step_info and "step_info" not in fields:
            fields["step_info"] = make_field(step_info, "explicit", "high", [evidence(rel, "step info section")])

        step_process = markdown_block(text, "解题步骤") or markdown_block(text, "题目解答")
        process_lines = [line for line in clean_lines(step_process.splitlines()) if len(line) >= 4]
        if process_lines and "step_process" not in fields:
            fields["step_process"] = make_field("\n".join(process_lines[:12]), "explicit", "high", [evidence(rel, "step process section")])

        flag_value = search_flag_literal(text)
        if flag_value and "flag_value" not in fields:
            fields["flag_value"] = make_field(flag_value, "explicit", "high", [evidence(rel, "flag literal in markdown")])

        for heading, key in [("前置知识", "prerequisites"), ("考察知识点", "knowledge_points"), ("解题工具", "tools")]:
            items = extract_section_list(text, heading)
            if items and key not in fields:
                fields[key] = make_field(items[:8], "explicit", "high", [evidence(rel, f"{heading} section")])

    return fields


def infer_source_from_generic_files(files: list[Path], root: Path) -> dict[str, dict[str, Any]]:
    fields: dict[str, dict[str, Any]] = {}
    for path in files:
        if path.suffix.lower() == ".md":
            continue
        text = read_text(path)
        rel = relative_to(path, root)

        if "description" not in fields and path.name.lower().startswith("readme"):
            paragraph = extract_first_paragraph(text)
            if paragraph:
                fields["description"] = make_field(paragraph, "inferred", "medium", [evidence(rel, "README first paragraph")])

        if "source" not in fields:
            if "原创" in text:
                fields["source"] = make_field("原创", "inferred", "medium", [evidence(rel, "text contains 原创")])
            elif "搬运" in text:
                fields["source"] = make_field("搬运", "inferred", "medium", [evidence(rel, "text contains 搬运")])

        if "score" not in fields:
            match = re.search(r"(?:分值|score)\s*[:：]?\s*(\d{1,4})", text, re.IGNORECASE)
            if match:
                fields["score"] = make_field(match.group(1), "inferred", "medium", [evidence(rel, "score pattern")])

        if "flag_value" not in fields:
            flag_value = search_flag_literal(text)
            if flag_value:
                fields["flag_value"] = make_field(flag_value, "explicit", "high", [evidence(rel, "flag literal in source")])

    return fields


def infer_entrypoint(start_script: Path | None, dockerfile: Path | None, project_dir: Path) -> tuple[str, list[dict[str, str]], str]:
    if start_script is not None:
        return "/start.sh", [evidence(relative_to(start_script, project_dir), "start.sh detected")], "high"
    if dockerfile is not None:
        docker_text = read_text(dockerfile)
        match = re.search(r"(?:ENTRYPOINT|CMD)\s*\[(.*?)\]", docker_text, re.IGNORECASE)
        if match:
            raw = sanitize_text(match.group(1).replace('"', "").replace("'", ""))
            return raw, [evidence(relative_to(dockerfile, project_dir), "Dockerfile entrypoint/cmd")], "medium"
        return "/start.sh", [evidence(relative_to(dockerfile, project_dir), "Dockerfile detected; default /start.sh")], "low"
    return "", [], "low"


def infer_context(project_dir: Path, extra_paths: list[Path]) -> dict[str, Any]:
    files = collect_files(project_dir, extra_paths)
    text_files = [path for path in files if is_text_candidate(path)]
    markdown_files = [
        path
        for path in files
        if path.suffix.lower() == ".md"
        and all(segment not in relative_to(path, project_dir) for segment in ("agents/", "references/", "assets/"))
    ]
    yaml_files = [path for path in files if path.name.lower() in {"meta.yaml", "meta.yml", "challenge.yaml", "challenge.yml"}]
    structured_json_files = [path for path in files if path.name.lower() in STRUCTURED_JSON_FILES]
    dockerfile = next((path for path in files if path.name.lower() == "dockerfile"), None)
    start_script = next((path for path in files if path.name.lower() == "start.sh"), None)
    changeflag_script = next((path for path in files if path.name.lower() == "changeflag.sh"), None)
    check_script = next((path for path in files if path.name.lower() == "check.sh" or "check/" in relative_to(path, project_dir)), None)

    fields: dict[str, dict[str, Any]] = {}

    for yaml_file in yaml_files:
        yaml_fields = infer_from_yaml(load_yaml_file(yaml_file), relative_to(yaml_file, project_dir))
        for key, value in yaml_fields.items():
            merge_field(fields, key, value["value"], value["status"], value["confidence"], value["evidence"])

    for json_file in structured_json_files:
        json_fields = infer_from_structured_json(load_json_file(json_file), relative_to(json_file, project_dir))
        for key, value in json_fields.items():
            merge_field(fields, key, value["value"], value["status"], value["confidence"], value["evidence"])

    for key, value in parse_markdown_sources(markdown_files, project_dir).items():
        merge_field(fields, key, value["value"], value["status"], value["confidence"], value["evidence"])

    generic_fields = infer_source_from_generic_files(text_files, project_dir)
    for key, value in generic_fields.items():
        merge_field(fields, key, value["value"], value["status"], value["confidence"], value["evidence"])

    text_blobs = [read_text(path) for path in text_files]
    combined_text = "\n".join(text_blobs)

    if "category" not in fields:
        category, evidence_items, confidence = infer_category_from_texts([combined_text] + [path.name for path in files])
        merge_field(fields, "category", category, "inferred", confidence, evidence_items)

    if "difficulty" not in fields:
        difficulty, evidence_items, confidence = infer_difficulty_from_text(text_blobs)
        merge_field(fields, "difficulty", difficulty, "inferred", confidence, evidence_items)

    if "ports" not in fields:
        ports: list[str] = []
        port_evidence: list[dict[str, str]] = []
        if dockerfile is not None:
            ports = extract_ports_from_text(read_text(dockerfile))
            if ports:
                port_evidence = [evidence(relative_to(dockerfile, project_dir), "Dockerfile port pattern")]
        if not ports and start_script is not None:
            ports = extract_ports_from_text(read_text(start_script))
            if ports:
                port_evidence = [evidence(relative_to(start_script, project_dir), "start.sh port pattern")]
        if not ports:
            ports = extract_ports_from_text(combined_text)
            if ports:
                port_evidence = [evidence("text-scan", "combined text port pattern")]
        merge_field(fields, "ports", ports, "inferred", "medium" if ports else "low", port_evidence)

    if "flag_value" not in fields:
        flag_value = search_flag_literal(combined_text)
        merge_field(
            fields,
            "flag_value",
            flag_value,
            "explicit",
            "high" if flag_value else "low",
            [evidence("text-scan", "flag literal search")] if flag_value else [],
        )

    if "flag_type" not in fields:
        combined_lower = combined_text.lower()
        if changeflag_script is not None or "dynamic flag" in combined_lower or "动态flag" in combined_lower or "changeflag" in combined_lower:
            merge_field(
                fields,
                "flag_type",
                "动态Flag",
                "inferred",
                "medium",
                [evidence(relative_to(changeflag_script, project_dir) if changeflag_script else "text-scan", "dynamic flag entry detected")],
            )
        elif fields.get("flag_value", {}).get("value"):
            merge_field(fields, "flag_type", "静态Flag", "inferred", "medium", [evidence("text-scan", "static flag literal found")])

    if "entrypoint" not in fields:
        entrypoint, entry_evidence, entry_confidence = infer_entrypoint(start_script, dockerfile, project_dir)
        merge_field(fields, "entrypoint", entrypoint, "inferred", entry_confidence, entry_evidence)

    if "flag_path" not in fields:
        merge_field(fields, "flag_path", "/flag", "inferred", "low", [evidence("default", "default flag path")])
    if "flag_permission" not in fields:
        merge_field(fields, "flag_permission", "400", "inferred", "low", [evidence("default", "default flag permission")])

    if "question_type" not in fields:
        question_type = "环境型" if any((yaml_files, dockerfile, start_script, check_script, fields.get("ports", {}).get("value"))) else "附件型"
        evidence_items = [evidence("artifact-scan", "build artifacts imply environment mode")] if question_type == "环境型" else [evidence("artifact-scan", "no deployment artifacts found")]
        merge_field(fields, "question_type", question_type, "inferred", "medium", evidence_items)

    if "resource_level" not in fields:
        resource_level = "8" if fields.get("question_type", {}).get("value") == "环境型" else "4"
        merge_field(fields, "resource_level", resource_level, "inferred", "medium", [evidence("derived", "question type to resource level")])

    if "step_info" not in fields:
        merge_field(fields, "step_info", MANUAL_DEFAULTS.get("step_info", "访问题目页面"), "inferred", "low", [evidence("data/template_defaults.yaml", "default step info")])

    category = fields.get("category", {}).get("value", "")
    category_spec = CATEGORY_RULES.get(category, {}) if isinstance(CATEGORY_RULES, dict) else {}
    goal_hint = str(category_spec.get("goal_hint", ""))
    step_outline = [str(item) for item in category_spec.get("step_outline", [])]
    merge_field(fields, "goal_hint", goal_hint, "inferred", "medium" if goal_hint else "low", [evidence("data/categories.yaml", f"goal hint for {category}")])
    merge_field(fields, "step_outline", step_outline, "inferred", "medium" if step_outline else "low", [evidence("data/categories.yaml", f"step outline for {category}")])

    if "goal" not in fields:
        merge_field(
            fields,
            "goal",
            goal_hint,
            "inferred",
            "medium" if goal_hint else "low",
            [evidence("data/categories.yaml", f"goal hint fallback for {category}")],
        )

    if "prerequisites" not in fields:
        prerequisites = [f"熟悉 {category} 题型常见分析方法"] if category else []
        merge_field(fields, "prerequisites", prerequisites, "inferred", "low" if prerequisites else "low", [evidence("derived", "category prerequisite fallback")])

    if "knowledge_points" not in fields:
        knowledge_points = [category, goal_hint] if category and goal_hint else ([category] if category else [])
        merge_field(fields, "knowledge_points", [item for item in knowledge_points if item], "inferred", "low", [evidence("derived", "category knowledge fallback")])

    if "tools" not in fields:
        default_tools = {
            "Web": ["浏览器", "抓包工具", "源码审计工具"],
            "Pwn": ["`checksec`", "`gdb` / `pwndbg`", "`pwntools`"],
            "Crypto": ["Python 3", "数学计算或密码学脚本"],
            "Misc": ["题目所需基础分析工具"],
            "Reverse": ["IDA / Ghidra", "调试器"],
            "Mobile": ["模拟器 / 真机", "静态分析与 Hook 工具"],
            "IoT": ["固件解包工具", "仿真或调试工具"],
        }
        merge_field(fields, "tools", default_tools.get(category, []), "inferred", "low", [evidence("derived", "category tool fallback")])

    ports = fields.get("ports", {}).get("value", []) or []
    main_port = ports[0] if ports else ""
    note_value = fields.get("note", {}).get("value", "")
    if not note_value:
        question_type = fields.get("question_type", {}).get("value", "")
        if question_type == "环境型" and main_port:
            note_value = str(DEFAULT_NOTES.get("environment", "")).format(entrypoint=fields.get("entrypoint", {}).get("value", "/start.sh"), port=main_port)
        elif question_type == "环境型":
            note_value = "环境型题目 / 请补充实际监听端口、启动方式与平台录入注意事项"
        elif question_type == "附件型":
            note_value = str(DEFAULT_NOTES.get("attachment", ""))
        merge_field(fields, "note", note_value, "inferred", "medium" if note_value else "low", [evidence("data/template_defaults.yaml", "default note template")])

    if "unexpected" not in fields:
        merge_field(fields, "unexpected", [MANUAL_DEFAULTS.get("unexpected_placeholder", "- [请补充非预期利用点、误报点或额外测试结论]")], "placeholder", "low", [evidence("data/template_defaults.yaml", "unexpected placeholder")])

    if "image_name" not in fields:
        title = fields.get("title", {}).get("value", "") or project_dir.name
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", title).strip("-").lower() or "ctf-challenge"
        merge_field(fields, "image_name", slug, "inferred", "low", [evidence("derived", "image name slug")])

    keywords = []
    for item in [fields.get("category", {}).get("value", ""), fields.get("difficulty", {}).get("value", ""), fields.get("flag_type", {}).get("value", "")]:
        if item and item not in keywords:
            keywords.append(item)
    merge_field(fields, "keywords", keywords, "inferred", "low", [evidence("derived", "keyword summary")])

    evidence_map = {key: value.get("evidence", []) for key, value in fields.items()}
    missing_field_specs = [
        ("title", "题目名称"),
        ("description", "题目描述"),
        ("source", "题目来源"),
        ("score", "题目分值"),
        ("flag_value", "题目Flag"),
    ]
    missing_fields = [label for key, label in missing_field_specs if not fields.get(key, {}).get("value")]

    build_artifact_items = [
        relative_to(yaml_files[0], project_dir) if yaml_files else "",
        relative_to(dockerfile, project_dir) if dockerfile else "",
        relative_to(start_script, project_dir) if start_script else "",
        relative_to(changeflag_script, project_dir) if changeflag_script else "",
        relative_to(check_script, project_dir) if check_script else "",
    ]
    build_artifact_items = [item for item in build_artifact_items if item]

    proposal = {
        "title_candidate": fields.get("title", make_field("", "placeholder", "low", [])),
        "category_candidate": fields.get("category", make_field("", "placeholder", "low", [])),
        "question_type": fields.get("question_type", make_field("", "placeholder", "low", [])),
        "flag_type": fields.get("flag_type", make_field("", "placeholder", "low", [])),
        "step_mode": make_field(
            "manual-only" if not fields.get("step_process", {}).get("value") else "mixed",
            "inferred",
            "medium",
            [evidence("derived", "step process presence")],
        ),
        "build_artifact_absorption": make_field(
            build_artifact_items,
            "explicit" if build_artifact_items else "placeholder",
            "high" if build_artifact_items else "low",
            [evidence("artifact-scan", "build artifact summary")],
        ),
        "missing_fields": missing_fields,
        "summary_lines": [
            f"题目名称候选：{fields.get('title', {}).get('value') or PLACEHOLDERS.get('title')}",
            f"题目分类候选：{fields.get('category', {}).get('value') or PLACEHOLDERS.get('category')}",
            f"题目类型判断：{fields.get('question_type', {}).get('value') or PLACEHOLDERS.get('question_type')}",
            f"Flag 类型判断：{fields.get('flag_type', {}).get('value') or PLACEHOLDERS.get('flag_type')}",
            f"仍需人工补写字段：{', '.join(missing_fields) if missing_fields else '无'}",
        ],
    }

    context = {
        "version": "v0.4.0",
        "project_dir": str(project_dir.resolve()),
        "scanned_files": [relative_to(path, project_dir) for path in files],
        "sources": {
            "challenge_yaml": relative_to(yaml_files[0], project_dir) if yaml_files else "",
            "dockerfile": relative_to(dockerfile, project_dir) if dockerfile else "",
            "start_script": relative_to(start_script, project_dir) if start_script else "",
            "changeflag_script": relative_to(changeflag_script, project_dir) if changeflag_script else "",
            "check_script": relative_to(check_script, project_dir) if check_script else "",
        },
        "fields": fields,
        "attachments": build_attachment_tree(project_dir),
        "proposal": proposal,
        "evidence": evidence_map,
        "inferred": {key: value.get("value") for key, value in fields.items()},
    }
    return context


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract structured context for writeup rendering.")
    parser.add_argument("paths", nargs="*", help="Optional explicit files or directories to include.")
    parser.add_argument("--project-dir", help="Project directory to inspect.")
    parser.add_argument("--output", help="Write JSON output to a file.")
    parser.add_argument("--pretty", action="store_true", help="Pretty print JSON.")
    parser.add_argument("--proposal-out", help="Optional markdown file for proposal summary.")
    return parser.parse_args()


def render_proposal_markdown(context: dict[str, Any]) -> str:
    proposal = context["proposal"]
    lines = [
        "# Writeup Proposal Summary",
        "",
        f"- 题目名称候选：{proposal['title_candidate'].get('value') or PLACEHOLDERS.get('title')}",
        f"- 分类候选：{proposal['category_candidate'].get('value') or PLACEHOLDERS.get('category')}",
        f"- 题目类型：{proposal['question_type'].get('value') or PLACEHOLDERS.get('question_type')}",
        f"- Flag 类型：{proposal['flag_type'].get('value') or PLACEHOLDERS.get('flag_type')}",
        f"- 解题步骤模式：{proposal['step_mode'].get('value')}",
        "",
        "## 构建产物吸收结果",
    ]
    artifacts = proposal["build_artifact_absorption"].get("value", [])
    if artifacts:
        lines.extend([f"- {item}" for item in artifacts])
    else:
        lines.append("- 无")
    lines.extend([
        "",
        "## 仍需人工补写字段",
    ])
    missing = proposal.get("missing_fields", [])
    if missing:
        lines.extend([f"- {item}" for item in missing])
    else:
        lines.append("- 无")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    positional_paths = [Path(item).resolve() for item in args.paths]
    if args.project_dir:
        project_dir = Path(args.project_dir).resolve()
        extra_paths = positional_paths
    elif positional_paths:
        first = positional_paths[0]
        project_dir = first if first.is_dir() else first.parent
        extra_paths = positional_paths[1:] if first.is_dir() else positional_paths
    else:
        project_dir = Path(".").resolve()
        extra_paths = []
    context = infer_context(project_dir, extra_paths)
    payload = json.dumps(context, ensure_ascii=False, indent=2 if args.pretty else None)
    if args.output:
        Path(args.output).write_text(payload + ("\n" if not payload.endswith("\n") else ""), encoding="utf-8")
    else:
        sys.stdout.write(payload)
        if not payload.endswith("\n"):
            sys.stdout.write("\n")
    if args.proposal_out:
        Path(args.proposal_out).write_text(render_proposal_markdown(context) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
