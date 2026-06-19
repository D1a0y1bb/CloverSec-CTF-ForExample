#!/usr/bin/env python3
"""CloverSec CTF human-facing naming helpers."""

from __future__ import annotations

import re
from typing import Any


CONTAINER_CHALLENGE_SUBDIRS = ["题目源码", "题目镜像", "题目手册"]
ATTACHMENT_CHALLENGE_SUBDIRS = ["题目附件", "题目手册"]

CATEGORY_DISPLAY = {
    "web": "Web",
    "pwn": "Pwn",
    "reverse": "Reverse",
    "rev": "Reverse",
    "crypto": "Crypto",
    "misc": "Misc",
    "forensics": "Forensics",
    "forensic": "Forensics",
    "osint": "OSINT",
    "ai": "AI",
    "mobile": "Mobile",
    "iot": "IoT",
    "blockchain": "Blockchain",
}


def challenge_dir_name(metadata: dict[str, Any]) -> str:
    category = display_category(metadata.get("分类") or metadata.get("题目分类") or metadata.get("category"))
    title = clean_name(metadata.get("名称") or metadata.get("题目名称") or metadata.get("题目标题") or metadata.get("name") or "未命名题目")
    return f"{category}-{title}"


def manual_filename(fields: dict[str, Any]) -> str:
    category = display_category(fields.get("题目分类") or fields.get("分类") or fields.get("category")).upper()
    title = clean_name(fields.get("题目标题") or fields.get("名称") or fields.get("题目名称") or fields.get("name") or "未命名题目")
    return f"{category}-{title}.md"


def challenge_subdirs(question_type: str | dict[str, Any]) -> list[str]:
    if isinstance(question_type, dict):
        question_type = str(
            question_type.get("题目类型")
            or question_type.get("question_type")
            or question_type.get("resource_type")
            or question_type.get("project_type")
            or ""
        )
    text = str(question_type or "").lower()
    if any(token in text for token in ["附件", "attachment", "misc", "crypto", "forensics", "离线"]):
        return list(ATTACHMENT_CHALLENGE_SUBDIRS)
    return list(CONTAINER_CHALLENGE_SUBDIRS)


def display_category(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "Misc"
    normalized = text.strip().lower()
    return CATEGORY_DISPLAY.get(normalized, text[:1].upper() + text[1:])


def clean_name(value: Any) -> str:
    text = str(value or "").strip() or "未命名题目"
    text = re.sub(r'[\\/:*?"<>|]+', "-", text)
    text = re.sub(r"\s+", " ", text).strip(". ")
    return text[:80] or "未命名题目"
