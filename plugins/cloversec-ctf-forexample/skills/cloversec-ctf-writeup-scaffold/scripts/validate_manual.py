#!/usr/bin/env python3
"""Validate generated manual markdown files."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ALLOWED_DIFFICULTIES = {"简单", "中等", "困难", "[简单/中等/困难]"}
ALLOWED_CATEGORIES = {"Web", "Pwn", "Crypto", "Misc", "Reverse", "Mobile", "IoT", "[Web/Pwn/Crypto/Misc/Reverse/Mobile/IoT]"}
ALLOWED_FLAG_TYPES = {"静态Flag", "动态Flag", "[静态Flag/动态Flag]"}
ALLOWED_SOURCES = {"原创", "搬运", "[原创/搬运]"}
ALLOWED_TYPES = {"环境型", "附件型", "[环境型/附件型]"}
ALLOWED_RESOURCE = {"8", "4", "[8/4]"}

REQUIRED_HEADINGS = [
    "## 1 题目设计部署信息",
    "### 1.1 题目名称",
    "### 1.2 题目描述",
    "### 1.3 题目难度",
    "### 1.4 考察信息",
    "### 1.5 旗帜信息",
    "### 1.6 附件情况",
    "### 1.7 部署方式",
    "#### 1.7.1 Dockerfile 构建启动",
    "#### 1.7.2 Tar 镜像包导入启动",
    "### 1.8 非预期测试",
    "## 2 HUB上传部分&题解信息",
    "### 2.1 题目标题",
    "### 2.2 题目内容",
    "### 2.3 Flag类型",
    "### 2.4 题目Flag",
    "### 2.5 题目来源",
    "### 2.6 题目分类",
    "### 2.7 题目分值",
    "### 2.8 题目等级",
    "### 2.9 题目类型",
    "### 2.10 资源等级",
    "### 2.11 题目备注",
    "### 2.12 题目解答",
    "### 2.13 添加关键字",
    "### 2.14 上传附件",
]
PLAIN_HEADINGS = [
    "### 2.1 题目标题",
    "### 2.2 题目内容",
    "### 2.3 Flag类型",
    "### 2.4 题目Flag",
    "### 2.5 题目来源",
    "### 2.6 题目分类",
    "### 2.7 题目分值",
    "### 2.8 题目等级",
    "### 2.9 题目类型",
    "### 2.10 资源等级",
    "### 2.11 题目备注",
]


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")


def extract_plain_block(text: str, heading: str) -> str:
    pattern = re.compile(rf"^{re.escape(heading)}\n```plain\n(?P<body>.*?)\n```", re.MULTILINE | re.DOTALL)
    match = pattern.search(text)
    return match.group("body").strip() if match else ""


def extract_section(text: str, heading: str, next_heading_pattern: str) -> str:
    pattern = re.compile(rf"^{re.escape(heading)}\n(?P<body>.*?)(?=^{next_heading_pattern}|\Z)", re.MULTILINE | re.DOTALL)
    match = pattern.search(text)
    return match.group("body") if match else ""


def validate_bullet_section(text: str, heading: str, next_heading_pattern: str, label: str, errors: list[str]) -> None:
    body = extract_section(text, heading, next_heading_pattern)
    if not body:
        errors.append(f"无法定位 `{label}` 内容区间")
        return
    bullet_lines = [line for line in body.splitlines() if line.strip()]
    for line in bullet_lines:
        stripped = line.lstrip()
        if not stripped.startswith(("●", "○")):
            errors.append(f"`{label}` 存在未使用 `●/○` 的条目")
            break


def validate_file(path: Path) -> list[str]:
    text = read_text(path)
    errors: list[str] = []

    for heading in REQUIRED_HEADINGS:
        if heading not in text:
            errors.append(f"缺少章节：{heading}")

    if "### 2.11 题目备注\n```plain" not in text or "---\n\n### 2.12 题目解答" not in text:
        errors.append("`2.11` 与 `2.12` 之间缺少强制分隔符或 plain 代码块结构异常")

    for heading in PLAIN_HEADINGS:
        if f"{heading}\n```plain" not in text:
            errors.append(f"章节未使用 plain 代码块：{heading}")

    difficulty = extract_plain_block(text, "### 2.8 题目等级")
    if difficulty and not ("★" in difficulty or difficulty.startswith("[")):
        errors.append("`2.8 题目等级` 应为星级展示或占位符")

    section_flag_type = extract_plain_block(text, "### 2.3 Flag类型")
    if section_flag_type and section_flag_type not in ALLOWED_FLAG_TYPES:
        errors.append("`2.3 Flag类型` 不在允许集合内")

    section_source = extract_plain_block(text, "### 2.5 题目来源")
    if section_source and section_source not in ALLOWED_SOURCES:
        errors.append("`2.5 题目来源` 不在允许集合内")

    section_category = extract_plain_block(text, "### 2.6 题目分类")
    if section_category and section_category not in ALLOWED_CATEGORIES:
        errors.append("`2.6 题目分类` 不在允许集合内")

    section_type = extract_plain_block(text, "### 2.9 题目类型")
    if section_type and section_type not in ALLOWED_TYPES:
        errors.append("`2.9 题目类型` 不在允许集合内")

    section_resource = extract_plain_block(text, "### 2.10 资源等级")
    if section_resource and section_resource not in ALLOWED_RESOURCE:
        errors.append("`2.10 资源等级` 不在允许集合内")

    difficulty_section = re.search(r"^### 1\.3 题目难度\n(?P<body>.+)$", text, re.MULTILINE)
    if difficulty_section:
        difficulty_text = difficulty_section.group("body").strip()
        if difficulty_text not in ALLOWED_DIFFICULTIES:
            errors.append("`1.3 题目难度` 不在允许集合内")

    validate_bullet_section(text, "### 1.6 附件情况", r"### 1\.7 ", "1.6 附件情况", errors)
    validate_bullet_section(text, "### 2.14 上传附件", r"\Z", "2.14 上传附件", errors)

    keyword_section = extract_section(text, "### 2.13 添加关键字", r"### 2\.14 ").strip()
    if not keyword_section:
        errors.append("`2.13 添加关键字` 不能为空")

    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate generated markdown manuals.")
    parser.add_argument("files", nargs="+", help="Markdown files to validate.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    overall_errors = False
    for item in args.files:
        path = Path(item)
        errors = validate_file(path)
        if errors:
            overall_errors = True
            print(f"[FAIL] {path}")
            for error in errors:
                print(f"  - {error}")
        else:
            print(f"[OK] {path}")
    return 1 if overall_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
