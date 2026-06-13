#!/usr/bin/env python3
"""Render manual_template.md and manual_filled_draft.md from extracted context."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from extract_context import (
    ALLOWED_CATEGORIES,
    ALLOWED_DIFFICULTIES,
    ALLOWED_FLAG_TYPES,
    ALLOWED_RESOURCE_LEVELS,
    ALLOWED_SOURCES,
    ALLOWED_TYPES,
    PLACEHOLDERS,
    STARS_MAP,
    infer_context,
    render_proposal_markdown,
)

DIFFICULTY_LEVELS = {
    "1": {"编号": "1", "难度等级": "超简单（Basic）", "题目难度": "★", "描述": "签到，基础题目，1-5分钟左右"},
    "2": {"编号": "2", "难度等级": "简单（Easy）", "题目难度": "★", "描述": "单点漏洞、基础利用，5-10分钟左右"},
    "3": {"编号": "3", "难度等级": "中下（Easy-Medium）", "题目难度": "★★", "描述": "简单审计或调试分析、1-2步链"},
    "4": {"编号": "4", "难度等级": "中等偏下（Lower-Medium）", "题目难度": "★★★", "描述": "多步链但直观，涉及多个知识点"},
    "5": {"编号": "5", "难度等级": "中等（Medium）", "题目难度": "★★★", "描述": "2-3步链、常见防护"},
    "6": {"编号": "6", "难度等级": "中等偏上（Upper-Medium）", "题目难度": "★★★★", "描述": "较深利用链"},
    "7": {"编号": "7", "难度等级": "中上（Medium-Hard）", "题目难度": "★★★★", "描述": "高级技巧、复杂逻辑"},
    "8": {"编号": "8", "难度等级": "低难（Hard-Easy）", "题目难度": "★★★★", "描述": "高阶题较低档"},
    "9": {"编号": "9", "难度等级": "较难（Hard）", "题目难度": "★★★★★", "描述": "深度技术"},
    "10": {"编号": "10", "难度等级": "破天（Insane）", "题目难度": "★★★★★★", "描述": "压轴题"},
}

DIFFICULTY_TO_LEVEL = {
    "简单": "2",
    "中等": "5",
    "困难": "9",
}


def plain_block(value: str) -> str:
    return f"```plain\n{value}\n```"


def bash_block(lines: list[str]) -> str:
    return "```bash\n" + "\n".join(lines) + "\n```"


def value_of(context: dict[str, Any], key: str, default: Any = "") -> Any:
    field = context.get("fields", {}).get(key, {})
    value = field.get("value")
    if value in (None, "", [], {}):
        return default
    return value


def difficulty_profile(context: dict[str, Any]) -> dict[str, str] | None:
    level = str(value_of(context, "difficulty_level", "")).strip()
    if level.endswith("级"):
        level = level[:-1]
    if level not in DIFFICULTY_LEVELS:
        level = DIFFICULTY_TO_LEVEL.get(str(value_of(context, "difficulty", "")).strip(), "")
    if level not in DIFFICULTY_LEVELS:
        return None
    return dict(DIFFICULTY_LEVELS[level])


def choice_or_placeholder(value: str, allowed: list[str], placeholder_key: str) -> str:
    if value in allowed:
        return value
    return PLACEHOLDERS.get(placeholder_key, "")


def string_or_placeholder(value: str, placeholder_key: str) -> str:
    text = str(value).strip() if value is not None else ""
    return text if text else str(PLACEHOLDERS.get(placeholder_key, ""))


def normalize_list_item(item: str) -> str:
    text = str(item).strip()
    return text if not text else __import__("re").sub(r"^(?:[-*•●○]|\d+[、.．)])\s*", "", text).strip()


def markdown_list(items: list[str], fallback: str, ordered: bool = False) -> list[str]:
    cleaned = [normalize_list_item(str(item)) for item in items if str(item).strip()]
    if not cleaned:
        return [fallback]
    if ordered:
        return [f"{index}、{item}" for index, item in enumerate(cleaned, start=1)]
    return [f"- {item}" for item in cleaned]


def attachment_lines(items: list[dict[str, Any]]) -> list[str]:
    if not items:
        return ["● `[待补充附件目录]`（请结合实际题目目录补充）"]
    result: list[str] = []
    for item in items:
        result.append(f"● `{item['path']}`（{item['description']}）")
        for child in item.get("children", []):
            result.append(f"○ `{child['path']}`（{child['description']}）")
    return result


def generate_deploy_commands(context: dict[str, Any]) -> tuple[list[str], list[str]]:
    image_name = str(value_of(context, "image_name", "ctf-challenge"))
    entrypoint = str(value_of(context, "entrypoint", "/start.sh"))
    ports = value_of(context, "ports", []) or []
    port = str(ports[0]) if ports else "[端口]"
    build_commands = [
        f"docker build -t {image_name}:latest .",
        f"docker run -d -p {port}:{port} {image_name}:latest {entrypoint}",
    ]
    tar_commands = [
        f"docker load -i {image_name}.tar",
        f"docker run -d -p {port}:{port} {image_name}:latest {entrypoint}",
    ]
    return build_commands, tar_commands


def render_flag_section(context: dict[str, Any], template_mode: bool) -> list[str]:
    flag_type = str(value_of(context, "flag_type", ""))
    flag_value = str(value_of(context, "flag_value", ""))
    flag_path = str(value_of(context, "flag_path", "/flag"))
    flag_permission = str(value_of(context, "flag_permission", "400"))

    lines = [
        f"- Flag 类型：{choice_or_placeholder(flag_type, ALLOWED_FLAG_TYPES, 'flag_type')}",
        f"- 静态 Flag：`{flag_value}`" if flag_value else f"- 静态 Flag：{PLACEHOLDERS.get('flag_value')}",
        f"- 容器内 Flag 路径固定为 `{flag_path}`，权限建议为 `{flag_permission}`。",
        "- 若平台启用动态 Flag，请在容器启动阶段完成写入，并确保业务进程只能按预期路径读取。",
        "- 如存在 `changeflag.sh` 或平台注入逻辑，请在交付前复核动态 Flag 是否真正生效。",
    ]
    if template_mode and not flag_value:
        lines.append("- 模板版不补全未知 Flag，需由出题人根据实际题目补写。")
    return lines


def render_assessment_section(context: dict[str, Any], template_mode: bool) -> list[str]:
    category = str(value_of(context, "category", ""))
    goal = str(value_of(context, "goal", ""))
    goal_hint = str(value_of(context, "goal_hint", ""))
    knowledge_points = value_of(context, "knowledge_points", []) or []
    lines: list[str] = []
    if category:
        lines.append(f"- 题目分类候选：`{category}`")
    if goal:
        lines.append(f"- 题目目标：{goal}")
    elif goal_hint:
        lines.append(f"- 题目目标：{goal_hint}")
    if knowledge_points:
        lines.extend(markdown_list([str(item) for item in knowledge_points], "- [请补充考察知识点]"))
    elif template_mode:
        lines.append("- [请补充考察知识点]")
    return lines or ["- [请补充考察信息]"]


def render_unexpected_section(context: dict[str, Any]) -> list[str]:
    items = value_of(context, "unexpected", []) or []
    normalized = [str(item).strip() for item in items if str(item).strip()]
    return normalized or ["- [请补充非预期利用点、误报点或额外测试结论]"]


def render_keywords(context: dict[str, Any]) -> str:
    keywords = [str(item).strip() for item in (value_of(context, "keywords", []) or []) if str(item).strip()]
    return "、".join(keywords) if keywords else "[请补充关键字]"


def build_field_exports(context: dict[str, Any]) -> dict[str, dict[str, Any]]:
    title = string_or_placeholder(value_of(context, "title", ""), "title")
    description = string_or_placeholder(value_of(context, "description", ""), "description")
    category = choice_or_placeholder(str(value_of(context, "category", "")), ALLOWED_CATEGORIES, "category")
    flag_type = choice_or_placeholder(str(value_of(context, "flag_type", "")), ALLOWED_FLAG_TYPES, "flag_type")
    flag_value = string_or_placeholder(str(value_of(context, "flag_value", "")), "flag_value")
    source = choice_or_placeholder(str(value_of(context, "source", "")), ALLOWED_SOURCES, "source")
    score = string_or_placeholder(str(value_of(context, "score", "")), "score")
    question_type = choice_or_placeholder(str(value_of(context, "question_type", "")), ALLOWED_TYPES, "question_type")
    resource_level = choice_or_placeholder(str(value_of(context, "resource_level", "")), ALLOWED_RESOURCE_LEVELS, "resource_level")
    note = string_or_placeholder(str(value_of(context, "note", "")), "note")
    profile = difficulty_profile(context)
    tools = value_of(context, "tools", []) or []
    difficulty_no = profile["编号"] if profile else "[1-10]"
    difficulty_stars = profile["题目难度"] if profile else "[★]"
    difficulty_label = profile["难度等级"] if profile else "[难度等级待补充]"

    hub_fields = {
        "题目标题": title,
        "题目内容": description,
        "Flag类型": flag_type,
        "题目Flag": flag_value,
        "题目来源": source,
        "题目分类": category,
        "题目分值": score,
        "题目等级": f"{difficulty_no}级" if profile else "[1-10级]",
        "题目难度": difficulty_stars,
        "题目难度等级": difficulty_label,
        "题目类型": question_type,
        "资源等级": resource_level,
        "题目备注": note,
        "添加关键字": render_keywords(context),
    }
    xlsx_fields = {
        "名称": title,
        "赛事来源": source,
        "题目来源": source,
        "分类": category,
        "题目类型": question_type,
        "Flag类型": flag_type,
        "Flag": flag_value,
        "难度编号": difficulty_no,
        "星级": difficulty_stars,
        "分值": score,
        "资源等级": resource_level,
        "开放端口": ",".join(str(item) for item in (value_of(context, "ports", []) or [])),
        "解题工具": "、".join(str(item) for item in tools),
        "手册状态": "草稿",
        "备注": note,
    }
    return {"hub_fields": hub_fields, "xlsx_fields": xlsx_fields}


def render_upload_attachment_section(context: dict[str, Any]) -> list[str]:
    sources = context.get("sources", {})
    uploaded: list[str] = []
    for key in ["challenge_yaml", "dockerfile", "start_script", "changeflag_script", "check_script"]:
        value = str(sources.get(key, "")).strip()
        if value:
            uploaded.append(value)
    if not uploaded:
        return ["● `[待确认上传附件]`（请结合实际题目产物补充）"]
    result = [f"● `{path}`（建议随题目归档或作为平台附件上传）" for path in uploaded]
    return result


def render_writeup_section(context: dict[str, Any], template_mode: bool) -> list[str]:
    category = str(value_of(context, "category", ""))
    prerequisites = [str(item) for item in (value_of(context, "prerequisites", []) or [])]
    knowledge_points = [str(item) for item in (value_of(context, "knowledge_points", []) or [])]
    tools = [str(item) for item in (value_of(context, "tools", []) or [])]
    goal = str(value_of(context, "goal", ""))
    step_process = str(value_of(context, "step_process", ""))
    step_outline = [str(item) for item in (value_of(context, "step_outline", []) or [])]
    flag_value = str(value_of(context, "flag_value", ""))
    flag_type = str(value_of(context, "flag_type", ""))
    step_placeholder = "（请结合实际解题路径补写详细步骤，附关键代码、关键命令和截图说明）"

    lines = [
        "#### 2.12.1 前置知识",
        *markdown_list(prerequisites, "- [请补充前置知识]"),
        "",
        "#### 2.12.2 考察知识点",
        *markdown_list(knowledge_points or ([category] if category else []), "- [请补充考察知识点]"),
        "",
        "#### 2.12.3 解题工具",
        *markdown_list(tools, "- [请补充解题工具]"),
        "",
        "#### 2.12.4 题目目标",
        string_or_placeholder(goal, "goal"),
        "",
        "#### 2.12.5 解题步骤",
    ]

    if template_mode:
        if step_outline:
            lines.extend(markdown_list(step_outline, step_placeholder, ordered=True))
        else:
            lines.append(step_placeholder)
    elif step_process:
        process_lines = [line.strip() for line in step_process.splitlines() if line.strip()]
        lines.extend(markdown_list(process_lines, step_placeholder, ordered=True))
    elif step_outline:
        lines.extend(markdown_list(step_outline, step_placeholder, ordered=True))
        lines.append("补充说明：当前草稿只按题型给出最小引导，详细利用链仍需人工复核补写。")
    else:
        lines.append(step_placeholder)

    lines.extend([
        "",
        "#### 2.12.6 Flag",
        flag_value if flag_value else PLACEHOLDERS.get("flag_value", "[题目Flag待补充]"),
    ])
    if flag_type:
        lines.append(f"说明：当前判断为 `{flag_type}`。")
    return lines


def render_document(context: dict[str, Any], template_mode: bool) -> str:
    title = string_or_placeholder(value_of(context, "title", ""), "title")
    description = string_or_placeholder(value_of(context, "description", ""), "description")
    difficulty = choice_or_placeholder(str(value_of(context, "difficulty", "")), ALLOWED_DIFFICULTIES, "difficulty")
    category = choice_or_placeholder(str(value_of(context, "category", "")), ALLOWED_CATEGORIES, "category")
    flag_type = choice_or_placeholder(str(value_of(context, "flag_type", "")), ALLOWED_FLAG_TYPES, "flag_type")
    flag_value = string_or_placeholder(str(value_of(context, "flag_value", "")), "flag_value")
    source = choice_or_placeholder(str(value_of(context, "source", "")), ALLOWED_SOURCES, "source")
    score = string_or_placeholder(str(value_of(context, "score", "")), "score")
    question_type = choice_or_placeholder(str(value_of(context, "question_type", "")), ALLOWED_TYPES, "question_type")
    resource_level = choice_or_placeholder(str(value_of(context, "resource_level", "")), ALLOWED_RESOURCE_LEVELS, "resource_level")
    note = string_or_placeholder(str(value_of(context, "note", "")), "note")
    attachments = attachment_lines(context.get("attachments", []))
    build_commands, tar_commands = generate_deploy_commands(context)
    profile = difficulty_profile(context)
    difficulty_stars = f"{profile['编号']}级 {profile['题目难度']}" if profile else PLACEHOLDERS.get("difficulty", "[简单/中等/困难]")

    lines = [
        "## 1 题目设计部署信息",
        "",
        "### 1.1 题目名称",
        title,
        "",
        "### 1.2 题目描述",
        description,
        "",
        "### 1.3 题目难度",
        difficulty,
        "",
        "### 1.4 考察信息",
        *render_assessment_section(context, template_mode),
        "",
        "### 1.5 旗帜信息",
        *render_flag_section(context, template_mode),
        "",
        "### 1.6 附件情况",
        *attachments,
        "",
        "### 1.7 部署方式",
        "#### 1.7.1 Dockerfile 构建启动",
        bash_block(build_commands),
        "",
        "#### 1.7.2 Tar 镜像包导入启动",
        bash_block(tar_commands),
        "",
        "### 1.8 非预期测试",
        *render_unexpected_section(context),
        "",
        "## 2 HUB上传部分&题解信息",
        "",
        "### 2.1 题目标题",
        plain_block(title),
        "",
        "### 2.2 题目内容",
        plain_block(description),
        "",
        "### 2.3 Flag类型",
        plain_block(flag_type),
        "",
        "### 2.4 题目Flag",
        plain_block(flag_value),
        "",
        "### 2.5 题目来源",
        plain_block(source),
        "",
        "### 2.6 题目分类",
        plain_block(category),
        "",
        "### 2.7 题目分值",
        plain_block(score),
        "",
        "### 2.8 题目等级",
        plain_block(difficulty_stars),
        "",
        "### 2.9 题目类型",
        plain_block(question_type),
        "",
        "### 2.10 资源等级",
        plain_block(resource_level),
        "",
        "### 2.11 题目备注",
        plain_block(note),
        "",
        "---",
        "",
        "### 2.12 题目解答",
        *render_writeup_section(context, template_mode),
        "",
        "### 2.13 添加关键字",
        render_keywords(context),
        "",
        "### 2.14 上传附件",
        *render_upload_attachment_section(context),
    ]
    return "\n".join(lines).rstrip() + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render manual template and draft.")
    parser.add_argument("paths", nargs="*", help="Optional files or directories to include during inference.")
    parser.add_argument("--project-dir", default=".", help="Project directory to inspect.")
    parser.add_argument("--context", help="Optional JSON context file from extract_context.py.")
    parser.add_argument("--output-dir", default=".", help="Directory to write manual outputs.")
    parser.add_argument("--context-out", help="Optional path to write writeup_context.json.")
    parser.add_argument("--proposal-out", help="Optional path to write proposal markdown.")
    return parser.parse_args()


def load_context(args: argparse.Namespace) -> dict[str, Any]:
    if args.context:
        return json.loads(Path(args.context).read_text(encoding="utf-8"))
    project_dir = Path(args.project_dir).resolve()
    extra_paths = [Path(item).resolve() for item in args.paths]
    return infer_context(project_dir, extra_paths)


def main() -> int:
    args = parse_args()
    context = load_context(args)
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    (output_dir / "manual_template.md").write_text(render_document(context, template_mode=True), encoding="utf-8")
    (output_dir / "manual_filled_draft.md").write_text(render_document(context, template_mode=False), encoding="utf-8")
    field_exports = build_field_exports(context)
    (output_dir / "hub_fields.json").write_text(
        json.dumps(field_exports["hub_fields"], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (output_dir / "xlsx_fields.json").write_text(
        json.dumps(field_exports["xlsx_fields"], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    if args.context_out:
        Path(args.context_out).write_text(json.dumps(context, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.proposal_out:
        Path(args.proposal_out).write_text(render_proposal_markdown(context) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
