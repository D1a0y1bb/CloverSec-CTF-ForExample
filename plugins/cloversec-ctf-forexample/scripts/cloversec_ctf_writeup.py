#!/usr/bin/env python3
"""Writeup and Hub field helpers for CloverSec CTF workflows."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import cloversec_ctf_naming as naming


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


def difficulty_profile(value: Any) -> dict[str, str]:
    key = _difficulty_key(value)
    if key not in DIFFICULTY_LEVELS:
        raise ValueError(f"unsupported difficulty level: {value}")
    return dict(DIFFICULTY_LEVELS[key])


def build_hub_fields(case: dict[str, Any]) -> dict[str, dict[str, Any]]:
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    flag = case.get("flag") if isinstance(case.get("flag"), dict) else {}
    writeup = case.get("writeup") if isinstance(case.get("writeup"), dict) else {}
    difficulty = difficulty_profile(metadata.get("难度编号") or metadata.get("题目等级") or "1")
    title = _string(metadata.get("名称"))
    flag_value = _string(flag.get("value") or metadata.get("Flag"))
    flag_type = _hub_flag_type(metadata.get("Flag类型") or flag.get("type"))
    score = _string(metadata.get("分值") or "100")
    resource_level = _string(metadata.get("资源等级") or "4")
    challenge_type = _string(metadata.get("题目类型") or "未知")
    category = _string(metadata.get("分类"))
    source = _string(metadata.get("题目来源") or metadata.get("赛事来源"))
    description = _string(metadata.get("题目内容") or writeup.get("description"))
    remark = _string(metadata.get("备注") or _default_remark(case))
    keywords = _list_text(writeup.get("keywords"))

    hub_fields = {
        "题目标题": title,
        "题目内容": description,
        "Flag类型": flag_type,
        "题目Flag": flag_value,
        "题目来源": source,
        "题目分类": category,
        "题目分值": score,
        "题目等级": f"{difficulty['编号']}级",
        "题目难度": difficulty["题目难度"],
        "题目难度等级": difficulty["难度等级"],
        "题目类型": challenge_type,
        "资源等级": resource_level,
        "题目备注": remark,
        "添加关键字": keywords,
    }
    xlsx_fields = {
        "名称": title,
        "题目来源": source,
        "赛事来源": _string(metadata.get("赛事来源") or source),
        "分类": category,
        "题目类型": challenge_type,
        "Flag类型": flag_type,
        "Flag": flag_value,
        "难度编号": difficulty["编号"],
        "星级": difficulty["题目难度"],
        "分值": score,
        "资源等级": resource_level,
        "开放端口": _string(metadata.get("开放端口")),
        "解题工具": _string(metadata.get("解题工具") or ", ".join(_list_text(writeup.get("tools")))),
        "备注": remark,
        "手册状态": "正式",
    }
    return {"hub_fields": hub_fields, "xlsx_fields": xlsx_fields}


def render_manual(case: dict[str, Any], hub_fields: dict[str, Any]) -> str:
    writeup = case.get("writeup") if isinstance(case.get("writeup"), dict) else {}
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    name = _string(hub_fields.get("题目标题"))
    category = _string(hub_fields.get("题目分类") or metadata.get("分类"))
    difficulty = _string(hub_fields.get("题目难度") or metadata.get("星级"))
    difficulty_level = _string(hub_fields.get("题目难度等级") or hub_fields.get("题目等级"))
    score = _string(hub_fields.get("题目分值"))
    flag_value = _string(hub_fields.get("题目Flag"))
    flag_type = _string(hub_fields.get("Flag类型"))
    source = _string(hub_fields.get("题目来源") or metadata.get("题目来源") or metadata.get("赛事来源"))
    challenge_type = _string(hub_fields.get("题目类型") or metadata.get("题目类型"))
    resource_level = _string(hub_fields.get("资源等级") or metadata.get("资源等级"))
    remark = _string(hub_fields.get("题目备注") or metadata.get("备注"))
    description = _string(writeup.get("description") or hub_fields.get("题目内容") or "待人工确认：题目描述缺少可靠来源。")
    prerequisites = _list_text(writeup.get("prerequisites")) or ["待人工确认：需要根据题面和源码补充前置知识。"]
    knowledge = _list_text(writeup.get("knowledge_points")) or ["待人工确认：需要根据题面、源码或 WP 补充考察点。"]
    tools = _list_text(writeup.get("tools")) or _split_tools(metadata.get("解题工具")) or ["待人工确认：需要根据解题过程补充工具。"]
    steps = _list_text(writeup.get("step_process")) or _list_text(writeup.get("steps"))
    attachments = _manual_attachment_lines(case, writeup, metadata)
    docker_artifacts = case.get("docker_artifacts") if isinstance(case.get("docker_artifacts"), dict) else {}
    build_commands, tar_commands = _deploy_commands(case, docker_artifacts)
    unexpected = _list_text(writeup.get("unexpected_tests")) or ["已按现有资料检查常规解法；非预期测试结果待人工复核。"]
    keywords = _list_text(hub_fields.get("添加关键字"))
    target = _string(writeup.get("goal") or "获取题目 Flag，并与内部归档表中的完整 Flag 保持一致。")
    step_lines = _solve_step_lines(steps)

    lines = [
        "## 1 题目设计部署信息",
        "",
        "### 1.1 题目名称",
        name,
        "",
        "### 1.2 题目描述",
        description,
        "",
        "### 1.3 题目难度",
        difficulty or difficulty_level or "待人工确认",
        "",
        "### 1.4 考察信息",
        *_plus_list(knowledge),
        "",
        "### 1.5 旗帜信息",
        f"● Flag 类型：{flag_type or '待人工确认'}",
        f"● 原始静态 flag：`{flag_value or '待人工确认'}`",
        "● 动态 Flag 题以平台 `/flag` 和 `/changeflag.sh` 为准；静态 Flag 题以归档字段为准。",
        "",
        "### 1.6 附件情况",
        *_dot_list(attachments),
        "",
        "### 1.7 部署方式",
        "#### 1.7.1 Dockerfile 构建启动",
        _bash_block(build_commands),
        "",
        "#### 1.7.2 Tar 镜像包导入启动",
        _bash_block(tar_commands),
        "",
        "### 1.8 非预期测试",
        *_plus_list(unexpected),
        "",
        "## 2 HUB上传部分&题解信息",
        "",
        "### 2.1 题目标题",
        _plain_block([name]),
        "",
        "### 2.2 题目内容",
        _plain_block([description]),
        "",
        "### 2.3 Flag类型",
        _plain_block([flag_type or "待人工确认"]),
        "",
        "### 2.4 题目Flag",
        _plain_block([flag_value or "待人工确认"]),
        "",
        "### 2.5 题目来源",
        _plain_block([source or "待人工确认"]),
        "",
        "### 2.6 题目分类",
        _plain_block([category or "待人工确认"]),
        "",
        "### 2.7 题目分值",
        _plain_block([score or "待人工确认"]),
        "",
        "### 2.8 题目等级",
        _plain_block([_string(metadata.get("题目等级") or metadata.get("难度编号") or difficulty_level or difficulty or "待人工确认")]),
        "",
        "### 2.9 题目类型",
        _plain_block([challenge_type or "待人工确认"]),
        "",
        "### 2.10 资源等级",
        _plain_block([resource_level or "待人工确认"]),
        "",
        "### 2.11 题目备注",
        _plain_block([remark or "无"]),
        "",
        "---",
        "",
        "### 2.12 题目解答",
        "",
        "#### 题目描述",
        "##### 题目名称",
        name,
        "",
        "##### 题目难度",
        difficulty or difficulty_level or "待人工确认",
        "",
        "##### 题目分值",
        score or "待人工确认",
        "",
        description,
        "",
        "#### 前置知识",
        *_numbered(prerequisites),
        "",
        "#### 考察知识点",
        *_numbered(knowledge),
        "",
        "#### 解题工具",
        *_numbered(tools),
        "",
        "#### 题目目标",
        target,
        "",
        "#### 解题步骤",
        *step_lines,
        "",
        "#### Flag",
        flag_value or "待人工确认",
        "",
    ]
    if keywords:
        lines.extend(["### 2.13 添加关键字", "、".join(keywords), ""])
    return "\n".join(lines).rstrip() + "\n"


def validate_hub_fields(hub_fields: dict[str, Any]) -> list[str]:
    required = ["题目标题", "Flag类型", "题目Flag", "题目分类", "题目分值", "题目等级", "题目类型", "资源等级"]
    return [f"{field} is required" for field in required if not _string(hub_fields.get(field)).strip()]


def _manual_attachment_lines(case: dict[str, Any], writeup: dict[str, Any], metadata: dict[str, Any]) -> list[str]:
    values = _list_text(writeup.get("attachments")) or _list_text(metadata.get("附件说明"))
    for item in case.get("attachments", []) if isinstance(case.get("attachments"), list) else []:
        if isinstance(item, dict):
            path = _string(item.get("path") or item.get("local_path"))
            name = _string(item.get("name") or Path(path).name)
        else:
            path = _string(item)
            name = Path(path).name
        if name:
            values.append(f"{name}：{path or '路径待人工确认'}")
    return values or ["本题未声明附件；如后续补充附件，需要同步更新手册和归档表。"]


def _archive_screenshot_names(case: dict[str, Any]) -> list[str]:
    archive = case.get("archive") if isinstance(case.get("archive"), dict) else {}
    names: list[str] = []
    for item in archive.get("screenshots", []) if isinstance(archive.get("screenshots"), list) else []:
        if isinstance(item, dict):
            path = _string(item.get("path") or item.get("local_path"))
            name = _string(item.get("name") or Path(path).name)
        else:
            path = _string(item)
            name = Path(path).name
        if name:
            names.append(f"{name}：用于证明解题过程或运行状态。")
    return names


def _deploy_commands(case: dict[str, Any], docker_artifacts: dict[str, Any]) -> tuple[list[str], list[str]]:
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    title = naming.clean_name(metadata.get("名称") or metadata.get("题目名称") or "challenge").lower()
    image_name = _string(docker_artifacts.get("image_name") or f"cloversec/{title}:latest")
    tar_path = _string(docker_artifacts.get("tar_path") or f"{title}_latest.tar")
    ports = _list_text(docker_artifacts.get("ports")) or _split_tools(metadata.get("开放端口"))
    port_arg = f"-p {ports[0]}" if ports else "# 待人工确认端口映射"
    build_commands = [
        f"docker build --platform linux/amd64 -t {image_name} .",
        f"docker run --rm {port_arg} --name {title} {image_name}",
    ]
    tar_commands = [
        f"docker load -i {tar_path}",
        f"docker run --rm {port_arg} --name {title} {image_name}",
    ]
    question_type = _string(metadata.get("题目类型"))
    if "附件" in question_type or not docker_artifacts:
        return ["附件题不需要 Docker 构建，直接使用 `题目附件/` 中的原始附件。"], ["附件题不需要镜像包导入。"]
    return build_commands, tar_commands


def _solve_step_lines(steps: list[str]) -> list[str]:
    if not steps:
        return ["待人工确认：当前资料没有可验证的完整解题过程，不能编造步骤。"]
    return _numbered(steps)


def _command_output_lines(command_outputs: list[str], flag_value: str) -> list[str]:
    if command_outputs:
        return _numbered(command_outputs)
    if flag_value:
        return ["```text", flag_value, "```"]
    return ["待人工确认：缺少命令输出或运行截图。"]


def _bash_block(commands: list[str]) -> str:
    return "```bash\n" + "\n".join(commands) + "\n```"


def _plain_block(values: list[str]) -> str:
    return "```plain\n" + "\n".join(values) + "\n```"


def _difficulty_key(value: Any) -> str:
    text = _string(value).strip()
    if text.endswith("级"):
        text = text[:-1]
    return text


def _hub_flag_type(value: Any) -> str:
    text = _string(value).strip()
    if text in {"dynamic", "动态", "动态Flag"}:
        return "动态Flag"
    if text in {"static", "静态", "静态Flag"}:
        return "静态Flag"
    return text or "未知"


def _default_remark(case: dict[str, Any]) -> str:
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    challenge_type = _string(metadata.get("题目类型"))
    port = _string(metadata.get("开放端口"))
    if challenge_type == "环境型" and port:
        return f"web容器/默认start.sh启动/映射端口{port}"
    return ""


def _list_text(value: Any) -> list[str]:
    if isinstance(value, list):
        return [_string(item) for item in value if _string(item).strip()]
    if _string(value).strip():
        return [_string(value)]
    return []


def _split_tools(value: Any) -> list[str]:
    text = _string(value)
    if not text:
        return []
    return [item.strip() for item in text.replace("，", ",").split(",") if item.strip()]


def _numbered(values: list[str]) -> list[str]:
    return [f"{index}、{value}" for index, value in enumerate(values, start=1)]


def _plus_list(values: list[str]) -> list[str]:
    return [f"+ {value}" for value in values]


def _dot_list(values: list[str]) -> list[str]:
    return [f"● {value}" for value in values]


def _string(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF writeup and Hub field utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    render_parser = subparsers.add_parser("render", help="render hub fields and formal manual")
    render_parser.add_argument("case_json")
    render_parser.add_argument("--output-dir", required=True)

    args = parser.parse_args(argv)
    if args.command == "render":
        case = json.loads(Path(args.case_json).read_text(encoding="utf-8"))
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        fields = build_hub_fields(case)
        hub_fields = fields["hub_fields"]
        (output_dir / "hub_fields.json").write_text(
            json.dumps(hub_fields, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        (output_dir / "xlsx_fields.json").write_text(
            json.dumps(fields["xlsx_fields"], ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        formal_manual = render_manual(case, hub_fields)
        manual_name = naming.manual_filename(hub_fields)
        (output_dir / manual_name).write_text(formal_manual, encoding="utf-8")
        (output_dir / "题目解题手册.md").write_text(formal_manual, encoding="utf-8")
        print(f"wrote {output_dir}")
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
