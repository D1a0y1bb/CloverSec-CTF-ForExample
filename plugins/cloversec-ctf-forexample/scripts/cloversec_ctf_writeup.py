#!/usr/bin/env python3
"""Writeup and Hub field helpers for CloverSec CTF workflows."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


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
        "手册状态": "草稿",
    }
    return {"hub_fields": hub_fields, "xlsx_fields": xlsx_fields}


def render_manual(case: dict[str, Any], hub_fields: dict[str, Any], filled: bool = True) -> str:
    writeup = case.get("writeup") if isinstance(case.get("writeup"), dict) else {}
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    name = _string(hub_fields.get("题目标题"))
    difficulty = _string(hub_fields.get("题目难度"))
    score = _string(hub_fields.get("题目分值"))
    flag_value = _string(hub_fields.get("题目Flag"))
    prerequisites = _list_text(writeup.get("prerequisites")) or ["（待填写）"]
    knowledge = _list_text(writeup.get("knowledge_points")) or ["（待填写）"]
    tools = _list_text(writeup.get("tools")) or _split_tools(hub_fields.get("解题工具")) or ["（待填写）"]
    steps = _list_text(writeup.get("steps")) or ["（待填写题目信息）", "（待填写解题过程）"]
    command_outputs = _list_text(writeup.get("command_outputs")) or _list_text(writeup.get("commands")) or ["（待补充关键命令与输出）"]
    screenshots = _list_text(writeup.get("screenshots")) or ["（待补充截图文件名和说明）"]
    attachments = _list_text(writeup.get("attachments")) or _list_text(metadata.get("附件说明")) or ["（待说明附件名称、用途和校验方式）"]
    environment = _list_text(writeup.get("environment")) or [
        _string(metadata.get("开放端口") and f"开放端口：{metadata.get('开放端口')}") or "（待补充环境启动方式）"
    ]
    description = _string(writeup.get("description") or hub_fields.get("题目内容") or "（待填写）")
    if not filled:
        name = "（请输入题目名称）"
        difficulty = "（请输入题目难度）"
        score = "（请输入题目分值）"
        flag_value = "（请输入 Flag）"
        description = "（请输入题目描述）"

    lines = [
        f"# {name if filled else '题目解题手册'}",
        "",
        "## 题目说明",
        "",
        f"- 题目名称：{name}",
        f"- 题目分类：{_string(hub_fields.get('题目分类')) or '（待填写）'}",
        f"- 题目难度：{difficulty}",
        f"- 题目分值：{score}",
        "",
        description,
        "",
        "## 环境说明",
        "",
    ]
    lines.extend(_numbered(environment))
    lines.extend(["", "## 附件说明", ""])
    lines.extend(_numbered(attachments))
    lines.extend(["", "## 前置知识", ""])
    lines.extend(_numbered(prerequisites))
    lines.extend(["", "## 考察知识点", ""])
    lines.extend(_numbered(knowledge))
    lines.extend(["", "## 解题工具", ""])
    lines.extend(_numbered(tools))
    lines.extend(["", "## 解题步骤", ""])
    lines.extend(_numbered(steps))
    lines.extend(["", "## 命令输出", ""])
    lines.extend(_numbered(command_outputs))
    lines.extend(["", "## 截图说明", ""])
    lines.extend(_numbered(screenshots))
    lines.extend(
        [
            "",
            "## Flag",
            "",
            flag_value,
            "",
            "## 复现说明",
            "",
            "1、按环境说明准备题目资源。",
            "2、按解题步骤执行，核对命令输出和截图。",
            "3、最终得到的 Flag 需要与内部 xlsx 字段保持一致。",
            "",
        ]
    )
    return "\n".join(lines)


def render_manual_template(case: dict[str, Any], hub_fields: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# 题目解题手册",
            "",
            "## 题目说明",
            "",
            "- 题目名称：（待填写）",
            "- 题目分类：（待填写）",
            "- 题目难度：（待填写）",
            "- 题目分值：（待填写）",
            "",
            "（待填写题目内容）",
            "",
            "## 环境说明",
            "",
            "1、（待填写环境启动方式、端口、附件使用方式）",
            "",
            "## 附件说明",
            "",
            "1、（待填写附件名称、用途、hash 或来源说明）",
            "",
            "## 前置知识",
            "",
            "1、（待填写）",
            "",
            "## 考察知识点",
            "",
            "1、（待填写）",
            "",
            "## 解题工具",
            "",
            "1、（待填写）",
            "",
            "## 解题步骤",
            "",
            "1、（待填写完整步骤）",
            "",
            "## 命令输出",
            "",
            "1、（待填写关键命令和输出）",
            "",
            "## 截图说明",
            "",
            "1、（待填写截图文件名和说明）",
            "",
            "## Flag",
            "",
            "（待填写完整 Flag）",
            "",
            "## 复现说明",
            "",
            "1、（待填写复现检查结果）",
            "",
        ]
    )


def validate_hub_fields(hub_fields: dict[str, Any]) -> list[str]:
    required = ["题目标题", "Flag类型", "题目Flag", "题目分类", "题目分值", "题目等级", "题目类型", "资源等级"]
    return [f"{field} is required" for field in required if not _string(hub_fields.get(field)).strip()]


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


def _string(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF writeup and Hub field utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    render_parser = subparsers.add_parser("render", help="render hub fields and manual drafts")
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
        (output_dir / "manual_template.md").write_text(render_manual_template(case, hub_fields), encoding="utf-8")
        formal_manual = render_manual(case, hub_fields, filled=True)
        (output_dir / "manual_filled_draft.md").write_text(formal_manual, encoding="utf-8")
        (output_dir / "题目解题手册.md").write_text(formal_manual, encoding="utf-8")
        print(f"wrote {output_dir}")
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
