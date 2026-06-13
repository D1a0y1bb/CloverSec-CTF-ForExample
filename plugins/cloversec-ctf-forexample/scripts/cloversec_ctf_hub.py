#!/usr/bin/env python3
"""Hub submission package helpers for CloverSec CTF workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any


HUB_SITE_OBSERVATION = {
    "observed_at": "2026-06-13",
    "login": {
        "entry_url": "https://hub.yunyansec.com/#/resource/ctf",
        "unauthenticated_behavior": "CTF list API returns 403 and redirects to SSO login.",
        "sso_host": "sso.seclover.com",
        "requires": ["username", "password", "captcha"],
    },
    "routes": {
        "ctf_list": "https://hub.yunyansec.com/#/resource/ctf",
        "ctf_create": "https://hub.yunyansec.com/#/activity/submitctf/0/0/0",
    },
    "endpoints": {
        "list": "GET /ctf/",
        "classify": "GET /ctf/classify/?type=1",
        "create": "POST /ctf/add/",
        "upload_file": "POST /ctf/upload_file/",
        "upload_image": "POST /ctf/upload_image/",
        "template": "GET /media/resource/WPTemplate/ctf/template.json",
    },
    "upload_limits": {
        "attached": "ZIP/RAR, <=500M",
        "other_attached": "ZIP/RAR, <=500M",
    },
}


HUB_FORM_FIELDS = [
    {"hub_label": "题目标题", "payload_key": "name", "source_key": "题目标题", "selector": 'input[placeholder="请输入题目标题"]', "required": True},
    {"hub_label": "题目内容", "payload_key": "desc", "source_key": "题目内容", "selector": 'textarea[placeholder="请输入题目内容"]', "required": True},
    {"hub_label": "Flag类型", "payload_key": "flag_type", "source_key": "Flag类型", "selector": 'radio: 静态Flag / 动态Flag', "required": True},
    {"hub_label": "题目Flag", "payload_key": "flag", "source_key": "题目Flag", "selector": 'input[placeholder="请输入题目Flag"]', "required": True},
    {"hub_label": "题目来源", "payload_key": "source", "source_key": "题目来源", "selector": 'input[placeholder="请输入题目来源"]', "required": True},
    {"hub_label": "题目分类", "payload_key": "classify", "source_key": "题目分类", "selector": "Ant Select from /ctf/classify/?type=1", "required": True},
    {"hub_label": "题目分值", "payload_key": "score", "source_key": "题目分值", "selector": 'input[placeholder="请输入题目分值"]', "required": True},
    {"hub_label": "题目等级", "payload_key": "level", "source_key": "题目等级", "selector": "level selector", "required": True},
    {"hub_label": "题目类型", "payload_key": "test_type", "source_key": "题目类型", "selector": "radio: 环境型 / 附件型", "required": True},
    {"hub_label": "资源等级", "payload_key": "resource_level", "source_key": "资源等级", "selector": 'input[placeholder="请输入资源等级"]', "required": True},
    {"hub_label": "题目备注", "payload_key": "remark", "source_key": "题目备注", "selector": 'input[placeholder="请输入题目备注"]', "required": False},
    {"hub_label": "题目解答", "payload_key": "answer", "source_key": "manual_markdown", "selector": '[contenteditable="true"]', "required": True},
    {"hub_label": "关键字", "payload_key": "keyword", "source_key": "添加关键字", "selector": 'input[placeholder="题目关键字，回车添加关键字"]', "required": True},
    {"hub_label": "上传附件", "payload_key": "attached", "source_key": "upload_files", "selector": ".upload-file-one", "required": False},
    {"hub_label": "其他附件", "payload_key": "other_attached", "source_key": "upload_files", "selector": ".upload-file-two", "required": False},
]


def default_screenshot_plan() -> list[dict[str, str]]:
    return [
        {"filename": "01-challenge-page.png", "description": "题目页面或题目信息截图"},
        {"filename": "02-container-running.png", "description": "容器运行或服务访问截图"},
        {"filename": "03-solve-proof.png", "description": "解题验证截图"},
    ]


def create_submission_package(
    case: dict[str, Any],
    hub_fields: dict[str, Any],
    manual_markdown: str,
    output_dir: str | Path,
) -> dict[str, Any]:
    root = Path(output_dir)
    fields_dir = root / "fields"
    manual_dir = root / "manual"
    attachments_dir = root / "attachments"
    images_dir = root / "images"
    screenshots_dir = root / "screenshots"
    manifests_dir = root / "manifests"
    for directory in [fields_dir, manual_dir, attachments_dir, images_dir, screenshots_dir, manifests_dir]:
        directory.mkdir(parents=True, exist_ok=True)

    (fields_dir / "hub_fields.json").write_text(json.dumps(hub_fields, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (fields_dir / "hub_fields_preview.json").write_text(json.dumps(hub_fields, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (manual_dir / "manual_filled_draft.md").write_text(manual_markdown, encoding="utf-8")

    upload_files: list[dict[str, Any]] = []
    issues: list[str] = []
    for item in case.get("attachments", []) if isinstance(case.get("attachments"), list) else []:
        source = Path(item.get("path", ""))
        copied = _copy_file(source, attachments_dir / (item.get("name") or source.name), issues)
        if copied:
            upload_files.append(_file_record(copied, "attachment"))

    docker_artifacts = case.get("docker_artifacts") if isinstance(case.get("docker_artifacts"), dict) else {}
    tar_path = docker_artifacts.get("tar_path")
    if tar_path:
        source = Path(tar_path)
        copied = _copy_file(source, images_dir / source.name, issues)
        if copied:
            upload_files.append(_file_record(copied, "image_tar"))

    screenshot_records = []
    screenshot_sources = []
    archive = case.get("archive") if isinstance(case.get("archive"), dict) else {}
    if isinstance(archive.get("screenshots"), list):
        screenshot_sources = [Path(item) for item in archive["screenshots"]]
    for index, plan in enumerate(default_screenshot_plan()):
        record = dict(plan)
        if index < len(screenshot_sources):
            copied = _copy_file(screenshot_sources[index], screenshots_dir / plan["filename"], issues)
            if copied:
                record.update(_file_record(copied, "screenshot"))
        screenshot_records.append(record)

    manifest = {
        "case_id": case.get("case_id", ""),
        "hub_fields": hub_fields,
        "upload_files": upload_files,
        "screenshots": screenshot_records,
        "issues": issues,
        "summary": {
            "total_upload_files": len(upload_files),
            "screenshot_slots": len(screenshot_records),
            "issues": len(issues),
        },
    }
    (manifests_dir / "upload_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (root / "hub_submission_checklist.md").write_text(render_checklist(manifest), encoding="utf-8")
    return manifest


def render_checklist(manifest: dict[str, Any]) -> str:
    fields = manifest.get("hub_fields", {})
    lines = [
        "# Hub 提交核对清单",
        "",
        "## 表单字段",
        "",
        f"- 题目标题：{fields.get('题目标题', '')}",
        f"- 题目分类：{fields.get('题目分类', '')}",
        f"- Flag类型：{fields.get('Flag类型', '')}",
        f"- 题目类型：{fields.get('题目类型', '')}",
        f"- 题目等级：{fields.get('题目等级', '')}",
        "",
        "## 上传文件",
        "",
    ]
    upload_files = manifest.get("upload_files", [])
    if upload_files:
        for item in upload_files:
            lines.append(f"- {item['role']}：{item['relative_path']}，SHA256 `{item['sha256']}`")
    else:
        lines.append("- 暂无上传文件。")
    lines.extend(["", "## 截图", ""])
    for item in manifest.get("screenshots", []):
        lines.append(f"- {item['filename']}：{item['description']}")
    if manifest.get("issues"):
        lines.extend(["", "## 待处理问题", ""])
        lines.extend(f"- {issue}" for issue in manifest["issues"])
    return "\n".join(lines) + "\n"


def create_browser_assist_plan(
    manifest: dict[str, Any],
    *,
    hub_url: str = "https://hub.yunyansec.com/#/resource/ctf",
) -> dict[str, Any]:
    fields = manifest.get("hub_fields", {}) if isinstance(manifest.get("hub_fields"), dict) else {}
    upload_files = manifest.get("upload_files", []) if isinstance(manifest.get("upload_files"), list) else []
    screenshots = manifest.get("screenshots", []) if isinstance(manifest.get("screenshots"), list) else []
    form_payload = create_hub_form_payload(fields, manifest=manifest)
    return {
        "hub_url": hub_url,
        "mode": "browser-assisted",
        "site_observation": HUB_SITE_OBSERVATION,
        "form_fields": HUB_FORM_FIELDS,
        "form_payload": form_payload,
        "validation": validate_hub_form_payload(form_payload),
        "security_boundaries": [
            "只使用用户已经登录的浏览器会话。",
            "不读取或保存 Cookie、token、CSRF、localStorage、sessionStorage、密码或验证码。",
            "提交前必须让用户确认字段、上传文件和截图。",
            "默认不自动点击最终提交按钮。",
        ],
        "steps": [
            {"id": "open-hub", "action": "打开 Hub CTF 资源页面", "target": hub_url, "requires_user_confirmation": False},
            {"id": "verify-login", "action": "确认页面处于用户已登录状态", "target": "browser", "requires_user_confirmation": True},
            {"id": "open-create-form", "action": "打开新增 CTF 题目路由 #/activity/submitctf/0/0/0", "target": "browser", "requires_user_confirmation": False},
            {"id": "resolve-classify", "action": "从 /ctf/classify/?type=1 选择与题目分类匹配的分类项", "target": "form", "requires_user_confirmation": True},
            {"id": "fill-fields", "action": "按 form_payload 和 form_fields 填写表单字段", "target": "form", "requires_user_confirmation": False},
            {"id": "upload-files", "action": "上传附件、镜像 tar 和手册材料", "target": "upload", "requires_user_confirmation": True},
            {"id": "upload-screenshots", "action": "上传截图并核对截图用途", "target": "screenshots", "requires_user_confirmation": True},
            {"id": "pre-submit-review", "action": "生成提交前字段差异和缺失项", "target": "preview", "requires_user_confirmation": True},
            {"id": "manual-submit", "action": "用户确认后手动提交或明确授权自动提交", "target": "submit", "requires_user_confirmation": True},
        ],
        "field_count": len(fields),
        "upload_file_count": len(upload_files),
        "screenshot_count": len(screenshots),
        "fields": fields,
        "upload_files": upload_files,
        "screenshots": screenshots,
    }


def create_hub_form_payload(hub_fields: dict[str, Any], *, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    manifest = manifest or {}
    upload_files = manifest.get("upload_files", []) if isinstance(manifest.get("upload_files"), list) else []
    attached = next((item for item in upload_files if item.get("role") == "attachment"), {})
    image_tar = next((item for item in upload_files if item.get("role") == "image_tar"), {})
    answer = _string(hub_fields.get("题目解答") or hub_fields.get("manual_markdown") or "")
    payload = {
        "name": _string(hub_fields.get("题目标题")),
        "desc": _string(hub_fields.get("题目内容")),
        "flag": _string(hub_fields.get("题目Flag")),
        "source": _string(hub_fields.get("题目来源")),
        "classify": _string(hub_fields.get("题目分类")),
        "answer": answer,
        "keyword": _list_value(hub_fields.get("添加关键字")),
        "attached": _string(attached.get("relative_path")),
        "attached_name": Path(_string(attached.get("relative_path"))).name if attached else "",
        "other_attached": _string(image_tar.get("relative_path")),
        "other_attached_name": Path(_string(image_tar.get("relative_path"))).name if image_tar else "",
        "flag_type": _hub_flag_type(_string(hub_fields.get("Flag类型"))),
        "flag_script": _string(hub_fields.get("Flag脚本")),
        "test_type": _hub_test_type(_string(hub_fields.get("题目类型"))),
        "score": _string(hub_fields.get("题目分值")),
        "level": _hub_level(_string(hub_fields.get("题目等级"))),
        "remark": _string(hub_fields.get("题目备注")),
        "resource_level": _string(hub_fields.get("资源等级")),
    }
    return payload


def validate_hub_form_payload(payload: dict[str, Any]) -> dict[str, Any]:
    required = ["name", "desc", "flag", "source", "classify", "answer", "keyword", "flag_type", "test_type", "score", "level", "resource_level"]
    missing = []
    for key in required:
        value = payload.get(key)
        if isinstance(value, list):
            empty = len(value) == 0
        else:
            empty = not _string(value).strip()
        if empty:
            missing.append(key)
    return {
        "status": "ready" if not missing else "needs_input",
        "missing": missing,
        "notes": [
            "classify 在页面中需要匹配为分类 ID，不能只依赖中文分类文本。",
            "answer 需要写入富文本编辑器；Markdown 到 HTML 的转换由 Agent 在浏览器步骤执行或人工确认。",
            "attached/other_attached 需要先通过页面上传控件上传，返回 URL 后才能提交。",
        ],
    }


def render_browser_assist_plan(plan: dict[str, Any]) -> str:
    lines = [
        "# Hub 浏览器辅助填表方案",
        "",
        f"- Hub 页面：{plan.get('hub_url', '')}",
        f"- 新增题目路由：{plan.get('site_observation', {}).get('routes', {}).get('ctf_create', '')}",
        f"- 字段数：{plan.get('field_count', 0)}",
        f"- 上传文件数：{plan.get('upload_file_count', 0)}",
        f"- 截图数：{plan.get('screenshot_count', 0)}",
        f"- 表单状态：{plan.get('validation', {}).get('status', '')}",
        "",
        "## 安全边界",
        "",
    ]
    lines.extend(f"- {item}" for item in plan.get("security_boundaries", []))
    lines.extend(["", "## 步骤", ""])
    for step in plan.get("steps", []):
        confirm = "需要确认" if step.get("requires_user_confirmation") else "无需确认"
        lines.append(f"- {step.get('id', '')}：{step.get('action', '')}（{confirm}）")
    lines.extend(["", "## Hub 字段映射", ""])
    for field in plan.get("form_fields", []):
        required = "必填" if field.get("required") else "可选"
        lines.append(f"- {field.get('hub_label', '')} -> `{field.get('payload_key', '')}` / `{field.get('selector', '')}`（{required}）")
    if plan.get("validation", {}).get("missing"):
        lines.extend(["", "## 缺失字段", ""])
        lines.extend(f"- `{item}`" for item in plan["validation"]["missing"])
    lines.extend(["", "## 字段预览", ""])
    for key, value in plan.get("fields", {}).items():
        lines.append(f"- {key}：{value}")
    return "\n".join(lines) + "\n"


def _copy_file(source: Path, target: Path, issues: list[str]) -> Path | None:
    if not source.exists() or not source.is_file():
        issues.append(f"missing file: {source}")
        return None
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    return target


def _file_record(path: Path, role: str) -> dict[str, Any]:
    return {
        "role": role,
        "relative_path": path.parent.name + "/" + path.name,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hub_flag_type(value: str) -> int | str:
    if value in {"静态Flag", "静态", "static"}:
        return 1
    if value in {"动态Flag", "动态", "dynamic"}:
        return 2
    return value


def _hub_test_type(value: str) -> int | str:
    if value in {"环境型", "容器题", "container"}:
        return 1
    if value in {"附件型", "附件题", "attachment"}:
        return 2
    return value


def _hub_level(value: str) -> str:
    text = value.strip()
    return text[:-1] if text.endswith("级") else text


def _list_value(value: Any) -> list[str]:
    if isinstance(value, list):
        return [_string(item) for item in value if _string(item).strip()]
    if _string(value).strip():
        return [_string(value)]
    return []


def _string(value: Any) -> str:
    return "" if value is None else str(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF Hub submission package utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    package_parser = subparsers.add_parser("package", help="create Hub submission package")
    package_parser.add_argument("--case-json", required=True)
    package_parser.add_argument("--hub-fields", required=True)
    package_parser.add_argument("--manual", required=True)
    package_parser.add_argument("--output-dir", required=True)

    browser_parser = subparsers.add_parser("browser-plan", help="create Hub browser-assisted filling plan")
    browser_parser.add_argument("--manifest", required=True)
    browser_parser.add_argument("--output", required=True)
    browser_parser.add_argument("--report")
    browser_parser.add_argument("--hub-url", default="https://hub.yunyansec.com/#/resource/ctf")

    args = parser.parse_args(argv)
    if args.command == "package":
        case = json.loads(Path(args.case_json).read_text(encoding="utf-8"))
        fields = json.loads(Path(args.hub_fields).read_text(encoding="utf-8"))
        manual = Path(args.manual).read_text(encoding="utf-8")
        create_submission_package(case, fields, manual, args.output_dir)
        print(f"wrote {args.output_dir}")
        return 0
    if args.command == "browser-plan":
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        plan = create_browser_assist_plan(manifest, hub_url=args.hub_url)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        report = Path(args.report) if args.report else output.with_suffix(".md")
        report.write_text(render_browser_assist_plan(plan), encoding="utf-8")
        print(f"wrote {output}")
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
