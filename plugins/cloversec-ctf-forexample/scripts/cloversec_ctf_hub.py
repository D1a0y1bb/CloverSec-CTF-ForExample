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


CLASSIFY_TEXT_KEYS = ["题目分类", "classify_label", "classify_name", "name", "label", "title"]
CLASSIFY_ID_KEYS = ["题目分类ID", "classify_id", "id", "value", "key"]


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
        "upload_results": [],
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
    classify_options: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    fields = manifest.get("hub_fields", {}) if isinstance(manifest.get("hub_fields"), dict) else {}
    upload_files = manifest.get("upload_files", []) if isinstance(manifest.get("upload_files"), list) else []
    screenshots = manifest.get("screenshots", []) if isinstance(manifest.get("screenshots"), list) else []
    form_payload = create_hub_form_payload(fields, manifest=manifest, classify_options=classify_options)
    validation = validate_hub_form_payload(form_payload, manifest=manifest)
    return {
        "hub_url": hub_url,
        "mode": "browser-assisted",
        "auto_submit": False,
        "stop_before_submit": True,
        "login_state_gate": {
            "required_before_fill": True,
            "must_check_before_open_create_form": True,
            "logged_in_evidence": [
                "Hub CTF list page is accessible without redirecting to login.",
                "Page header shows a logged-in user identity instead of login/register.",
                "Challenge classify options can be loaded or selected on the visible page.",
            ],
            "unauthenticated_indicators": [
                "登录/注册",
                "login or SSO redirect",
                "403 from CTF list API",
                "empty form that later redirects to login on submit",
            ],
            "on_unauthenticated": "stop_before_fill_and_wait_for_user_login",
        },
        "site_observation": HUB_SITE_OBSERVATION,
        "form_fields": HUB_FORM_FIELDS,
        "form_payload": form_payload,
        "validation": validation,
        "security_boundaries": [
            "只使用用户已经登录的浏览器会话。",
            "没有确认登录态前，不填写字段、不上传附件、不生成提交前状态。",
            "不读取或保存 Cookie、token、CSRF、localStorage、sessionStorage、密码或验证码。",
            "提交前必须让用户确认字段、上传文件和截图。",
            "不自动点击最终提交按钮。",
        ],
        "steps": [
            {"id": "open-hub", "action": "打开 Hub CTF 资源页面", "target": hub_url, "requires_user_confirmation": False},
            {"id": "verify-login", "action": "确认页面处于用户已登录状态；如仍显示登录/注册、SSO 或 403，停止等待用户登录，不填写表单", "target": "browser", "requires_user_confirmation": True},
            {"id": "open-create-form", "action": "仅在确认登录后打开新增 CTF 题目路由 #/activity/submitctf/0/0/0", "target": "browser", "requires_user_confirmation": False},
            {"id": "resolve-classify", "action": "从 /ctf/classify/?type=1 选择与题目分类匹配的分类项", "target": "form", "requires_user_confirmation": True},
            {"id": "fill-fields", "action": "按 form_payload 和 form_fields 填写表单字段", "target": "form", "requires_user_confirmation": False},
            {"id": "upload-files", "action": "上传附件、镜像 tar 和手册材料", "target": "upload", "requires_user_confirmation": True},
            {"id": "upload-screenshots", "action": "上传截图并核对截图用途", "target": "screenshots", "requires_user_confirmation": True},
            {"id": "pre-submit-review", "action": "生成提交前字段差异和缺失项", "target": "preview", "requires_user_confirmation": True},
            {"id": "manual-submit", "action": "停止在最终提交前，由用户检查后手动提交", "target": "submit", "requires_user_confirmation": True},
        ],
        "field_count": len(fields),
        "upload_file_count": len(upload_files),
        "screenshot_count": len(screenshots),
        "fields": fields,
        "upload_files": upload_files,
        "screenshots": screenshots,
        "upload_results": manifest.get("upload_results", []) if isinstance(manifest.get("upload_results"), list) else [],
    }


def create_chrome_assist_plan(
    manifest: dict[str, Any],
    *,
    hub_url: str = "https://hub.yunyansec.com/#/resource/ctf",
    classify_options: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    base_plan = create_browser_assist_plan(manifest, hub_url=hub_url, classify_options=classify_options)
    plan = dict(base_plan)
    plan.update(
        {
            "mode": "chrome-assisted",
            "requires_chrome_plugin": True,
            "auto_submit": False,
            "stop_before_submit": True,
            "chrome_execution_contract": {
                "browser": "Chrome plugin or Codex browser-control equivalent",
                "entry_url": hub_url,
                "create_url": HUB_SITE_OBSERVATION["routes"]["ctf_create"],
                "login_state_gate": plan.get("login_state_gate", {}),
                "file_upload_requirement": (
                    "Chrome extension file upload must be allowed; if setFiles returns Not allowed, enable "
                    '"Allow access to file URLs" for the Codex extension in chrome://extensions.'
                ),
                "allowed_actions": [
                    "open_page",
                    "wait_for_user_login",
                    "fill_visible_form_fields",
                    "select_visible_classify_option",
                    "set_visible_file_inputs",
                    "record_visible_upload_results",
                    "take_pre_submit_screenshot",
                ],
                "forbidden_actions": [
                    "read_cookie",
                    "read_token",
                    "read_csrf_secret",
                    "read_localStorage",
                    "read_sessionStorage",
                    "save_password",
                    "solve_captcha",
                    "click_final_submit",
                ],
                "stop_points": [
                    {"id": "login-required", "condition": "资源页或提交页显示登录/注册、SSO、403 或未登录状态", "action": "停止填写，等待用户登录后重新打开新增题目页"},
                    {"id": "upload-result-required", "condition": "页面上传控件未返回可见结果", "action": "等待用户确认上传状态"},
                    {"id": "pre-submit-review", "condition": "最终提交按钮可见前", "action": "停止并展示字段差异、上传结果和截图"},
                ],
                "field_payload": plan.get("form_payload", {}),
                "field_selectors": HUB_FORM_FIELDS,
                "upload_files": plan.get("upload_files", []),
                "screenshots": plan.get("screenshots", []),
            },
            "steps": [
                {"id": "open-chrome", "action": "用用户当前 Chrome 会话打开 Hub CTF 页面", "target": hub_url, "requires_user_confirmation": False},
                {"id": "wait-login", "action": "先确认已登录；如果出现登录/注册、验证码或权限页，停止并等待用户处理，不填写表单", "target": "chrome", "requires_user_confirmation": True},
                {"id": "open-create-form", "action": "确认登录后再打开新增 CTF 题目路由 #/activity/submitctf/0/0/0", "target": "chrome", "requires_user_confirmation": False},
                {"id": "fill-visible-fields", "action": "只填写页面可见字段；富文本解答由页面可见编辑器写入", "target": "form", "requires_user_confirmation": False},
                {"id": "upload-visible-files", "action": "通过页面文件控件上传 manifest 中的附件、镜像 tar 和截图", "target": "upload", "requires_user_confirmation": True},
                {"id": "record-upload-results", "action": "只记录页面可见的上传结果 URL、文件名、状态和错误", "target": "upload", "requires_user_confirmation": False},
                {"id": "pre-submit-review", "action": "最终提交前停止，输出字段差异、缺失项、上传结果和预览截图", "target": "preview", "requires_user_confirmation": True},
            ],
        }
    )
    return plan


def create_hub_form_payload(
    hub_fields: dict[str, Any],
    *,
    manifest: dict[str, Any] | None = None,
    classify_options: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    manifest = manifest or {}
    upload_files = manifest.get("upload_files", []) if isinstance(manifest.get("upload_files"), list) else []
    attached = next((item for item in upload_files if item.get("role") == "attachment"), {})
    image_tar = next((item for item in upload_files if item.get("role") == "image_tar"), {})
    upload_results = manifest.get("upload_results", []) if isinstance(manifest.get("upload_results"), list) else []
    attached_upload = find_upload_result(upload_results, attached)
    image_upload = find_upload_result(upload_results, image_tar)
    answer = _string(hub_fields.get("题目解答") or hub_fields.get("manual_markdown") or "")
    classify_resolution = resolve_hub_classify(hub_fields, classify_options=classify_options)
    payload = {
        "name": _string(hub_fields.get("题目标题")),
        "desc": _string(hub_fields.get("题目内容")),
        "flag": _string(hub_fields.get("题目Flag")),
        "source": _string(hub_fields.get("题目来源")),
        "classify": classify_resolution.get("id") or _string(hub_fields.get("题目分类")),
        "classify_label": classify_resolution.get("label") or _string(hub_fields.get("题目分类")),
        "classify_resolution": classify_resolution,
        "answer": answer,
        "keyword": _list_value(hub_fields.get("添加关键字")),
        "attached": _string(attached_upload.get("url") or attached_upload.get("path") or attached.get("relative_path")),
        "attached_name": Path(_string(attached.get("relative_path"))).name if attached else "",
        "attached_upload_result": attached_upload,
        "other_attached": _string(image_upload.get("url") or image_upload.get("path") or image_tar.get("relative_path")),
        "other_attached_name": Path(_string(image_tar.get("relative_path"))).name if image_tar else "",
        "other_attached_upload_result": image_upload,
        "flag_type": _hub_flag_type(_string(hub_fields.get("Flag类型"))),
        "flag_script": _string(hub_fields.get("Flag脚本")),
        "test_type": _hub_test_type(_string(hub_fields.get("题目类型"))),
        "score": _string(hub_fields.get("题目分值")),
        "level": _hub_level(_string(hub_fields.get("题目等级"))),
        "remark": _string(hub_fields.get("题目备注")),
        "resource_level": _string(hub_fields.get("资源等级")),
    }
    return payload


def validate_hub_form_payload(payload: dict[str, Any], *, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    manifest = manifest or {}
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
    classify_resolution = payload.get("classify_resolution") if isinstance(payload.get("classify_resolution"), dict) else {}
    upload_files = manifest.get("upload_files", []) if isinstance(manifest.get("upload_files"), list) else []
    upload_results = manifest.get("upload_results", []) if isinstance(manifest.get("upload_results"), list) else []
    screenshots = manifest.get("screenshots", []) if isinstance(manifest.get("screenshots"), list) else []
    pending_uploads = []
    for item in upload_files:
        if not isinstance(item, dict):
            continue
        result = find_upload_result(upload_results, item)
        if not _string(result.get("url") or result.get("path") or result.get("file_id")).strip():
            pending_uploads.append(item.get("relative_path", ""))
    missing_screenshots = [
        item.get("filename", "")
        for item in screenshots
        if isinstance(item, dict) and not _string(item.get("relative_path") or item.get("path")).strip()
    ]
    blockers = list(missing)
    if not classify_resolution.get("id"):
        blockers.append("classify_id")
    if pending_uploads:
        blockers.append("upload_results")
    return {
        "status": "ready" if not blockers else "needs_input",
        "missing": missing,
        "blockers": blockers,
        "classify_resolution": classify_resolution,
        "pending_uploads": pending_uploads,
        "missing_screenshots": missing_screenshots,
        "notes": [
            "classify 在页面中需要匹配为分类 ID，不能只依赖中文分类文本。",
            "answer 需要写入富文本编辑器；Markdown 到 HTML 的转换由 Agent 在浏览器步骤执行或人工确认。",
            "attached/other_attached 需要先通过页面上传控件上传，返回 URL 后才能提交。",
        ],
    }


def resolve_hub_classify(hub_fields: dict[str, Any], *, classify_options: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    explicit_id = first_nonempty(hub_fields, CLASSIFY_ID_KEYS)
    label = first_nonempty(hub_fields, CLASSIFY_TEXT_KEYS)
    if explicit_id:
        return {"status": "resolved", "id": explicit_id, "label": label, "source": "hub_fields"}
    if not label:
        return {"status": "missing", "id": "", "label": "", "source": ""}
    wanted = normalize_classify_label(label)
    for option in classify_options or []:
        if not isinstance(option, dict):
            continue
        option_label = first_nonempty(option, CLASSIFY_TEXT_KEYS)
        option_id = first_nonempty(option, CLASSIFY_ID_KEYS)
        if option_id and normalize_classify_label(option_label) == wanted:
            return {"status": "resolved", "id": option_id, "label": option_label, "source": "classify_options"}
    return {"status": "needs_mapping", "id": "", "label": label, "source": "hub_fields"}


def apply_upload_results(manifest: dict[str, Any], upload_results: list[dict[str, Any]]) -> dict[str, Any]:
    updated = dict(manifest)
    normalized = []
    for item in upload_results:
        if not isinstance(item, dict):
            continue
        normalized.append(
            {
                "role": _string(item.get("role")),
                "relative_path": _string(item.get("relative_path") or item.get("local_path")),
                "name": _string(item.get("name") or Path(_string(item.get("relative_path") or item.get("local_path"))).name),
                "url": _string(item.get("url") or item.get("path") or item.get("file_url") or item.get("filePath")),
                "file_id": _string(item.get("file_id") or item.get("id") or item.get("uid")),
                "status": _string(item.get("status") or ("uploaded" if item.get("url") or item.get("path") or item.get("file_url") else "")),
                "error": _string(item.get("error")),
            }
        )
    updated["upload_results"] = normalized
    fields = updated.get("hub_fields", {}) if isinstance(updated.get("hub_fields"), dict) else {}
    updated["form_payload"] = create_hub_form_payload(fields, manifest=updated)
    updated["validation"] = validate_hub_form_payload(updated["form_payload"], manifest=updated)
    return updated


def find_upload_result(upload_results: list[dict[str, Any]], upload_file: dict[str, Any]) -> dict[str, Any]:
    if not upload_file:
        return {}
    role = _string(upload_file.get("role"))
    relative_path = _string(upload_file.get("relative_path"))
    name = Path(relative_path).name if relative_path else ""
    for result in upload_results:
        if not isinstance(result, dict):
            continue
        result_path = _string(result.get("relative_path") or result.get("local_path"))
        result_name = _string(result.get("name") or Path(result_path).name)
        if role and _string(result.get("role")) and role != _string(result.get("role")):
            continue
        if relative_path and result_path == relative_path:
            return result
        if name and result_name == name:
            return result
    return {}


def normalize_classify_label(value: str) -> str:
    aliases = {
        "web": "web",
        "pwn": "pwn",
        "misc": "misc",
        "crypto": "crypto",
        "reverse": "reverse",
        "rev": "reverse",
        "forensics": "forensics",
        "forensic": "forensics",
        "ai": "ai",
        "osint": "osint",
        "mobile": "mobile",
        "iot": "iot",
        "区块链": "blockchain",
        "blockchain": "blockchain",
    }
    lowered = _string(value).strip().lower()
    return aliases.get(lowered, lowered)


def first_nonempty(mapping: dict[str, Any], keys: list[str]) -> str:
    for key in keys:
        value = _string(mapping.get(key)).strip()
        if value:
            return value
    return ""


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
        f"- 自动提交：{'是' if plan.get('auto_submit') else '否'}",
        f"- 提交前停止：{'是' if plan.get('stop_before_submit') else '否'}",
        "",
        "## 安全边界",
        "",
    ]
    lines.extend(f"- {item}" for item in plan.get("security_boundaries", []))
    gate = plan.get("login_state_gate") if isinstance(plan.get("login_state_gate"), dict) else {}
    if gate:
        lines.extend(["", "## 登录态门槛", ""])
        lines.append(f"- 填写前必须确认登录：{'是' if gate.get('required_before_fill') else '否'}")
        lines.append("- 未登录处理：" + str(gate.get("on_unauthenticated", "")))
        indicators = gate.get("unauthenticated_indicators", [])
        if indicators:
            lines.append("- 未登录信号：" + "、".join(str(item) for item in indicators))
    lines.extend(["", "## 步骤", ""])
    for step in plan.get("steps", []):
        confirm = "需要确认" if step.get("requires_user_confirmation") else "无需确认"
        lines.append(f"- {step.get('id', '')}：{step.get('action', '')}（{confirm}）")
    contract = plan.get("chrome_execution_contract") if isinstance(plan.get("chrome_execution_contract"), dict) else {}
    if contract:
        lines.extend(["", "## Chrome 执行约束", ""])
        lines.append(f"- 入口页面：{contract.get('entry_url', '')}")
        lines.append(f"- 新增页面：{contract.get('create_url', '')}")
        if contract.get("file_upload_requirement"):
            lines.append(f"- 文件上传要求：{contract.get('file_upload_requirement')}")
        lines.append("- 禁止动作：" + "、".join(contract.get("forbidden_actions", [])))
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


def load_classify_options(path: str | Path) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ["data", "results", "items", "classify", "classifies"]:
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    nested = payload.get("data")
    if isinstance(nested, dict):
        for key in ["results", "items", "classify", "classifies"]:
            value = nested.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


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
    browser_parser.add_argument("--classify-options", help="JSON file from /ctf/classify/?type=1 or a normalized options list")

    chrome_parser = subparsers.add_parser("chrome-plan", help="create Chrome-assisted Hub filling plan")
    chrome_parser.add_argument("--manifest", required=True)
    chrome_parser.add_argument("--output", required=True)
    chrome_parser.add_argument("--report")
    chrome_parser.add_argument("--hub-url", default="https://hub.yunyansec.com/#/resource/ctf")
    chrome_parser.add_argument("--classify-options", help="JSON file from /ctf/classify/?type=1 or a normalized options list")

    upload_parser = subparsers.add_parser("apply-upload-results", help="merge Hub upload results back into an upload manifest")
    upload_parser.add_argument("--manifest", required=True)
    upload_parser.add_argument("--upload-results", required=True)
    upload_parser.add_argument("--output", required=True)

    validate_parser = subparsers.add_parser("validate-manifest", help="validate Hub submission readiness before final submit")
    validate_parser.add_argument("--manifest", required=True)
    validate_parser.add_argument("--classify-options", help="JSON file from /ctf/classify/?type=1 or a normalized options list")
    validate_parser.add_argument("--output", required=True)

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
        classify_options = load_classify_options(args.classify_options) if args.classify_options else None
        plan = create_browser_assist_plan(manifest, hub_url=args.hub_url, classify_options=classify_options)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        report = Path(args.report) if args.report else output.with_suffix(".md")
        report.write_text(render_browser_assist_plan(plan), encoding="utf-8")
        print(f"wrote {output}")
        return 0
    if args.command == "chrome-plan":
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        classify_options = load_classify_options(args.classify_options) if args.classify_options else None
        plan = create_chrome_assist_plan(manifest, hub_url=args.hub_url, classify_options=classify_options)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        report = Path(args.report) if args.report else output.with_suffix(".md")
        report.write_text(render_browser_assist_plan(plan), encoding="utf-8")
        print(f"wrote {output}")
        return 0
    if args.command == "apply-upload-results":
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        upload_results = json.loads(Path(args.upload_results).read_text(encoding="utf-8"))
        if isinstance(upload_results, dict):
            upload_results = upload_results.get("results", upload_results.get("upload_results", []))
        if not isinstance(upload_results, list):
            raise ValueError("upload results must be a list or an object containing results/upload_results")
        updated = apply_upload_results(manifest, upload_results)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(updated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {output}")
        return 0
    if args.command == "validate-manifest":
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        fields = manifest.get("hub_fields", {}) if isinstance(manifest.get("hub_fields"), dict) else {}
        classify_options = load_classify_options(args.classify_options) if args.classify_options else None
        payload = create_hub_form_payload(fields, manifest=manifest, classify_options=classify_options)
        validation = validate_hub_form_payload(payload, manifest=manifest)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps({"form_payload": payload, "validation": validation}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {output}")
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
