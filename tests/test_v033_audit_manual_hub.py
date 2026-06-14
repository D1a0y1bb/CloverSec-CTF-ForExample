import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import cloversec_ctf_audit as audit
import cloversec_ctf_archive as archive
import cloversec_ctf_data as data
import cloversec_ctf_hub as hub
import cloversec_ctf_manual_quality as manual_quality
import cloversec_ctf_retag as retag
import cloversec_ctf_search as search
import cloversec_ctf_workflow as workflow


def sample_case(tmp_path: Path) -> dict:
    source = tmp_path / "app.py"
    attachment = tmp_path / "challenge.zip"
    image = tmp_path / "web.tar"
    manual = tmp_path / "manual.md"
    screenshot = tmp_path / "solve.png"
    source.write_text("print('ok')\n", encoding="utf-8")
    attachment.write_bytes(b"zip-bytes")
    image.write_bytes(b"image-tar")
    screenshot.write_bytes(b"png")
    manual.write_text(sample_manual(), encoding="utf-8")
    return {
        "case_id": "case-033",
        "metadata": {
            "赛事来源": "2026 示例赛",
            "题目来源": "2026 示例赛",
            "名称": "Web1",
            "分类": "Web",
            "题目类型": "环境型",
            "Flag类型": "动态Flag",
            "Flag": "",
            "难度编号": "2",
            "星级": "★★",
            "分值": "100",
            "资源等级": "4",
            "提交时间": "2026-06-14",
            "开放端口": "80",
            "离线/在线解题": "在线",
            "解题工具": "python3",
            "提交用户名": "tester",
            "审核人": "",
            "是否通过": "否",
            "问题": "",
            "是否归档": "否",
            "材料状态": "已收集",
            "构建状态": "已构建",
            "手册状态": "草稿",
            "验证状态": "未验证",
            "归档目录": "",
            "环境包/附件包路径": "",
            "备注": "",
        },
        "flag": {"value": "flag{v033-full-flag}", "type": "dynamic", "sensitive": True},
        "confidence": "medium",
        "source_files": [{"path": source.as_posix(), "name": "app.py"}],
        "attachments": [{"path": attachment.as_posix(), "name": "challenge.zip"}],
        "docker_artifacts": {
            "image_name": "cloversec/web1:local",
            "platform": "linux/amd64",
            "tar_path": image.as_posix(),
        },
        "writeup": {"manual_path": manual.as_posix()},
        "archive": {"screenshots": [screenshot.as_posix()]},
        "research": {},
        "asset_collection": {},
        "environment": {},
        "hub_fields": {},
        "review": {},
        "evidence": [],
    }


def sample_manual() -> str:
    return """# Web1

## 题目描述
访问 Web 服务并读取 flag。

## 考点
路径遍历和环境变量读取。

## 环境
Docker 服务开放 80 端口。

## 解题步骤
1. 打开题目页面。
2. 运行 `python3 solve.py`。

## 附件
challenge.zip

## 截图
solve.png

## Flag
flag{v033-full-flag}
"""


def sample_hub_fields() -> dict:
    manual = sample_manual()
    return {
        "题目标题": "Web1",
        "题目内容": "访问 Web 服务并读取 flag。",
        "Flag类型": "动态Flag",
        "题目Flag": "flag{v033-full-flag}",
        "题目来源": "2026 示例赛",
        "题目分类": "Web",
        "题目分值": "100",
        "题目等级": "2",
        "题目类型": "环境型",
        "资源等级": "4",
        "题目备注": "",
        "题目解答": manual,
        "添加关键字": ["web", "ctf"],
    }


class V033AuditManualHubTests(unittest.TestCase):
    def test_manual_quality_outputs_report_and_keeps_full_flag_patch(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            payload = manual_quality.check_manual_quality(
                case=case,
                manual_markdown=sample_manual(),
                hub_fields=sample_hub_fields(),
                output_dir=tmp_path / "manual-quality",
            )

            self.assertTrue((tmp_path / "manual-quality" / "manual_quality.json").exists())
            self.assertTrue((tmp_path / "manual-quality" / "manual_quality_report.md").exists())
            self.assertTrue((tmp_path / "manual-quality" / "xlsx_fields_patch.json").exists())
            self.assertEqual(payload["xlsx_fields_patch"]["Flag"], "flag{v033-full-flag}")
            self.assertEqual(payload["summary"]["fail"], 0)

    def test_manual_quality_cli_accepts_missing_optional_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            case_path = tmp_path / "ctf_case.json"
            manual_path = tmp_path / "manual.md"
            hub_path = tmp_path / "hub_fields.json"
            output_dir = tmp_path / "manual-quality-cli"
            case_path.write_text(json.dumps(case, ensure_ascii=False), encoding="utf-8")
            manual_path.write_text(sample_manual(), encoding="utf-8")
            hub_path.write_text(json.dumps(sample_hub_fields(), ensure_ascii=False), encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "cloversec_ctf_manual_quality.py"),
                    "--case-json",
                    str(case_path),
                    "--manual",
                    str(manual_path),
                    "--hub-fields",
                    str(hub_path),
                    "--output-dir",
                    str(output_dir),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((output_dir / "manual_quality.json").exists())

    def test_audit_artifacts_cover_preview_lock_confirmation_batch_failure_and_notification(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            manifest = archive.create_archive_package(case, tmp_path / "archive")
            case = archive.apply_archive_outputs(case, manifest)
            cases_path = tmp_path / "ctf_cases.jsonl"
            cases_path.write_text(json.dumps(case, ensure_ascii=False) + "\n", encoding="utf-8")

            preview = audit.create_archive_preview(case, tmp_path / "audit", archive_root=tmp_path / "archive-preview-root")
            lock = audit.create_manifest_lock(case, tmp_path / "audit", archive_manifest=manifest)
            confirmation = audit.create_confirmation_request(action="hub", output_dir=tmp_path / "audit", case=case)
            batch = audit.create_batch_status_report([case], tmp_path / "batch")
            failure = audit.create_failure_library([case], tmp_path / "failure_cases.jsonl", extra_failures=[{"stage": "hub", "category": "returned", "message": "分类错误"}])
            notification = audit.create_stage_notification(stage="quality", output_dir=tmp_path / "notify", completed=["manual"], failed=[], pending_user=["Hub 分类"], next_inputs=["hub_fields.json"], artifacts=["manual_quality.json"])
            warnings = audit.classify_codex_warnings("WARNING cloversec-ctf missing tool\nWARNING openai-curated icon/defaultPrompt warning\n")

            self.assertEqual(preview["schema_version"], "cloversec.ctf.archive_preview.v1")
            self.assertEqual(lock["flag"]["value"], "flag{v033-full-flag}")
            self.assertTrue(confirmation["requires_user_confirmation"])
            self.assertTrue((tmp_path / "batch" / "batch_status_report.xlsx").exists())
            self.assertEqual(batch["summary"]["total"], 1)
            self.assertEqual(batch["summary"]["can_archive"], 0)
            self.assertGreaterEqual(batch["summary"]["pending_user"], 1)
            self.assertTrue(batch["rows"][0]["问题"])
            self.assertGreaterEqual(failure["summary"]["total"], 1)
            self.assertEqual(notification["summary"]["pending_user"], 1)
            self.assertEqual(warnings["summary"]["cloversec_blockers"], 1)
            self.assertEqual(warnings["summary"]["external_warnings"], 1)

    def test_dockerizer_gate_blocks_unconfirmed_container_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            case["metadata"]["验证状态"] = "通过"
            case["metadata"]["是否通过"] = "是"
            case["metadata"]["问题"] = ""
            case["metadata"]["构建状态"] = "已构建"
            case["metadata"]["是否归档"] = "否"
            case["docker_artifacts"] = {
                "project_dir": tmp_path.as_posix(),
                "dockerfile": "Dockerfile",
                "image_name": "upstream/web:latest",
            }

            batch = audit.create_batch_status_report([case], tmp_path / "batch")
            row = batch["rows"][0]
            failures = audit.create_failure_library([case], tmp_path / "failure_cases.jsonl")
            confirmation = audit.create_confirmation_request(action="dockerizer", output_dir=tmp_path / "dockerizer-confirm", case=case)

            self.assertEqual(row["可归档"], "否")
            self.assertIn("Dockerizer 改造待确认", row["待人工确认"])
            self.assertIn("cloversec-ctf-build-dockerizer", row["问题"])
            self.assertIn("platform_conversion_required", {item["category"] for item in failures["failures"]})
            self.assertIn("CONFIG PROPOSAL", confirmation["planned_outputs"])

    def test_dockerizer_gate_passes_when_platform_contract_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            case["metadata"]["验证状态"] = "通过"
            case["metadata"]["是否通过"] = "是"
            case["metadata"]["问题"] = ""
            case["metadata"]["是否归档"] = "否"
            case["docker_artifacts"] = {
                "project_dir": tmp_path.as_posix(),
                "dockerfile": "Dockerfile",
                "image_name": "cloversec/web:local",
                "platform_contract_verified": True,
            }

            row = audit.create_batch_status_report([case], tmp_path / "batch")["rows"][0]

            self.assertEqual(row["可归档"], "是")
            self.assertNotIn("Dockerizer 改造待确认", row["待人工确认"])

    def test_hub_draft_review_state_and_image_naming_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            screenshot = tmp_path / "solve.png"
            case["archive"]["screenshots"] = [{"path": screenshot.as_posix(), "name": "solve.png"}]
            draft = hub.create_hub_draft(
                case,
                sample_hub_fields(),
                sample_manual(),
                tmp_path / "hub",
                classify_options=[{"label": "Web", "id": "1"}],
            )
            review_state = hub.create_hub_review_state(case, tmp_path / "hub-review", review_status="approved", hub_id="CTF-2026060001")
            needs_id = retag.create_image_naming_plan(case, "", tmp_path / "image-needs-id")
            ready = retag.create_image_naming_plan(case, "CTF-2026060001", tmp_path / "image-ready", registry_prefix="registry.local/cloversec")

            self.assertFalse(draft["auto_submit"])
            self.assertFalse(draft["summary"]["can_submit"])
            self.assertTrue(draft["summary"]["can_fill_browser"])
            self.assertTrue(draft["manual_path"].endswith("manual_filled_draft.md"))
            self.assertTrue((tmp_path / "hub" / "hub_upload_manifest.json").exists())
            self.assertTrue((tmp_path / "hub" / "hub_screenshot_checklist.md").exists())
            self.assertTrue((tmp_path / "hub" / "hub_diff_report.md").exists())
            self.assertTrue(review_state["retag_required"])
            self.assertEqual(needs_id["status"], "needs_hub_id")
            self.assertEqual(ready["status"], "ready")
            self.assertEqual(ready["tar_name"], "ctf-2026060001.tar")
            self.assertIn("registry.local/cloversec/ctf-2026060001", ready["image_tag"])

    def test_results_to_cases_and_visible_content_evidence_are_structured(self):
        manifest = {
            "query": "IrisCTF 2025 web writeup",
            "years": [2025],
            "results": [
                {
                    "provider": "agent-web-search",
                    "kind": "web",
                    "title": "IrisCTF 2025 Web Challenge Writeup",
                    "url": "https://example.com/irisctf-2025-web-writeup",
                    "summary": "IrisCTF 2025 web writeup with challenge details",
                    "source_type": "agent_web_search",
                    "confidence": "medium",
                    "layer": "writeup_candidate",
                    "score": 70,
                    "quality_issues": [],
                }
            ],
        }
        cases = search.results_to_cases(manifest)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["metadata"]["分类"], "Web")
        self.assertEqual(cases[0]["metadata"]["年份"], "2025")
        self.assertIn("writeup_candidates", cases[0]["asset_collection"])

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            visible = tmp_path / "visible.json"
            visible.write_text(
                json.dumps({"title": "Infosec Writeups", "url": "https://infosecwriteups.com/x", "visible_text": "visible writeup body", "links": [{"title": "repo", "url": "https://github.com/a/b"}]}, ensure_ascii=False),
                encoding="utf-8",
            )
            evidence = workflow.import_visible_content_evidence(visible_content_path=visible, evidence_dir=tmp_path / "evidence")
            self.assertEqual(evidence["schema_version"], "cloversec.ctf.workflow.visible_content_evidence.v1")
            self.assertEqual(evidence["summary"]["records"], 1)
            self.assertTrue((tmp_path / "evidence" / "visible_content_evidence.json").exists())

    def test_new_mcp_tools_are_listed(self):
        servers = [
            ("cloversec_ctf_search_mcp.py", ["cloversec_ctf_results_to_cases"]),
            ("cloversec_ctf_archive_mcp.py", ["cloversec_ctf_archive_preview", "cloversec_ctf_manifest_lock"]),
            ("cloversec_ctf_quality_runner_mcp.py", ["cloversec_ctf_manual_quality", "cloversec_ctf_batch_status_report", "cloversec_ctf_failure_cases"]),
            ("cloversec_ctf_hub_assistant_mcp.py", ["cloversec_ctf_hub_draft", "cloversec_ctf_hub_review_state", "cloversec_ctf_image_naming_plan"]),
            ("cloversec_ctf_workflow_mcp.py", ["cloversec_ctf_visible_content_evidence", "cloversec_ctf_confirmation_request", "cloversec_ctf_stage_notification", "cloversec_ctf_codex_warning_report", "cloversec_ctf_platform_contract"]),
        ]
        for script, expected_tools in servers:
            process = subprocess.Popen(
                [sys.executable, str(SCRIPTS / script)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
            )
            try:
                assert process.stdin is not None
                assert process.stdout is not None
                process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
                process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n")
                process.stdin.close()
                init = json.loads(process.stdout.readline())
                tools = json.loads(process.stdout.readline())
            finally:
                if process.stdout is not None:
                    process.stdout.close()
                process.wait(timeout=5)
            self.assertEqual(init["result"]["serverInfo"]["version"], "0.4.1")
            tool_names = [item["name"] for item in tools["result"]["tools"]]
            for expected in expected_tools:
                self.assertIn(expected, tool_names)


if __name__ == "__main__":
    unittest.main()
