import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import cloversec_ctf_hub as hub
import cloversec_ctf_writeup as writeup


def sample_case(tmp_path):
    attachment = tmp_path / "challenge.zip"
    image = tmp_path / "web.tar"
    screenshot = tmp_path / "page.png"
    attachment.write_bytes(b"attachment")
    image.write_bytes(b"image")
    screenshot.write_bytes(b"png")
    return {
        "case_id": "case-001",
        "metadata": {
            "赛事来源": "2026 示例赛",
            "题目来源": "2026 示例赛",
            "名称": "[2026示例赛]Web1",
            "分类": "Web",
            "题目类型": "环境型",
            "难度编号": "3",
            "分值": "100",
            "资源等级": "4",
            "开放端口": "80",
            "解题工具": "dirsearch, python3",
            "备注": "web容器/默认start.sh启动/映射端口80",
        },
        "flag": {"value": "flag{stage-five-full-flag}", "type": "dynamic", "sensitive": True},
        "writeup": {
            "description": "访问页面后通过备份文件泄漏获取源码。",
            "prerequisites": ["Web 基础操作知识", "Python 语言基础知识"],
            "knowledge_points": ["备份文件泄漏", "代码审计"],
            "tools": ["dirsearch", "python3"],
            "steps": ["访问题目页面。", "扫描目录并下载备份文件。", "运行脚本得到 Flag。"],
            "keywords": ["源码泄漏", "代码审计"],
        },
        "attachments": [{"path": attachment.as_posix(), "name": "challenge.zip"}],
        "docker_artifacts": {"tar_path": image.as_posix(), "platform": "linux/amd64"},
        "hub_fields": {},
        "archive": {"screenshots": [screenshot.as_posix()]},
    }


class WriteupAndHubTests(unittest.TestCase):
    def test_difficulty_profile_keeps_ten_level_mapping(self):
        profile = writeup.difficulty_profile("10")

        self.assertEqual(profile["编号"], "10")
        self.assertEqual(profile["难度等级"], "破天（Insane）")
        self.assertEqual(profile["题目难度"], "★★★★★★")

    def test_build_hub_fields_keeps_full_flag_and_xlsx_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = sample_case(Path(tmp))

            result = writeup.build_hub_fields(case)

        self.assertEqual(result["hub_fields"]["题目标题"], "[2026示例赛]Web1")
        self.assertEqual(result["hub_fields"]["Flag类型"], "动态Flag")
        self.assertEqual(result["hub_fields"]["题目Flag"], "flag{stage-five-full-flag}")
        self.assertEqual(result["hub_fields"]["题目等级"], "3级")
        self.assertEqual(result["hub_fields"]["题目难度"], "★★")
        self.assertEqual(result["xlsx_fields"]["Flag"], "flag{stage-five-full-flag}")
        self.assertEqual(result["xlsx_fields"]["星级"], "★★")

    def test_render_manual_draft_contains_required_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = sample_case(Path(tmp))
            fields = writeup.build_hub_fields(case)["hub_fields"]

            manual = writeup.render_manual(case, fields, filled=True)

        self.assertIn("## 题目说明", manual)
        self.assertIn("- 题目名称：", manual)
        self.assertIn("## 解题工具", manual)
        self.assertIn("## 解题步骤", manual)
        self.assertIn("## 命令输出", manual)
        self.assertIn("## 截图说明", manual)
        self.assertIn("flag{stage-five-full-flag}", manual)

    def test_screenshot_plan_uses_stable_names(self):
        plan = hub.default_screenshot_plan()

        self.assertEqual([item["filename"] for item in plan], [
            "题目页面.png",
            "容器运行.png",
            "解题证明.png",
        ])

    def test_create_submission_package_writes_expected_structure(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            fields = writeup.build_hub_fields(case)
            manual = writeup.render_manual(case, fields["hub_fields"], filled=True)
            output_dir = tmp_path / "hub_submission_package"

            manifest = hub.create_submission_package(
                case=case,
                hub_fields=fields["hub_fields"],
                manual_markdown=manual,
                output_dir=output_dir,
            )

            self.assertTrue((output_dir / "fields" / "hub_fields.json").exists())
            self.assertTrue((output_dir / "fields" / "hub_fields_preview.json").exists())
            self.assertTrue((output_dir / "manual" / "manual_filled_draft.md").exists())
            self.assertTrue((output_dir / "manual" / "题目解题手册.md").exists())
            self.assertTrue((output_dir / "attachments" / "challenge.zip").exists())
            self.assertFalse((output_dir / "images" / "web.tar").exists())
            self.assertTrue((output_dir / "hub_submission_checklist.md").exists())
            self.assertEqual(manifest["summary"]["total_upload_files"], 2)
            image_tar = next(item for item in manifest["upload_files"] if item["role"] == "image_tar")
            self.assertEqual(image_tar["status"], "referenced")
            self.assertEqual(image_tar["path"], case["docker_artifacts"]["tar_path"])
            self.assertEqual(manifest["hub_fields"]["题目Flag"], "flag{stage-five-full-flag}")

    def test_hub_draft_fills_empty_content_answer_and_keywords_from_manual(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            manual = writeup.render_manual(case, writeup.build_hub_fields(case)["hub_fields"], filled=True)
            empty_fields = {
                "题目标题": "",
                "题目内容": "",
                "题目解答": "",
                "添加关键字": [],
                "题目分类": "Web",
                "题目来源": "2026 示例赛",
                "Flag类型": "动态Flag",
                "题目Flag": "flag{stage-five-full-flag}",
                "题目分值": "100",
                "题目等级": "3",
                "题目类型": "环境型",
                "资源等级": "4",
            }

            draft = hub.create_hub_draft(case, empty_fields, manual, tmp_path / "hub_submission_package", classify_options=[{"label": "Web", "id": "1"}])

        self.assertTrue(draft["form_payload"]["desc"].strip())
        self.assertTrue(draft["form_payload"]["answer"].strip())
        self.assertTrue(draft["form_payload"]["keyword"])
        self.assertNotIn("desc", draft["validation"]["missing"])
        self.assertNotIn("answer", draft["validation"]["missing"])
        self.assertNotIn("keyword", draft["validation"]["missing"])

    def test_browser_assist_plan_keeps_security_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            fields = writeup.build_hub_fields(case)
            manual = writeup.render_manual(case, fields["hub_fields"], filled=True)
            manifest = hub.create_submission_package(
                case=case,
                hub_fields=fields["hub_fields"],
                manual_markdown=manual,
                output_dir=tmp_path / "hub_submission_package",
            )

            plan = hub.create_browser_assist_plan(manifest)
            report = hub.render_browser_assist_plan(plan)

            self.assertEqual(plan["mode"], "browser-assisted")
            self.assertFalse(plan["auto_submit"])
            self.assertTrue(plan["stop_before_submit"])
            self.assertEqual(plan["site_observation"]["routes"]["ctf_create"], "https://hub.yunyansec.com/#/activity/submitctf/0/0/0")
            self.assertEqual(plan["form_payload"]["flag_type"], 2)
            self.assertEqual(plan["form_payload"]["test_type"], 1)
            self.assertEqual(plan["form_payload"]["level"], "3")
            self.assertNotIn("answer", plan["validation"]["missing"])
            self.assertTrue(plan["form_payload"]["answer"].strip())
            self.assertIn("classify_id", plan["validation"]["blockers"])
            self.assertIn("upload_results", plan["validation"]["blockers"])
            self.assertIn("容器运行.png", plan["validation"]["missing_screenshots"])
            self.assertTrue(plan["login_state_gate"]["required_before_fill"])
            self.assertEqual(plan["login_state_gate"]["on_unauthenticated"], "stop_before_fill_and_wait_for_user_login")
            self.assertTrue(any("不读取或保存 Cookie" in item for item in plan["security_boundaries"]))
            self.assertTrue(any("没有确认登录态前" in item for item in plan["security_boundaries"]))
            self.assertTrue(any(step["id"] == "manual-submit" for step in plan["steps"]))
            self.assertTrue(any("手动提交" in step["action"] for step in plan["steps"] if step["id"] == "manual-submit"))
            self.assertIn("Hub 浏览器辅助填表方案", report)
            self.assertIn("填写前必须确认登录：是", report)
            self.assertIn("POST /ctf/add/", json.dumps(plan, ensure_ascii=False))

    def test_chrome_assist_plan_stops_before_submit(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            fields = writeup.build_hub_fields(case)
            manual = writeup.render_manual(case, fields["hub_fields"], filled=True)
            manifest = hub.create_submission_package(
                case=case,
                hub_fields=fields["hub_fields"],
                manual_markdown=manual,
                output_dir=tmp_path / "hub_submission_package",
            )

            plan = hub.create_chrome_assist_plan(manifest)

        self.assertEqual(plan["mode"], "chrome-assisted")
        self.assertTrue(plan["requires_chrome_plugin"])
        self.assertFalse(plan["auto_submit"])
        self.assertTrue(plan["stop_before_submit"])
        contract = plan["chrome_execution_contract"]
        self.assertTrue(contract["login_state_gate"]["required_before_fill"])
        self.assertIn("登录/注册", contract["login_state_gate"]["unauthenticated_indicators"])
        self.assertIn("click_final_submit", contract["forbidden_actions"])
        self.assertIn("read_cookie", contract["forbidden_actions"])
        self.assertIn("read_localStorage", contract["forbidden_actions"])
        self.assertIn("Allow access to file URLs", contract["file_upload_requirement"])
        self.assertTrue(any(step["id"] == "pre-submit-review" for step in plan["steps"]))

    def test_hub_session_state_tracks_login_upload_and_manual_submit_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            fields = writeup.build_hub_fields(case)
            manual = writeup.render_manual(case, fields["hub_fields"], filled=True)
            draft = hub.create_hub_draft(case, fields["hub_fields"], manual, tmp_path / "hub_submission_package")
            manifest = json.loads((tmp_path / "hub_submission_package" / "hub_upload_manifest.json").read_text(encoding="utf-8"))
            upload_results = [
                {"role": "attachment", "status": "uploaded", "url": "/media/ctf/challenge.zip"},
                {"role": "image_tar", "status": "uploaded", "url": "/media/ctf/web.tar"},
            ]

            state = hub.create_hub_session_state(
                tmp_path / "hub_submission_package",
                case=case,
                draft=draft,
                manifest=manifest,
                visible_page={"url": "https://hub.yunyansec.com/#/resource/ctf", "title": "云演资源中心"},
                login_confirmed=True,
                field_fill_status="filled",
                upload_results=upload_results,
                pre_submit_screenshot=(tmp_path / "pre_submit.png").as_posix(),
                user_submitted=False,
            )
            state_path_exists = (tmp_path / "hub_submission_package" / "hub_session_state.json").exists()

        self.assertTrue(state["login"]["confirmed"])
        self.assertEqual(state["uploads"]["pending_count"], 0)
        self.assertIn("停在最终提交前", state["next_action"])
        self.assertIn("click_final_submit", state["forbidden_actions"])
        self.assertEqual(state["manual_submit"]["hub_record_id"], "")
        self.assertTrue(state_path_exists)

    def test_hub_classify_options_and_upload_results_update_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            fields = writeup.build_hub_fields(case)
            manual = writeup.render_manual(case, fields["hub_fields"], filled=True)
            manifest = hub.create_submission_package(
                case=case,
                hub_fields=fields["hub_fields"],
                manual_markdown=manual,
                output_dir=tmp_path / "hub_submission_package",
            )
            options = [{"id": 101, "name": "Web"}, {"id": 102, "name": "Misc"}]
            upload_results = [
                {"role": "attachment", "relative_path": "attachments/challenge.zip", "url": "/media/ctf/challenge.zip", "status": "uploaded"},
                {"role": "image_tar", "relative_path": "images/web.tar", "url": "/media/ctf/web.tar", "status": "uploaded"},
            ]

            updated = hub.apply_upload_results(manifest, upload_results)
            payload = hub.create_hub_form_payload(fields["hub_fields"], manifest=updated, classify_options=options)
            validation = hub.validate_hub_form_payload(payload, manifest=updated)

        self.assertEqual(payload["classify"], "101")
        self.assertEqual(payload["classify_resolution"]["source"], "classify_options")
        self.assertEqual(payload["attached"], "/media/ctf/challenge.zip")
        self.assertEqual(payload["other_attached"], "/media/ctf/web.tar")
        self.assertNotIn("upload_results", validation["blockers"])
        self.assertNotIn("answer", validation["missing"])
        self.assertTrue(payload["answer"].strip())

    def test_hub_cli_validate_manifest_accepts_classify_options(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            fields = writeup.build_hub_fields(case)
            manual = writeup.render_manual(case, fields["hub_fields"], filled=True)
            manifest = hub.create_submission_package(
                case=case,
                hub_fields=fields["hub_fields"],
                manual_markdown=manual,
                output_dir=tmp_path / "hub_submission_package",
            )
            manifest_path = tmp_path / "manifest.json"
            classify_path = tmp_path / "classify.json"
            output = tmp_path / "validation.json"
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
            classify_path.write_text(json.dumps({"data": [{"id": 101, "name": "Web"}]}, ensure_ascii=False), encoding="utf-8")

            code = hub.main([
                "validate-manifest",
                "--manifest",
                str(manifest_path),
                "--classify-options",
                str(classify_path),
                "--output",
                str(output),
            ])
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(code, 0)
        self.assertEqual(payload["form_payload"]["classify"], "101")
        self.assertIn("upload_results", payload["validation"]["blockers"])

    def test_hub_cli_chrome_plan_writes_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            fields = writeup.build_hub_fields(case)
            manual = writeup.render_manual(case, fields["hub_fields"], filled=True)
            manifest = hub.create_submission_package(
                case=case,
                hub_fields=fields["hub_fields"],
                manual_markdown=manual,
                output_dir=tmp_path / "hub_submission_package",
            )
            manifest_path = tmp_path / "manifest.json"
            output = tmp_path / "chrome_plan.json"
            report = tmp_path / "chrome_plan.md"
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")

            code = hub.main([
                "chrome-plan",
                "--manifest",
                str(manifest_path),
                "--output",
                str(output),
                "--report",
                str(report),
            ])
            payload = json.loads(output.read_text(encoding="utf-8"))
            report_text = report.read_text(encoding="utf-8")

        self.assertEqual(code, 0)
        self.assertEqual(payload["mode"], "chrome-assisted")
        self.assertIn("click_final_submit", payload["chrome_execution_contract"]["forbidden_actions"])
        self.assertIn("Allow access to file URLs", payload["chrome_execution_contract"]["file_upload_requirement"])
        self.assertIn("Allow access to file URLs", report_text)
        self.assertIn("提交前停止：是", report_text)

    def test_hub_assistant_mcp_tools_list_and_chrome_plan(self):
        manifest = {
            "hub_fields": {
                "题目标题": "Demo",
                "题目内容": "Demo desc",
                "题目Flag": "flag{demo}",
                "题目来源": "Demo CTF",
                "题目分类": "Web",
                "题目分值": "100",
                "题目等级": "3级",
                "题目类型": "环境型",
                "资源等级": "4",
                "添加关键字": ["web"],
                "Flag类型": "静态Flag",
            },
            "upload_files": [],
            "screenshots": [],
        }
        process = subprocess.Popen(
            [sys.executable, str(SCRIPTS / "cloversec_ctf_hub_assistant_mcp.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert process.stdin is not None
            assert process.stdout is not None
            process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
            process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n")
            process.stdin.write(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "cloversec_ctf_hub_chrome_plan",
                            "arguments": {
                                "manifest": manifest,
                                "classify_options": [{"id": 101, "name": "Web"}],
                            },
                        },
                    }
                )
                + "\n"
            )
            process.stdin.flush()
            init = json.loads(process.stdout.readline())
            tools = json.loads(process.stdout.readline())
            call = json.loads(process.stdout.readline())
        finally:
            if process.stdin:
                process.stdin.close()
            if process.stdout:
                process.stdout.close()
            process.terminate()
            process.wait(timeout=5)

        self.assertEqual(init["result"]["serverInfo"]["name"], "cloversec-ctf-hub-assistant")
        self.assertTrue(any(item["name"] == "cloversec_ctf_hub_chrome_plan" for item in tools["result"]["tools"]))
        self.assertIn("chrome-assisted", call["result"]["content"][0]["text"])
        self.assertIn("click_final_submit", call["result"]["content"][0]["text"])

    def test_cli_writeup_outputs_json_and_manual(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            case_path = tmp_path / "ctf_case.json"
            output_dir = tmp_path / "writeup"
            case_path.write_text(json.dumps(case, ensure_ascii=False), encoding="utf-8")

            code = writeup.main(["render", str(case_path), "--output-dir", str(output_dir)])

            self.assertEqual(code, 0)
            self.assertTrue((output_dir / "hub_fields.json").exists())
            self.assertTrue((output_dir / "manual_filled_draft.md").exists())
            self.assertTrue((output_dir / "题目解题手册.md").exists())

    def test_hub_visible_page_id_is_not_formal_hub_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)

            state = hub.create_hub_review_state(
                case,
                tmp_path / "hub-review",
                review_status="approved",
                visible_page={"id": "12345", "url": "https://hub.yunyansec.com/#/resource/ctf"},
            )

        self.assertFalse(state["retag_required"])
        self.assertEqual(state["hub_record_id"], "12345")
        self.assertEqual(state["HUB编号"], "")


if __name__ == "__main__":
    unittest.main()
