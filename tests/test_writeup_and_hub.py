import json
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

        self.assertIn("### 题目描述", manual)
        self.assertIn("#### 题目名称", manual)
        self.assertIn("#### 解题工具", manual)
        self.assertIn("### 解题步骤", manual)
        self.assertIn("flag{stage-five-full-flag}", manual)

    def test_screenshot_plan_uses_stable_names(self):
        plan = hub.default_screenshot_plan()

        self.assertEqual([item["filename"] for item in plan], [
            "01-challenge-page.png",
            "02-container-running.png",
            "03-solve-proof.png",
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
            self.assertTrue((output_dir / "attachments" / "challenge.zip").exists())
            self.assertTrue((output_dir / "images" / "web.tar").exists())
            self.assertTrue((output_dir / "hub_submission_checklist.md").exists())
            self.assertEqual(manifest["summary"]["total_upload_files"], 2)
            self.assertEqual(manifest["hub_fields"]["题目Flag"], "flag{stage-five-full-flag}")

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
            self.assertEqual(plan["site_observation"]["routes"]["ctf_create"], "https://hub.yunyansec.com/#/activity/submitctf/0/0/0")
            self.assertEqual(plan["form_payload"]["flag_type"], 2)
            self.assertEqual(plan["form_payload"]["test_type"], 1)
            self.assertEqual(plan["form_payload"]["level"], "3")
            self.assertIn("answer", plan["validation"]["missing"])
            self.assertTrue(any("不读取或保存 Cookie" in item for item in plan["security_boundaries"]))
            self.assertTrue(any(step["id"] == "manual-submit" for step in plan["steps"]))
            self.assertIn("Hub 浏览器辅助填表方案", report)
            self.assertIn("POST /ctf/add/", json.dumps(plan, ensure_ascii=False))

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


if __name__ == "__main__":
    unittest.main()
