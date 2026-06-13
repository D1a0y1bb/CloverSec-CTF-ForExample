import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import cloversec_ctf_archive as archive
import cloversec_ctf_data as data
import cloversec_ctf_final as final
import cloversec_ctf_retag as retag
import cloversec_ctf_review as review


def sample_case(tmp_path):
    source = tmp_path / "src.py"
    attachment = tmp_path / "challenge.zip"
    image = tmp_path / "web.tar"
    manual = tmp_path / "manual_filled_draft.md"
    screenshot = tmp_path / "solve.png"
    source.write_text("print('ctf')\n", encoding="utf-8")
    attachment.write_bytes(b"zip-bytes")
    image.write_bytes(b"docker-tar")
    manual.write_text("# writeup\n\nflag is recorded in structured data.\n", encoding="utf-8")
    screenshot.write_bytes(b"png")
    return {
        "case_id": "case-001",
        "metadata": {
            "HUB编号": "",
            "赛事来源": "2026 示例赛",
            "题目来源": "2026 示例赛",
            "名称": "Web1",
            "分类": "Web",
            "题目类型": "环境型",
            "Flag类型": "动态Flag",
            "难度编号": "3",
            "星级": "★★",
            "分值": "100",
            "资源等级": "4",
            "提交时间": "2026-06-13",
            "开放端口": "80",
            "离线/在线解题": "在线",
            "解题工具": "python3",
            "提交用户名": "测试用户",
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
        "flag": {"value": "flag{stage-six-full-flag}", "type": "dynamic", "sensitive": True},
        "confidence": "high",
        "source_files": [{"path": source.as_posix(), "name": "src.py"}],
        "attachments": [{"path": attachment.as_posix(), "name": "challenge.zip"}],
        "docker_artifacts": {
            "image_name": "cloversec/web1:local",
            "platform": "linux/amd64",
            "tar_path": image.as_posix(),
            "run_verified": False,
        },
        "writeup": {
            "manual_path": manual.as_posix(),
            "solve_verified": False,
        },
        "archive": {"screenshots": [screenshot.as_posix()]},
        "research": {},
        "asset_collection": {},
        "environment": {},
        "hub_fields": {},
        "review": {},
        "evidence": [],
    }


class ArchiveReviewFinalTests(unittest.TestCase):
    def test_archive_package_copies_files_and_updates_xlsx_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            manifest = archive.create_archive_package(case, tmp_path / "archive")

            archive_dir = Path(manifest["archive_dir"])
            updated = archive.apply_archive_outputs(case, manifest)

            self.assertTrue((archive_dir / "source" / "src.py").exists())
            self.assertTrue((archive_dir / "attachments" / "challenge.zip").exists())
            self.assertTrue((archive_dir / "image" / "web.tar").exists())
            self.assertTrue((archive_dir / "writeup" / "manual_filled_draft.md").exists())
            self.assertTrue((archive_dir / "screenshots" / "solve.png").exists())
            self.assertTrue((archive_dir / "manifests" / "archive_manifest.json").exists())
            self.assertEqual(manifest["xlsx_fields"]["是否归档"], "是")
            self.assertEqual(updated["metadata"]["是否归档"], "是")
            self.assertEqual(updated["metadata"]["归档目录"], archive_dir.as_posix())
            self.assertEqual(updated["metadata"]["环境包/附件包路径"], "image/web.tar")

    def test_quality_review_keeps_unexecuted_docker_and_solve_checks_as_skip(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            manifest = archive.create_archive_package(case, tmp_path / "archive")
            case = archive.apply_archive_outputs(case, manifest)

            result = review.create_quality_review(case, archive_dir=manifest["archive_dir"])
            by_id = {item["id"]: item for item in result["checks"]}

            self.assertEqual(by_id["docker-run"]["status"], "skip")
            self.assertEqual(by_id["solve-proof"]["status"], "skip")
            self.assertEqual(by_id["image-platform"]["status"], "pass")
            self.assertEqual(result["xlsx_fields"]["验证状态"], "部分通过")
            self.assertEqual(result["xlsx_fields"]["是否通过"], "否")

    def test_retag_plan_updates_hub_id_and_new_image_without_running_docker(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)

            plan = retag.create_retag_plan(
                case,
                "CTF-2026060001",
                tmp_path / "retagged",
                registry_prefix="registry.local/cloversec",
            )
            updated = retag.apply_retag_outputs(case, plan)

            self.assertEqual(plan["new_image"], "registry.local/cloversec/CTF-2026060001")
            self.assertEqual(plan["xlsx_fields"]["HUB编号"], "CTF-2026060001")
            self.assertIn("docker tag", plan["commands"]["tag"])
            self.assertEqual(updated["metadata"]["HUB编号"], "CTF-2026060001")
            self.assertEqual(updated["docker_artifacts"]["image_name"], "registry.local/cloversec/CTF-2026060001")

    def test_final_outputs_write_xlsx_and_yuque_table_with_full_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            manifest = archive.create_archive_package(case, tmp_path / "archive")
            case = archive.apply_archive_outputs(case, manifest)
            quality = review.create_quality_review(case, archive_dir=manifest["archive_dir"])
            case = review.apply_review_outputs(case, quality)

            payload = final.create_final_outputs([case], tmp_path / "final")
            rows = data.read_xlsx(tmp_path / "final" / "archive.xlsx")
            yuque = (tmp_path / "final" / "yuque_table.md").read_text(encoding="utf-8")

            self.assertEqual(payload["summary"]["total"], 1)
            self.assertEqual(payload["summary"]["xlsx_readback_rows"], 1)
            self.assertEqual(rows[0]["Flag"], "flag{stage-six-full-flag}")
            self.assertIn("flag{stage-six-full-flag}", yuque)
            self.assertEqual(payload["summary"]["remaining_actions"], 0)

    def test_quality_review_cli_writes_report_and_updated_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            manifest = archive.create_archive_package(case, tmp_path / "archive")
            case = archive.apply_archive_outputs(case, manifest)
            case_path = tmp_path / "ctf_case.json"
            case_path.write_text(json.dumps(case, ensure_ascii=False), encoding="utf-8")

            code = review.main([
                "review",
                "--case-json",
                str(case_path),
                "--output-dir",
                str(tmp_path / "quality"),
                "--archive-dir",
                manifest["archive_dir"],
                "--output-case",
                str(tmp_path / "ctf_case.reviewed.json"),
            ])

            self.assertEqual(code, 0)
            self.assertTrue((tmp_path / "quality" / "quality_review.json").exists())
            self.assertTrue((tmp_path / "quality" / "quality_review_report.md").exists())
            self.assertTrue((tmp_path / "ctf_case.reviewed.json").exists())


if __name__ == "__main__":
    unittest.main()
