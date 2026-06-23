import json
import tarfile
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import cloversec_ctf_archive as archive
import cloversec_ctf_archive_runner as archive_runner
import cloversec_ctf_data as data
import cloversec_ctf_delivery as delivery
import cloversec_ctf_docker as docker_runner
import cloversec_ctf_final as final
import cloversec_ctf_quality_runner as quality_runner
import cloversec_ctf_retag as retag
import cloversec_ctf_review as review


def sample_case(tmp_path):
    source = tmp_path / "src.py"
    attachment = tmp_path / "challenge.zip"
    image = tmp_path / "web.tar"
    manual = tmp_path / "WEB-Web1.md"
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
            "材料状态": "只存在附件/源码线索",
            "构建状态": "已构建",
            "手册状态": "正式",
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
    def test_public_fixture_cases_cover_expected_states(self):
        fixture_path = ROOT / "tests" / "fixtures" / "ctf_cases.jsonl"
        cases = data.load_cases(fixture_path)
        by_id = {case["case_id"]: case for case in cases}

        self.assertIn("fixture-container-ok", by_id)
        self.assertIn("fixture-attachment-ok", by_id)
        self.assertIn("fixture-missing-manual", by_id)
        self.assertIn("fixture-missing-screenshot", by_id)
        self.assertIn("fixture-hub-numbered", by_id)
        self.assertEqual(by_id["fixture-hub-numbered"]["metadata"]["HUB编号"], "CTF-2026060001")
        self.assertFalse(by_id["fixture-missing-screenshot"]["archive"]["screenshots"])
        attachment_path = ROOT / by_id["fixture-attachment-ok"]["attachments"][0]["path"]
        with zipfile.ZipFile(attachment_path) as archive_file:
            self.assertIn("README.txt", archive_file.namelist())
        for case in cases:
            self.assertEqual(data.validate_case(case), [])

    def test_archive_package_copies_files_and_updates_xlsx_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            case["metadata"]["验证状态"] = "通过"
            case["metadata"]["是否通过"] = "是"
            manifest = archive.create_archive_package(case, tmp_path / "archive")

            archive_dir = Path(manifest["archive_dir"])
            updated = archive.apply_archive_outputs(case, manifest)

            self.assertTrue((archive_dir / "题目源码" / "src.py").exists())
            self.assertTrue((archive_dir / "题目附件" / "challenge.zip").exists())
            self.assertTrue((archive_dir / "题目镜像" / "web.tar").exists())
            self.assertTrue((archive_dir / "题目手册" / "题目解题手册.md").exists())
            self.assertFalse((archive_dir / "题目手册" / "截图").exists())
            self.assertFalse((archive_dir / "过程证据").exists())
            self.assertTrue(Path(manifest["manifest_path"]).exists())
            self.assertEqual(manifest["xlsx_fields"]["是否归档"], "是")
            self.assertEqual(updated["metadata"]["是否归档"], "是")
            self.assertEqual(updated["metadata"]["归档目录"], archive_dir.as_posix())
            self.assertEqual(updated["metadata"]["环境包/附件包路径"], "题目镜像/web.tar")
            image_records = [item for item in manifest["files"] if item["role"] == "image_tar"]
            self.assertEqual(image_records[0]["status"], "copied")

    def test_archive_package_copies_source_directory_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            src_dir = tmp_path / "srcdir"
            (src_dir / "backend").mkdir(parents=True)
            (src_dir / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            (src_dir / "backend" / "server.js").write_text("console.log('ok')\n", encoding="utf-8")
            (src_dir / ".DS_Store").write_bytes(b"junk")
            case["source_files"] = [{"path": src_dir.as_posix(), "name": "srcdir"}]
            case["metadata"]["验证状态"] = "通过"
            case["metadata"]["是否通过"] = "是"

            manifest = archive.create_archive_package(case, tmp_path / "archive")
            archive_dir = Path(manifest["archive_dir"])

            self.assertTrue((archive_dir / "题目源码" / "Dockerfile").exists())
            self.assertTrue((archive_dir / "题目源码" / "backend" / "server.js").exists())
            self.assertFalse((archive_dir / "题目源码" / ".DS_Store").exists())
            self.assertTrue(any(item["relative_path"] == "题目源码/Dockerfile" for item in manifest["files"]))

    def test_archive_package_dedupes_same_manual_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            case["metadata"]["验证状态"] = "通过"
            case["metadata"]["是否通过"] = "是"
            case["writeup"]["formal_manual_path"] = case["writeup"]["manual_path"]

            manifest = archive.create_archive_package(case, tmp_path / "archive")

        manual_files = [item for item in manifest["files"] if item["role"] == "writeup" and item["relative_path"].endswith("题目解题手册.md")]
        self.assertEqual(len(manual_files), 1)

    def test_archive_package_prefers_formal_manual_when_manual_path_differs(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            formal = tmp_path / "formal.md"
            formal.write_text("# formal manual\n", encoding="utf-8")
            case["writeup"]["formal_manual_path"] = formal.as_posix()

            manifest = archive.create_archive_package(case, tmp_path / "archive")
            archive_dir = Path(manifest["archive_dir"])
            manual_path = archive_dir / "题目手册" / "题目解题手册.md"
            manual_files = [item for item in manifest["files"] if item["role"] == "writeup" and item["relative_path"].endswith("题目解题手册.md")]

            self.assertEqual(len(manual_files), 1)
            self.assertEqual(manual_path.read_text(encoding="utf-8"), "# formal manual\n")
            self.assertTrue(any("manual_path ignored" in item for item in manifest.get("warnings", [])))

    def test_archive_package_does_not_mark_unverified_case_archived(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            manifest = archive.create_archive_package(case, tmp_path / "archive")
            updated = archive.apply_archive_outputs(case, manifest)

            self.assertEqual(manifest["xlsx_fields"]["是否归档"], "否")
            self.assertEqual(updated["metadata"]["是否归档"], "否")
            self.assertTrue(any("验证状态为未验证" in issue for issue in manifest["issues"]))
            self.assertTrue(any("是否通过为否" in issue for issue in manifest["issues"]))

    def test_archive_package_can_reference_image_tars_when_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            manifest = archive.create_archive_package(case, tmp_path / "archive", copy_image_tars=False)

            archive_dir = Path(manifest["archive_dir"])

            self.assertFalse((archive_dir / "题目镜像" / "web.tar").exists())
            image_records = [item for item in manifest["files"] if item["role"] == "image_tar"]
            self.assertEqual(image_records[0]["status"], "referenced")
            self.assertEqual(manifest["xlsx_fields"]["环境包/附件包路径"], case["docker_artifacts"]["tar_path"])

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
                hub_id_confirmed=True,
            )
            updated = retag.apply_retag_outputs(case, plan)

            self.assertEqual(plan["new_image"], "registry.local/cloversec/ctf-2026060001")
            self.assertEqual(plan["xlsx_fields"]["HUB编号"], "CTF-2026060001")
            self.assertIn("docker tag", plan["commands"]["tag"])
            self.assertEqual(updated["metadata"]["HUB编号"], "CTF-2026060001")
            self.assertEqual(updated["docker_artifacts"]["image_name"], "registry.local/cloversec/ctf-2026060001")

    def test_retag_agent_decision_rejects_null_boolean(self):
        invalid = retag.validate_agent_decision(
            {
                "can_execute": None,
                "requires_user_confirmation": True,
                "execute_docker": False,
                "next_action": "ask_user",
                "hub_id": "",
                "reason": "missing Hub id",
            }
        )
        valid = retag.validate_agent_decision(
            {
                "can_execute": False,
                "requires_user_confirmation": True,
                "execute_docker": False,
                "next_action": "ask_user",
                "hub_id": "",
                "reason": "missing Hub id",
            }
        )

        self.assertEqual(invalid["status"], "invalid")
        self.assertIn("can_execute must be boolean true/false", invalid["issues"])
        self.assertEqual(valid["status"], "valid")

    def test_final_outputs_write_xlsx_and_yuque_table_with_full_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            manifest = archive.create_archive_package(case, tmp_path / "archive")
            case = archive.apply_archive_outputs(case, manifest)
            quality = review.create_quality_review(case, archive_dir=manifest["archive_dir"])
            case = review.apply_review_outputs(case, quality)

            payload = final.create_final_outputs([case], tmp_path / "final")
            rows = data.read_xlsx(tmp_path / "final" / "最终归档表.xlsx")
            yuque = (tmp_path / "final" / "语雀粘贴表.md").read_text(encoding="utf-8")
            report = (tmp_path / "final" / "最终报告.md").read_text(encoding="utf-8")

            self.assertEqual(payload["summary"]["total"], 1)
            self.assertEqual(payload["summary"]["xlsx_readback_rows"], 1)
            self.assertEqual(payload["summary"]["human_handoff_paths"]["最终归档表"], (tmp_path / "final" / "最终归档表.xlsx").as_posix())
            self.assertEqual(payload["summary"]["human_handoff_paths"]["语雀粘贴表"], (tmp_path / "final" / "语雀粘贴表.md").as_posix())
            self.assertFalse((tmp_path / "final" / "archive.xlsx").exists())
            self.assertFalse((tmp_path / "final" / "yuque_table.md").exists())
            self.assertFalse((tmp_path / "final" / "final_report.md").exists())
            self.assertEqual(rows[0]["Flag"], "flag{stage-six-full-flag}")
            self.assertIn("flag{stage-six-full-flag}", yuque)
            self.assertIn("## 对人交付文件", report)
            self.assertIn("最终归档表.xlsx", report)
            self.assertGreater(payload["summary"]["remaining_actions"], 0)
            self.assertTrue(
                any("验证状态为部分通过" in item for item in payload["remaining_actions"])
            )
            self.assertTrue(any("缺少 HUB编号" in item for item in payload["remaining_actions"]))

    def test_final_outputs_report_xlsx_readback_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            expected = [{"名称": "Demo", "Flag": "flag{demo}", "验证状态": "通过"}]
            actual = [{"名称": "Demo", "Flag": "flag{changed}", "验证状态": "通过"}]
            errors = final.validate_final_xlsx_readback(expected, actual)

        self.assertTrue(errors)
        self.assertIn("Flag", errors[0])

    def test_final_outputs_resolves_relative_archive_paths_from_base_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            manifest = archive.create_archive_package(case, tmp_path / "archive")
            case = archive.apply_archive_outputs(case, manifest)
            archive_dir = Path(case["metadata"]["归档目录"])
            case["metadata"]["归档目录"] = archive_dir.relative_to(tmp_path).as_posix()
            case["metadata"]["HUB编号"] = "CTF-2026060001"
            case["metadata"]["验证状态"] = "通过"
            case["metadata"]["是否通过"] = "是"

            payload = final.create_final_outputs([case], tmp_path / "final", base_dir=tmp_path)

            self.assertFalse(
                any("归档目录不存在" in item for item in payload["remaining_actions"])
            )
            self.assertFalse(
                any("资源路径不存在" in item for item in payload["remaining_actions"])
            )

    def test_final_outputs_downgrades_pass_when_required_fields_are_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            case["metadata"]["验证状态"] = "通过"
            case["metadata"]["是否通过"] = "是"
            case["metadata"]["是否归档"] = "是"
            case["metadata"]["赛事来源"] = ""
            case["metadata"]["解题工具"] = ""
            case["metadata"]["归档目录"] = ""
            case["metadata"]["环境包/附件包路径"] = ""

            final.create_final_outputs([case], tmp_path / "final", base_dir=tmp_path)
            rows = data.read_xlsx(tmp_path / "final" / "最终归档表.xlsx")

            self.assertEqual(rows[0]["是否通过"], "否")
            self.assertEqual(rows[0]["是否归档"], "否")
            self.assertEqual(rows[0]["验证状态"], "部分通过")
            self.assertIn("缺少 赛事来源", rows[0]["问题"])

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

    def test_execute_docker_review_records_load_run_probe_and_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            case["docker_artifacts"]["ports"] = ["18080:80"]

            class Response:
                status = 200

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            def fake_run(args, **kwargs):
                if args[:3] == ["docker", "image", "inspect"]:
                    stdout = '[{"Os":"linux","Architecture":"amd64"}]'
                elif args[:2] == ["docker", "logs"]:
                    stdout = "service ready\n"
                elif args[:2] == ["docker", "run"]:
                    stdout = "container-id\n"
                else:
                    stdout = "ok\n"
                return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

            with mock.patch.object(review.subprocess, "run", side_effect=fake_run):
                with mock.patch.object(review.time, "sleep", return_value=None):
                    with mock.patch.object(review.http, "http_get", return_value={"status": 200}):
                        evidence = review.execute_docker_review(case, tmp_path / "quality", startup_wait=0)

            self.assertEqual(evidence["summary"]["status"], "pass")
            self.assertTrue(evidence["summary"]["run_verified"])
            self.assertEqual(evidence["summary"]["platform"], "linux/amd64")
            self.assertTrue((tmp_path / "quality" / "docker_logs.txt").exists())

            result = review.create_quality_review(case, docker_execution=evidence)
            by_id = {item["id"]: item for item in result["checks"]}
            self.assertEqual(by_id["docker-run"]["status"], "pass")
            self.assertEqual(by_id["docker-port-probe"]["status"], "pass")

    def test_retag_execute_records_tar_hash_and_platform(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            plan = retag.create_retag_plan(case, "CTF-2026060001", tmp_path / "retagged", hub_id_confirmed=True)

            def fake_run(args, **kwargs):
                if args[:2] == ["docker", "save"]:
                    Path(args[-1]).write_bytes(b"image-tar")
                if args[:3] == ["docker", "image", "inspect"]:
                    stdout = '[{"Os":"linux","Architecture":"amd64"}]'
                else:
                    stdout = "ok\n"
                return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

            with mock.patch.object(retag.subprocess, "run", side_effect=fake_run):
                execution = retag.execute_retag_plan(plan)
            plan["execution"] = execution
            updated = retag.apply_retag_outputs(case, plan)

            self.assertEqual(execution["summary"]["status"], "pass")
            self.assertEqual(execution["summary"]["platform"], "linux/amd64")
            self.assertEqual(len(execution["summary"]["tar_sha256"]), 64)
            self.assertEqual(updated["docker_artifacts"]["sha256"], execution["summary"]["tar_sha256"])

    def test_batch_archive_writes_updated_cases_and_final_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            cases_path = tmp_path / "ctf_cases.jsonl"
            cases_path.write_text(json.dumps(case, ensure_ascii=False) + "\n", encoding="utf-8")

            code = archive.main([
                "batch",
                "--cases",
                str(cases_path),
                "--output-root",
                str(tmp_path / "archive"),
                "--output-cases",
                str(tmp_path / "ctf_cases.archived.jsonl"),
                "--final-output-dir",
                str(tmp_path / "final"),
            ])

            self.assertEqual(code, 0)
            self.assertTrue((tmp_path / "archive" / "_cache" / "batch_archive_summary.json").exists())
            self.assertTrue((tmp_path / "archive" / "_cache" / "batch_archive_report.md").exists())
            self.assertTrue((tmp_path / "ctf_cases.archived.jsonl").exists())
            self.assertTrue((tmp_path / "final" / "最终归档表.xlsx").exists())
            self.assertFalse((tmp_path / "final" / "archive.xlsx").exists())

    def test_archive_runner_writes_resource_index_missing_report_and_final_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            cases_path = tmp_path / "ctf_cases.jsonl"
            cases_path.write_text(json.dumps(case, ensure_ascii=False) + "\n", encoding="utf-8")

            payload = archive_runner.run_archive_workflow(
                cases_path=cases_path,
                output_root=tmp_path / "archive-workflow",
            )

            self.assertEqual(payload["summary"]["cases"], 1)
            self.assertGreater(payload["summary"]["resource_count"], 0)
            self.assertTrue(Path(payload["paths"]["resource_index"]).exists())
            self.assertTrue(Path(payload["paths"]["missing_report"]).exists())
            self.assertTrue(Path(payload["summary"]["final_xlsx"]).exists())
            self.assertTrue(Path(payload["summary"]["yuque_table"]).exists())

    def test_fixture_missing_screenshot_is_reported_by_archive_and_quality(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cases = data.load_cases(ROOT / "tests" / "fixtures" / "ctf_cases.jsonl")
            selected = [case for case in cases if case["case_id"] == "fixture-missing-screenshot"]
            cases_path = tmp_path / "ctf_cases.jsonl"
            cases_path.write_text("".join(json.dumps(case, ensure_ascii=False) + "\n" for case in selected), encoding="utf-8")

            archive_payload = archive_runner.run_archive_workflow(
                cases_path=cases_path,
                output_root=tmp_path / "archive",
                output_cases=tmp_path / "ctf_cases.archived.jsonl",
                final_output_dir=tmp_path / "final",
            )
            quality_payload = quality_runner.run_quality_batch(
                cases_path=tmp_path / "ctf_cases.archived.jsonl",
                output_dir=tmp_path / "quality",
                output_cases=tmp_path / "ctf_cases.reviewed.jsonl",
            )
            reviewed_case = data.load_cases(tmp_path / "ctf_cases.reviewed.jsonl")[0]
            review_checks = {item["id"]: item for item in reviewed_case["review"]["checks"]}
            archive_summary = json.loads((tmp_path / "archive" / "_cache" / "batch_archive_summary.json").read_text(encoding="utf-8"))

            self.assertEqual(archive_payload["archive_summary"]["with_issues"], 1)
            self.assertEqual(review_checks["screenshot-files"]["status"], "fail")
            self.assertIn("缺少截图", review_checks["screenshot-files"]["message"])
            self.assertGreaterEqual(quality_payload["summary"]["with_failures"], 1)

    def test_delivery_package_writes_chinese_handoff_and_copies_image_tars(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workdir = tmp_path / "work" / "ctf-2026-collection"
            outputs = tmp_path / "outputs"
            workdir.mkdir(parents=True)
            outputs.mkdir()
            (outputs / "ctf_2026_10_after_docker_final_archive.xlsx").write_bytes(b"xlsx")
            (outputs / "ctf_2026_10_completed_final_archive.xlsx").write_bytes(b"completed-xlsx")
            (outputs / "ctf_2026_10_after_docker_yuque_table.md").write_text("| 题目 |\n", encoding="utf-8")
            (outputs / "ctf_2026_10_completed_yuque_table.md").write_text("| 完成版 |\n", encoding="utf-8")
            archive_dir = workdir / "archive" / "Web-EZSmuggler"
            (archive_dir / "题目源码").mkdir(parents=True)
            (archive_dir / "题目镜像").mkdir()
            (archive_dir / "题目手册").mkdir()
            (archive_dir / "题目源码" / "Dockerfile").write_text("FROM node:20\n", encoding="utf-8")
            (archive_dir / "题目源码" / "start.sh").write_text("#!/bin/bash\nnode backend/server.js\n", encoding="utf-8")
            (archive_dir / "题目源码" / "flag").write_text("flag{demo}\n", encoding="utf-8")
            (archive_dir / "题目手册" / "WEB-EZsmuggler.md").write_text("## 1 题目设计部署信息\n\n## 2 HUB上传部分&题解信息\n", encoding="utf-8")
            image_tar = archive_dir / "题目镜像" / "l7-smuggler_latest.tar"
            image_tar.write_bytes(b"tar")
            (archive_dir / ".DS_Store").write_bytes(b"mac")

            manifest = delivery.create_delivery_package(workdir=workdir, outputs_dir=outputs, output_dir=tmp_path / "交付包")

            delivery_dir = Path(manifest["paths"]["delivery_dir"])
            self.assertTrue((delivery_dir / "交付说明.md").exists())
            self.assertFalse((delivery_dir / "交付清单.json").exists())
            self.assertTrue((delivery_dir / "最终归档表.xlsx").exists())
            self.assertTrue((delivery_dir / "语雀粘贴表.md").exists())
            self.assertEqual((delivery_dir / "最终归档表.xlsx").read_bytes(), b"completed-xlsx")
            self.assertTrue((delivery_dir / "Web-EZSmuggler" / "题目源码" / "Dockerfile").exists())
            self.assertTrue((delivery_dir / "Web-EZSmuggler" / "题目手册" / "题目解题手册.md").exists())
            self.assertEqual(manifest["summary"]["package_issues"], 0)
            self.assertTrue((delivery_dir / "Web-EZSmuggler" / "题目镜像" / "l7-smuggler_latest.tar").exists())
            self.assertFalse(any(path.name == ".DS_Store" for path in delivery_dir.rglob("*")))
            self.assertFalse(any(path.suffix in {".json", ".jsonl"} for path in delivery_dir.rglob("*") if path.is_file()))
            self.assertEqual({path.name for path in delivery_dir.iterdir() if path.is_file()}, {"最终归档表.xlsx", "语雀粘贴表.md", "交付说明.md", "待处理问题.md", "质量检查报告.md"})
            self.assertFalse(any(path.name.startswith(("01-", "02-", "03-", "04-", "05-", "06-", "07-", "99-")) for path in delivery_dir.iterdir()))
            self.assertTrue(any(item["status"] == "copied" and item.get("subdir") == "题目镜像" for item in manifest["files"]))

    def test_delivery_package_allows_source_json_but_blocks_manual_drafts(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workdir = tmp_path / "work"
            outputs = tmp_path / "outputs"
            workdir.mkdir()
            outputs.mkdir()
            (outputs / "最终归档表.xlsx").write_bytes(b"xlsx")
            (outputs / "语雀粘贴表.md").write_text("| 题目 |\n", encoding="utf-8")
            archive_dir = workdir / "archive" / "Web-PasswordManager"
            (archive_dir / "题目源码").mkdir(parents=True)
            (archive_dir / "题目镜像").mkdir()
            (archive_dir / "题目手册").mkdir()
            (archive_dir / "题目源码" / "package.json").write_text('{"scripts":{"start":"node app.js"}}\n', encoding="utf-8")
            (archive_dir / "题目源码" / "Dockerfile").write_text("FROM node:20\n", encoding="utf-8")
            (archive_dir / "题目镜像" / "password-manager.tar").write_bytes(b"tar")
            (archive_dir / "题目手册" / "题目解题手册.md").write_text("# 题目解题手册\n", encoding="utf-8")
            (archive_dir / "题目手册" / "manual_filled_draft.md").write_text("# draft\n", encoding="utf-8")

            manifest = delivery.create_delivery_package(workdir=workdir, outputs_dir=outputs, output_dir=tmp_path / "交付包")

        delivery_dir = Path(manifest["paths"]["delivery_dir"])
        issues = {item["path"]: item["issue"] for item in manifest["package_issues"]}
        self.assertNotIn("Web-PasswordManager/题目源码/package.json", issues)
        self.assertFalse((delivery_dir / "Web-PasswordManager" / "题目手册" / "manual_filled_draft.md").exists())
        self.assertNotIn("Web-PasswordManager/题目手册/manual_filled_draft.md", issues)

    def test_delivery_package_flattens_raw_archive_and_renames_manual_for_humans(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            raw_output = tmp_path / "jsfs-cratectf-2024-platform"
            raw_output.mkdir()
            (raw_output / ".DS_Store").write_bytes(b"mac")
            archive_dir = raw_output / "archive" / "Pwn-JSFS"
            (archive_dir / "题目源码").mkdir(parents=True)
            (archive_dir / "题目镜像").mkdir()
            (archive_dir / "题目手册").mkdir()
            (archive_dir / "题目源码" / "Dockerfile").write_text("FROM oven/bun:latest\n", encoding="utf-8")
            (archive_dir / "题目镜像" / "jsfs.tar").write_bytes(b"tar")
            (archive_dir / "题目手册" / "PWN-JSFS.md").write_text("# JSFS\n", encoding="utf-8")
            (archive_dir / ".DS_Store").write_bytes(b"mac")
            (raw_output / "archive" / "_cache" / "Pwn-JSFS").mkdir(parents=True)
            (raw_output / "archive" / "_cache" / "Pwn-JSFS" / "archive_manifest.json").write_text("{}", encoding="utf-8")
            archived_case = sample_case(tmp_path)
            archived_case["case_id"] = "jsfs"
            archived_case["metadata"]["名称"] = "JSFS"
            archived_case["metadata"]["分类"] = "Pwn"
            archived_case["metadata"]["归档目录"] = archive_dir.as_posix()
            archived_case["metadata"]["验证状态"] = "通过"
            archived_case["metadata"]["是否通过"] = "是"
            archived_case["metadata"]["是否归档"] = "是"
            archived_case["metadata"]["环境包/附件包路径"] = "题目镜像/jsfs.tar"
            (raw_output / "jsfs_ctf_case.archived.json").write_text(json.dumps(archived_case, ensure_ascii=False), encoding="utf-8")

            manifest = delivery.create_delivery_package(workdir=raw_output, outputs_dir=raw_output, output_dir=tmp_path / "最终交付")
            zip_manifest = delivery.create_delivery_zip(manifest["paths"]["delivery_dir"], tmp_path / "最终交付.zip")

            delivery_dir = Path(manifest["paths"]["delivery_dir"])
            self.assertTrue((delivery_dir / "最终归档表.xlsx").exists())
            self.assertTrue((delivery_dir / "语雀粘贴表.md").exists())
            self.assertTrue((delivery_dir / "Pwn-JSFS" / "题目源码" / "Dockerfile").exists())
            self.assertTrue((delivery_dir / "Pwn-JSFS" / "题目镜像" / "jsfs.tar").exists())
            self.assertTrue((delivery_dir / "Pwn-JSFS" / "题目手册" / "题目解题手册.md").exists())
            self.assertFalse((delivery_dir / "archive").exists())
            self.assertFalse((delivery_dir / "_cache").exists())
            self.assertFalse(any(path.name == ".DS_Store" for path in delivery_dir.rglob("*")))
            self.assertEqual(manifest["summary"]["package_issues"], 0)
            with zipfile.ZipFile(zip_manifest["zip_path"]) as archive_file:
                names = archive_file.namelist()
            self.assertIn("Pwn-JSFS/题目手册/题目解题手册.md", names)
            self.assertFalse(any(name.startswith("__MACOSX/") or name.endswith(".DS_Store") or "/_cache/" in name for name in names))

    def test_delivery_package_normalizes_handmade_wrong_delivery_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workdir = tmp_path / "thread"
            outputs = workdir / "outputs"
            wrong = outputs / "WarmUp_正式交付"
            workdir.mkdir()
            (wrong / "容器交付件" / "app").mkdir(parents=True)
            (wrong / "镜像包").mkdir()
            (wrong / "录题字段").mkdir()
            (wrong / "验证记录").mkdir()
            (wrong / "容器交付件" / "Dockerfile").write_text("FROM php:7.4-apache\n", encoding="utf-8")
            (wrong / "容器交付件" / "start.sh").write_text("#!/bin/bash\napache2-foreground\n", encoding="utf-8")
            (wrong / "容器交付件" / "changeflag.sh").write_text("#!/bin/bash\ncat \"$1\" > /flag\n", encoding="utf-8")
            (wrong / "容器交付件" / "flag").write_text("csictf{typ3_juggl1ng_1n_php}\n", encoding="utf-8")
            (wrong / "容器交付件" / "app" / "index.php").write_text("<?php echo 'ok';\n", encoding="utf-8")
            (wrong / "镜像包" / "warm-up-php74-amd64.tar").write_bytes(b"tar")
            (wrong / "题目手册-正式.md").write_text("# Warm Up\n\n## 1 题目设计部署信息\n\n## 2 HUB上传部分&题解信息\n", encoding="utf-8")
            (wrong / "录题字段" / "xlsx_fields.json").write_text(
                json.dumps(
                    {
                        "名称": "Warm Up",
                        "分类": "Web",
                        "题目类型": "环境型",
                        "Flag类型": "静态Flag",
                        "Flag": "csictf{typ3_juggl1ng_1n_php}",
                        "环境包/附件包路径": "镜像包/warm-up-php74-amd64.tar",
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            manifest = delivery.create_delivery_package(workdir=workdir, outputs_dir=outputs, output_dir=outputs / "最终交付包")

            delivery_dir = Path(manifest["paths"]["delivery_dir"])
            self.assertTrue((delivery_dir / "交付说明.md").exists())
            self.assertTrue((delivery_dir / "最终归档表.xlsx").exists())
            self.assertTrue((delivery_dir / "语雀粘贴表.md").exists())
            self.assertTrue((delivery_dir / "Web-Warm Up" / "题目源码" / "Dockerfile").exists())
            self.assertTrue((delivery_dir / "Web-Warm Up" / "题目镜像" / "warm-up-php74-amd64.tar").exists())
            self.assertTrue((delivery_dir / "Web-Warm Up" / "题目手册" / "题目解题手册.md").exists())
            self.assertFalse((delivery_dir / "WarmUp_正式交付").exists())
            self.assertFalse((delivery_dir / "Web-Warm Up" / "录题字段").exists())
            rows = data.read_xlsx(delivery_dir / "最终归档表.xlsx")
            self.assertEqual(rows[0]["名称"], "Warm Up")
            self.assertEqual(rows[0]["环境包/附件包路径"], "题目镜像/warm-up-php74-amd64.tar")
            self.assertEqual(manifest["summary"]["package_issues"], 0)

    def test_delivery_scan_rejects_handmade_wrong_delivery_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            wrong = Path(tmp) / "WarmUp_正式交付"
            (wrong / "容器交付件").mkdir(parents=True)
            (wrong / "镜像包").mkdir()
            (wrong / "录题字段").mkdir()
            (wrong / "验证记录").mkdir()
            (wrong / "题目手册-正式.md").write_text("# 手册\n", encoding="utf-8")

            issues = delivery.scan_delivery_package(wrong)

            issue_paths = {item["path"] for item in issues}
            self.assertIn("容器交付件", issue_paths)
            self.assertIn("录题字段", issue_paths)
            self.assertIn("验证记录", issue_paths)

    def test_delivery_package_rejects_output_dir_that_would_delete_workdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw_output = Path(tmp) / "jsfs-cratectf-2024-platform"
            raw_output.mkdir()
            (raw_output / "archive" / "Pwn-JSFS" / "题目源码").mkdir(parents=True)

            with self.assertRaises(ValueError):
                delivery.create_delivery_package(workdir=raw_output, outputs_dir=raw_output, output_dir=raw_output)

            self.assertTrue((raw_output / "archive" / "Pwn-JSFS" / "题目源码").exists())

    def test_archive_package_creates_visible_dirs_and_placeholder_manual_when_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            case["writeup"] = {}
            case["source_files"] = []
            case["attachments"] = []
            case["docker_artifacts"]["tar_path"] = ""

            manifest = archive.create_archive_package(case, tmp_path / "归档")

            archive_dir = Path(manifest["archive_dir"])
            self.assertTrue((archive_dir / "题目源码").is_dir())
            self.assertTrue((archive_dir / "题目镜像").is_dir())
            self.assertTrue((archive_dir / "题目手册" / "题目解题手册.md").exists())
            self.assertIn("missing writeup", "\n".join(manifest["issues"]))
            self.assertEqual(manifest["xlsx_fields"]["是否归档"], "否")

    def test_delivery_package_keeps_official_handout_tar_gz_as_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workdir = tmp_path / "work"
            outputs = tmp_path / "outputs"
            workdir.mkdir()
            outputs.mkdir()
            (outputs / "最终归档表.xlsx").write_bytes(b"xlsx")
            (outputs / "语雀粘贴表.md").write_text("| 题目 |\n", encoding="utf-8")
            archive_dir = workdir / "archive" / "Web-Password Manager"
            (archive_dir / "题目源码").mkdir(parents=True)
            (archive_dir / "题目镜像").mkdir()
            (archive_dir / "题目手册").mkdir()
            handout = archive_dir / "题目源码" / "password-manager.tar.gz"
            inner = tmp_path / "README.md"
            inner.write_text("# handout\n", encoding="utf-8")
            with tarfile.open(handout, "w:gz") as package:
                package.add(inner, arcname="README.md")
            docker_like = archive_dir / "题目源码" / "docker-image.tar"
            with tarfile.open(docker_like, "w") as package:
                package.add(inner, arcname="manifest.json")
                package.add(inner, arcname="repositories")
                package.add(inner, arcname="layer/layer.tar")
            (archive_dir / "题目镜像" / "password-manager-amd64.tar").write_bytes(b"image-tar")
            (archive_dir / "题目手册" / "题目解题手册.md").write_text("# 手册\n", encoding="utf-8")

            manifest = delivery.create_delivery_package(workdir=workdir, outputs_dir=outputs, output_dir=tmp_path / "交付包")

            delivery_dir = Path(manifest["paths"]["delivery_dir"])
            challenge_dir = delivery_dir / "Web-Password Manager"
            self.assertTrue((challenge_dir / "题目源码" / "password-manager.tar.gz").exists())
            self.assertFalse((challenge_dir / "题目源码" / "docker-image.tar").exists())
            self.assertEqual(manifest["summary"]["package_issues"], 0)

    def test_delivery_package_default_output_dir_is_chinese_final_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workdir = tmp_path / "work"
            outputs = tmp_path / "outputs"
            workdir.mkdir()
            outputs.mkdir()

            manifest = delivery.create_delivery_package(workdir=workdir, outputs_dir=outputs)

            delivery_dir = Path(manifest["paths"]["delivery_dir"])
            self.assertEqual(delivery_dir.name, "最终交付包")
            self.assertTrue((delivery_dir / "交付说明.md").exists())
            self.assertFalse((outputs / f"交付包-{workdir.name}").exists())

    def test_delivery_package_does_not_include_process_evidence_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workdir = tmp_path / "work"
            outputs = tmp_path / "outputs"
            workdir.mkdir()
            outputs.mkdir()
            (outputs / "最终归档表.xlsx").write_bytes(b"xlsx")
            (outputs / "语雀粘贴表.md").write_text("| 题目 |\n", encoding="utf-8")
            (workdir / "workflow_state.json").write_text("{}", encoding="utf-8")

            manifest = delivery.create_delivery_package(workdir=workdir, outputs_dir=outputs, output_dir=tmp_path / "交付包")

            delivery_dir = Path(manifest["paths"]["delivery_dir"])
            self.assertFalse((delivery_dir / "过程证据").exists())
            self.assertEqual(manifest["process_evidence"]["machine_files"], 0)
            self.assertEqual(manifest["summary"]["package_issues"], 0)

    def test_delivery_package_can_include_process_evidence_when_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workdir = tmp_path / "work"
            outputs = tmp_path / "outputs"
            workdir.mkdir()
            outputs.mkdir()
            (outputs / "最终归档表.xlsx").write_bytes(b"xlsx")
            (outputs / "语雀粘贴表.md").write_text("| 题目 |\n", encoding="utf-8")
            (workdir / "workflow_state.json").write_text("{}", encoding="utf-8")

            manifest = delivery.create_delivery_package(
                workdir=workdir,
                outputs_dir=outputs,
                output_dir=tmp_path / "交付包",
                include_process_evidence=True,
            )

            delivery_dir = Path(manifest["paths"]["delivery_dir"])
            self.assertTrue((delivery_dir / "过程证据" / "机器数据" / "workdir" / "workflow_state.json").exists())
            self.assertEqual(manifest["summary"]["package_issues"], 0)

    def test_delivery_scan_removes_macos_metadata_before_reporting(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            delivery_dir = tmp_path / "outputs"
            challenge_dir = delivery_dir / "Web-Natural Prompt"
            (challenge_dir / "题目源码").mkdir(parents=True)
            (challenge_dir / "题目镜像").mkdir()
            (challenge_dir / "题目手册").mkdir()
            (delivery_dir / "交付说明.md").write_text("# 交付说明\n", encoding="utf-8")
            (delivery_dir / "最终归档表.xlsx").write_bytes(b"xlsx")
            (delivery_dir / "语雀粘贴表.md").write_text("", encoding="utf-8")
            (delivery_dir / "待处理问题.md").write_text("", encoding="utf-8")
            (delivery_dir / "质量检查报告.md").write_text("", encoding="utf-8")
            (delivery_dir / ".DS_Store").write_bytes(b"mac")
            (challenge_dir / ".DS_Store").write_bytes(b"mac")

            issues = delivery.scan_delivery_package(delivery_dir)

            self.assertFalse((delivery_dir / ".DS_Store").exists())
            self.assertFalse((challenge_dir / ".DS_Store").exists())
            self.assertFalse(any(item["path"].endswith(".DS_Store") for item in issues))

    def test_delivery_scan_blocks_quality_and_metadata_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            delivery_dir = Path(tmp) / "outputs"
            delivery_dir.mkdir()
            for name in ["_quality", "元数据", "manifests"]:
                (delivery_dir / name).mkdir()
                (delivery_dir / name / "report.json").write_text("{}", encoding="utf-8")

            issues = delivery.scan_delivery_package(delivery_dir)

            issue_paths = {item["path"] for item in issues}
            self.assertIn("_quality", issue_paths)
            self.assertIn("元数据", issue_paths)
            self.assertIn("manifests", issue_paths)

    def test_delivery_scan_allows_container_challenge_with_attachment_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            delivery_dir = Path(tmp) / "outputs"
            challenge = delivery_dir / "Pwn-JSFS"
            (challenge / "题目源码").mkdir(parents=True)
            (challenge / "题目镜像").mkdir()
            (challenge / "题目手册").mkdir()
            (challenge / "题目附件").mkdir()
            (challenge / "题目源码" / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            (challenge / "题目镜像" / "jsfs.tar").write_bytes(b"tar")
            (challenge / "题目手册" / "题目解题手册.md").write_text("# 手册\n", encoding="utf-8")
            (challenge / "题目附件" / "handout.zip").write_bytes(b"zip")
            for filename in ["交付说明.md", "语雀粘贴表.md", "待处理问题.md", "质量检查报告.md"]:
                (delivery_dir / filename).write_text("# ok\n", encoding="utf-8")
            (delivery_dir / "最终归档表.xlsx").write_bytes(b"xlsx")

            issues = delivery.scan_delivery_package(delivery_dir)

            self.assertEqual(issues, [])

    def test_delivery_scan_rejects_container_attachment_that_duplicates_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            delivery_dir = Path(tmp) / "outputs"
            challenge = delivery_dir / "Pwn-JSFS"
            (challenge / "题目源码" / "app").mkdir(parents=True)
            (challenge / "题目镜像").mkdir()
            (challenge / "题目手册").mkdir()
            (challenge / "题目附件" / "app").mkdir(parents=True)
            (challenge / "题目源码" / "app" / "server.js").write_text("console.log('same')\n", encoding="utf-8")
            (challenge / "题目附件" / "app" / "server.js").write_text("console.log('same')\n", encoding="utf-8")
            (challenge / "题目附件" / "solve.py").write_text("print('debug exploit')\n", encoding="utf-8")
            (challenge / "题目镜像" / "jsfs.tar").write_bytes(b"tar")
            (challenge / "题目手册" / "题目解题手册.md").write_text("# 手册\n", encoding="utf-8")
            for filename in ["交付说明.md", "语雀粘贴表.md", "待处理问题.md", "质量检查报告.md"]:
                (delivery_dir / filename).write_text("# ok\n", encoding="utf-8")
            (delivery_dir / "最终归档表.xlsx").write_bytes(b"xlsx")

            issues = delivery.scan_delivery_package(delivery_dir)

            issue_paths = {item["path"] for item in issues}
            self.assertIn("Pwn-JSFS/题目附件/app/server.js", issue_paths)
            self.assertFalse(any(item["path"].endswith("solve.py") for item in issues))

    def test_delivery_package_skips_legacy_attachment_files_that_duplicate_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workdir = tmp_path / "crator"
            outputs = tmp_path / "outputs"
            workdir.mkdir()
            outputs.mkdir()
            (outputs / "最终归档表.xlsx").write_bytes(b"xlsx")
            (outputs / "语雀粘贴表.md").write_text("| 题目 |\n", encoding="utf-8")
            (workdir / "ctf_case.json").write_text(json.dumps({"metadata": {"分类": "Web", "名称": "crator"}}, ensure_ascii=False), encoding="utf-8")
            source = workdir / "dockerizer_work"
            attachment = workdir / "题目附件"
            (source / "app").mkdir(parents=True)
            (attachment / "app").mkdir(parents=True)
            (source / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            (source / "start.sh").write_text("#!/bin/bash\n/app/run\n", encoding="utf-8")
            (source / "changeflag.sh").write_text("#!/bin/bash\ncat \"$1\" > /flag\n", encoding="utf-8")
            (source / "flag").write_text("flag{demo}\n", encoding="utf-8")
            (source / "app" / "server.js").write_text("console.log('same')\n", encoding="utf-8")
            (attachment / "app" / "server.js").write_text("console.log('same')\n", encoding="utf-8")
            (attachment / "solve.py").write_text("print('debug exploit')\n", encoding="utf-8")
            (workdir / "题目镜像").mkdir()
            (workdir / "题目镜像" / "crator.tar").write_bytes(b"tar")
            (workdir / "手册").mkdir()
            (workdir / "手册" / "题目解题手册.md").write_text("# 题目解题手册\n", encoding="utf-8")

            manifest = delivery.create_delivery_package(workdir=workdir, outputs_dir=outputs, output_dir=tmp_path / "交付包")

            delivery_dir = Path(manifest["paths"]["delivery_dir"])
            challenge_dir = delivery_dir / "Web-crator"
            self.assertFalse((challenge_dir / "题目附件" / "app" / "server.js").exists())
            self.assertTrue((challenge_dir / "题目附件" / "solve.py").exists())
            self.assertEqual(manifest["summary"]["package_issues"], 0)

    def test_delivery_zip_uses_sibling_path_and_utf8_chinese_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            delivery_dir = Path(tmp) / "最终交付"
            challenge = delivery_dir / "Web-中文题"
            (challenge / "题目附件").mkdir(parents=True)
            (challenge / "题目手册").mkdir()
            (challenge / "题目附件" / "附件.txt").write_text("demo\n", encoding="utf-8")
            (challenge / "题目手册" / "题目解题手册.md").write_text("# 手册\n", encoding="utf-8")
            for filename in ["交付说明.md", "语雀粘贴表.md", "待处理问题.md", "质量检查报告.md"]:
                (delivery_dir / filename).write_text("# ok\n", encoding="utf-8")
            (delivery_dir / "最终归档表.xlsx").write_bytes(b"xlsx")
            (delivery_dir / ".DS_Store").write_bytes(b"mac")

            zip_manifest = delivery.create_delivery_zip(delivery_dir)

            zip_path = Path(zip_manifest["zip_path"])
            self.assertEqual(zip_path.parent, delivery_dir.parent)
            self.assertFalse(zip_path.as_posix().startswith(delivery_dir.as_posix() + "/"))
            with zipfile.ZipFile(zip_path) as archive_file:
                names = archive_file.namelist()
            self.assertIn("最终归档表.xlsx", names)
            self.assertIn("Web-中文题/题目附件/附件.txt", names)
            self.assertFalse(any(".DS_Store" in name or name.startswith("__MACOSX/") for name in names))

    def test_delivery_cli_scan_reports_json_and_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            delivery_dir = Path(tmp) / "交付"
            delivery_dir.mkdir()
            (delivery_dir / "README.md").write_text("# wrong\n", encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "cloversec_ctf_delivery.py"),
                    "scan",
                    str(delivery_dir),
                    "--json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 1)
            payload = json.loads(result.stdout)
            self.assertGreater(payload["issue_count"], 0)

    def test_delivery_package_only_keeps_formal_manual_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workdir = tmp_path / "work"
            outputs = tmp_path / "outputs"
            workdir.mkdir()
            outputs.mkdir()
            (outputs / "最终归档表.xlsx").write_bytes(b"xlsx")
            (outputs / "语雀粘贴表.md").write_text("| 题目 |\n", encoding="utf-8")
            archive_dir = workdir / "archive" / "Web-Demo"
            (archive_dir / "题目源码").mkdir(parents=True)
            (archive_dir / "题目镜像").mkdir()
            manual_dir = archive_dir / "题目手册"
            (manual_dir / "Hub提交材料").mkdir(parents=True)
            (archive_dir / "题目源码" / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            (archive_dir / "题目镜像" / "demo.tar").write_bytes(b"tar")
            (manual_dir / "题目解题手册.md").write_text("# 正式手册\n", encoding="utf-8")
            (manual_dir / "Hub提交材料" / "hub_fields.json").write_text("{}", encoding="utf-8")
            (manual_dir / "Hub提交材料" / "browser_assist_plan.md").write_text("# 过程材料\n", encoding="utf-8")

            manifest = delivery.create_delivery_package(workdir=workdir, outputs_dir=outputs, output_dir=tmp_path / "交付包")

            delivery_dir = Path(manifest["paths"]["delivery_dir"])
            self.assertTrue((delivery_dir / "Web-Demo" / "题目手册" / "题目解题手册.md").exists())
            self.assertFalse((delivery_dir / "Web-Demo" / "题目手册" / "Hub提交材料").exists())
            self.assertEqual(manifest["summary"]["package_issues"], 0)

    def test_delivery_scan_rejects_process_dirs_inside_manual_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            delivery_dir = Path(tmp) / "outputs"
            challenge = delivery_dir / "Web-zoo-feedback-form"
            (challenge / "题目源码").mkdir(parents=True)
            (challenge / "题目镜像").mkdir()
            (challenge / "题目手册" / "Hub提交材料").mkdir(parents=True)
            (challenge / "题目手册" / "验证证据").mkdir()
            (challenge / "题目源码" / "Dockerfile").write_text("FROM python:3.11\n", encoding="utf-8")
            (challenge / "题目镜像" / "zoo-feedback-form-amd64.tar").write_bytes(b"tar")
            (challenge / "题目手册" / "题目解题手册.md").write_text("# 手册\n", encoding="utf-8")
            (challenge / "题目手册" / "Hub提交材料" / "hub_fields.json").write_text("{}", encoding="utf-8")
            for filename in ["交付说明.md", "语雀粘贴表.md", "待处理问题.md", "质量检查报告.md"]:
                (delivery_dir / filename).write_text("# ok\n", encoding="utf-8")
            (delivery_dir / "最终归档表.xlsx").write_bytes(b"xlsx")

            issues = delivery.scan_delivery_package(delivery_dir)

            paths = {item["path"] for item in issues}
            self.assertIn("Web-zoo-feedback-form/题目手册/Hub提交材料", paths)
            self.assertIn("Web-zoo-feedback-form/题目手册/验证证据", paths)

    def test_delivery_zip_refuses_dirty_human_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            delivery_dir = Path(tmp) / "outputs"
            challenge = delivery_dir / "Web-zoo-feedback-form"
            (challenge / "题目源码").mkdir(parents=True)
            (challenge / "题目镜像").mkdir()
            (challenge / "题目手册" / "验证证据").mkdir(parents=True)
            (challenge / "题目源码" / "Dockerfile").write_text("FROM python:3.11\n", encoding="utf-8")
            (challenge / "题目镜像" / "zoo-feedback-form-amd64.tar").write_bytes(b"tar")
            (challenge / "题目手册" / "题目解题手册.md").write_text("# 手册\n", encoding="utf-8")
            for filename in ["交付说明.md", "语雀粘贴表.md", "待处理问题.md", "质量检查报告.md"]:
                (delivery_dir / filename).write_text("# ok\n", encoding="utf-8")
            (delivery_dir / "最终归档表.xlsx").write_bytes(b"xlsx")

            with self.assertRaises(ValueError):
                delivery.create_delivery_zip(delivery_dir, Path(tmp) / "outputs.zip")

    def test_delivery_package_same_outputs_dir_does_not_write_cache_to_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workdir = tmp_path / "work"
            outputs = tmp_path / "outputs"
            workdir.mkdir()
            outputs.mkdir()
            archived_case = sample_case(tmp_path)
            archived_case["metadata"]["名称"] = "Natural Prompt"
            archived_case["metadata"]["分类"] = "Web"
            (workdir / "ctf_case.archived.json").write_text(json.dumps(archived_case, ensure_ascii=False), encoding="utf-8")

            manifest = delivery.create_delivery_package(workdir=workdir, outputs_dir=outputs, output_dir=outputs)

            self.assertEqual(Path(manifest["paths"]["delivery_dir"]), outputs)
            self.assertTrue((outputs / "最终归档表.xlsx").exists())
            self.assertTrue((outputs / "语雀粘贴表.md").exists())
            self.assertFalse((outputs / "_cache").exists())
            self.assertFalse((outputs / "_delivery_cache").exists())
            self.assertFalse(any(path.name in {"_cache", "_delivery_cache"} for path in outputs.rglob("*")))

    def test_delivery_package_reorganizes_legacy_single_challenge_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workdir = tmp_path / "irisctf-2025-password-manager"
            outputs = tmp_path / "outputs"
            workdir.mkdir()
            outputs.mkdir()
            (outputs / "最终归档表.xlsx").write_bytes(b"xlsx")
            (outputs / "语雀粘贴表.md").write_text("| 题目 |\n", encoding="utf-8")
            (workdir / "ctf_case.json").write_text(
                json.dumps({"metadata": {"分类": "Web", "名称": "Password Manager"}}, ensure_ascii=False),
                encoding="utf-8",
            )
            source = workdir / "dockerizer_work"
            (source / ".ctfbuild").mkdir(parents=True)
            (source / "verification").mkdir()
            (source / "src").mkdir()
            (source / "Dockerfile").write_text("FROM golang:1.22\n", encoding="utf-8")
            (source / "start.sh").write_text("#!/bin/bash\n/app/main\n", encoding="utf-8")
            (source / "changeflag.sh").write_text("#!/bin/bash\n", encoding="utf-8")
            (source / "flag").write_text("flag{demo}\n", encoding="utf-8")
            (source / "src" / "users.json").write_text("{}\n", encoding="utf-8")
            (source / "docker_artifacts.json").write_text("{}\n", encoding="utf-8")
            (source / ".ctfbuild" / "proposal.json").write_text("{}\n", encoding="utf-8")
            (source / "verification" / "image.inspect.json").write_text("{}\n", encoding="utf-8")
            (workdir / "题目镜像").mkdir()
            (workdir / "题目镜像" / "irisctf-2025-password-manager.tar").write_bytes(b"tar")
            (workdir / "题目镜像" / "image.inspect.json").write_text("{}\n", encoding="utf-8")
            (workdir / "题目镜像" / "docker_artifacts.validated.json").write_text("{}\n", encoding="utf-8")
            (workdir / "手册").mkdir()
            (workdir / "手册" / "manual_filled_draft.md").write_text("# draft\n", encoding="utf-8")
            (workdir / "手册" / "题目解题手册.md").write_text("# 题目解题手册\n", encoding="utf-8")

            manifest = delivery.create_delivery_package(workdir=workdir, outputs_dir=outputs, output_dir=tmp_path / "交付包")
            delivery_dir = Path(manifest["paths"]["delivery_dir"])
            challenge_dir = delivery_dir / "Web-Password Manager"
            checks = {
                "dockerfile": (challenge_dir / "题目源码" / "Dockerfile").exists(),
                "source_json": (challenge_dir / "题目源码" / "src" / "users.json").exists(),
                "docker_artifacts": (challenge_dir / "题目源码" / "docker_artifacts.json").exists(),
                "ctfbuild": (challenge_dir / "题目源码" / ".ctfbuild").exists(),
                "verification": (challenge_dir / "题目源码" / "verification").exists(),
                "image_tar": (challenge_dir / "题目镜像" / "irisctf-2025-password-manager.tar").exists(),
                "image_inspect": (challenge_dir / "题目镜像" / "image.inspect.json").exists(),
                "image_artifacts": (challenge_dir / "题目镜像" / "docker_artifacts.validated.json").exists(),
                "manual": (challenge_dir / "题目手册" / "题目解题手册.md").exists(),
                "draft_manual": (challenge_dir / "题目手册" / "manual_filled_draft.md").exists(),
            }

        self.assertTrue(checks["dockerfile"])
        self.assertTrue(checks["source_json"])
        self.assertFalse(checks["docker_artifacts"])
        self.assertFalse(checks["ctfbuild"])
        self.assertFalse(checks["verification"])
        self.assertTrue(checks["image_tar"])
        self.assertFalse(checks["image_inspect"])
        self.assertFalse(checks["image_artifacts"])
        self.assertTrue(checks["manual"])
        self.assertFalse(checks["draft_manual"])
        self.assertEqual(manifest["summary"]["challenge_count"], 1)
        self.assertEqual(manifest["summary"]["package_issues"], 0)

    def test_delivery_package_can_reference_image_tars_when_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workdir = tmp_path / "work" / "ctf-2026-collection"
            outputs = tmp_path / "outputs"
            workdir.mkdir(parents=True)
            outputs.mkdir()
            (outputs / "最终归档表.xlsx").write_bytes(b"xlsx")
            (outputs / "语雀粘贴表.md").write_text("| 题目 |\n", encoding="utf-8")
            archive_dir = workdir / "archive" / "Web-EZSmuggler"
            (archive_dir / "题目镜像").mkdir(parents=True)
            (archive_dir / "题目镜像" / "l7-smuggler_latest.tar").write_bytes(b"tar")

            manifest = delivery.create_delivery_package(
                workdir=workdir,
                outputs_dir=outputs,
                output_dir=tmp_path / "交付包",
                copy_image_tars=False,
            )

            delivery_dir = Path(manifest["paths"]["delivery_dir"])
            self.assertFalse((delivery_dir / "Web-EZSmuggler" / "题目镜像" / "l7-smuggler_latest.tar").exists())
            self.assertTrue(any(item["status"] == "referenced" and item.get("subdir") == "题目镜像" for item in manifest["files"]))

    def test_delivery_package_copies_image_tars_over_general_copy_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workdir = tmp_path / "work" / "ctf-2026-collection"
            outputs = tmp_path / "outputs"
            workdir.mkdir(parents=True)
            outputs.mkdir()
            (outputs / "最终归档表.xlsx").write_bytes(b"xlsx")
            (outputs / "语雀粘贴表.md").write_text("| 题目 |\n", encoding="utf-8")
            archive_dir = workdir / "archive" / "Web-EZSmuggler"
            (archive_dir / "题目镜像").mkdir(parents=True)
            image_tar = archive_dir / "题目镜像" / "l7-smuggler_latest.tar"
            image_tar.write_bytes(b"tar-over-limit")

            manifest = delivery.create_delivery_package(
                workdir=workdir,
                outputs_dir=outputs,
                output_dir=tmp_path / "交付包",
                copy_limit=1,
            )

            delivery_dir = Path(manifest["paths"]["delivery_dir"])
            self.assertTrue((delivery_dir / "Web-EZSmuggler" / "题目镜像" / "l7-smuggler_latest.tar").exists())
            self.assertTrue(any(item["status"] == "copied" and item.get("subdir") == "题目镜像" for item in manifest["files"]))

    def test_delivery_package_does_not_require_optional_stage_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workdir = tmp_path / "work" / "ctf-2026-collection"
            outputs = tmp_path / "outputs"
            workdir.mkdir(parents=True)
            outputs.mkdir()
            (outputs / "最终归档表.xlsx").write_bytes(b"xlsx")
            (outputs / "语雀粘贴表.md").write_text("| 名称 |\n|---|\n", encoding="utf-8")
            (outputs / "最终报告.md").write_text("# 最终报告\n", encoding="utf-8")
            (outputs / "archive_package.zip").write_bytes(b"zip")
            (outputs / "missing_report.md").write_text("# 待处理问题\n", encoding="utf-8")
            writeup_dir = workdir / "writeup"
            writeup_dir.mkdir()
            (writeup_dir / "题目解题手册.md").write_text("# 题目解题手册\n", encoding="utf-8")

            manifest = delivery.create_delivery_package(workdir=workdir, outputs_dir=outputs, output_dir=tmp_path / "交付包")

        missing_keys = {item["key"] for item in manifest["missing"]}
        self.assertNotIn("completion_report_md", missing_keys)
        self.assertNotIn("solver_summary_md", missing_keys)
        self.assertEqual(missing_keys, set())

    def test_quality_runner_writes_batch_evidence_and_updated_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = sample_case(tmp_path)
            manifest = archive.create_archive_package(case, tmp_path / "archive")
            case = archive.apply_archive_outputs(case, manifest)
            cases_path = tmp_path / "ctf_cases.jsonl"
            cases_path.write_text(json.dumps(case, ensure_ascii=False) + "\n", encoding="utf-8")

            payload = quality_runner.run_quality_batch(
                cases_path=cases_path,
                output_dir=tmp_path / "quality-batch",
            )

            self.assertEqual(payload["summary"]["total"], 1)
            self.assertTrue(Path(payload["paths"]["summary_json"]).exists())
            self.assertTrue(Path(payload["paths"]["summary_report"]).exists())
            self.assertTrue(Path(payload["paths"]["output_cases"]).exists())
            self.assertTrue(Path(payload["entries"][0]["quality_review"]).exists())
            self.assertIn("solve-proof", "\n".join(payload["entries"][0]["issues"]))

    def test_docker_runner_records_platform_logs_hash_and_probes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            tar_path = tmp_path / "image.tar"

            class Response:
                status = 200

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            def fake_run(args, **kwargs):
                if args[:3] == ["docker", "image", "inspect"]:
                    stdout = '[{"Os":"linux","Architecture":"amd64"}]'
                elif args[:2] == ["docker", "logs"]:
                    stdout = "service ready\n"
                elif args[:2] == ["docker", "save"]:
                    Path(args[-1]).write_bytes(b"image-tar")
                    stdout = "saved\n"
                elif args[:2] == ["docker", "run"]:
                    stdout = "container-id\n"
                else:
                    stdout = "ok\n"
                return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

            with mock.patch.object(docker_runner.subprocess, "run", side_effect=fake_run):
                with mock.patch.object(docker_runner.time, "sleep", return_value=None):
                    with mock.patch.object(docker_runner.http, "http_get", return_value={"status": 200}):
                        with mock.patch.object(docker_runner, "authorization_errors", return_value=[]):
                            evidence = docker_runner.execute_docker_workflow(
                                case={"case_id": "docker-001"},
                                output_dir=tmp_path / "docker",
                                image_name="busybox:1.36",
                                tar_path=tar_path,
                                ports=["18080:80"],
                                operations=["inspect", "run", "logs", "stop", "save"],
                                startup_wait=0,
                            )

            self.assertEqual(evidence["summary"]["status"], "pass")
            self.assertEqual(evidence["summary"]["platform"], "linux/amd64")
            self.assertEqual(len(evidence["summary"]["tar_sha256"]), 64)
            self.assertTrue(Path(evidence["summary"]["logs_path"]).exists())
            self.assertTrue(Path(evidence["evidence_path"]).exists())
            self.assertTrue(Path(evidence["report_path"]).exists())

    def test_docker_runner_uses_tcp_probe_for_tcp_challenge_and_cleans_failed_created_container(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            calls: list[list[str]] = []

            def fake_run(args, **kwargs):
                calls.append(args)
                if args[:3] == ["docker", "image", "inspect"]:
                    return subprocess.CompletedProcess(args, 0, stdout='[{"Os":"linux","Architecture":"amd64"}]', stderr="")
                if args[:2] == ["docker", "run"]:
                    return subprocess.CompletedProcess(args, 1, stdout="", stderr="created then failed")
                return subprocess.CompletedProcess(args, 0, stdout="ok\n", stderr="")

            with mock.patch.object(docker_runner.subprocess, "run", side_effect=fake_run):
                with mock.patch.object(docker_runner, "authorization_errors", return_value=[]):
                    evidence = docker_runner.execute_docker_workflow(
                        case={"case_id": "tcp-001"},
                        output_dir=tmp_path / "docker",
                        image_name="demo/tcp:local",
                        ports=["19999:9999"],
                        operations=["inspect", "run", "logs", "stop"],
                        container_inference={"runtime": {"service_protocol": "tcp"}},
                        startup_wait=0,
                    )

        self.assertEqual(evidence["summary"]["status"], "fail")
        self.assertTrue(any(args[:3] == ["docker", "rm", "-f"] for args in calls))
        self.assertTrue(evidence["plan"]["tcp_probes"])
        self.assertEqual(evidence["plan"]["probe_urls"], [])
        self.assertFalse(any(str(probe.get("url", "")).startswith("http://") for probe in evidence["probes"]))

    def test_quality_review_docker_execution_uses_tcp_probe_and_cleans_failed_container(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            calls: list[list[str]] = []

            def fake_run(args, **kwargs):
                calls.append(args)
                if args[:3] == ["docker", "image", "inspect"]:
                    return subprocess.CompletedProcess(args, 0, stdout='[{"Os":"linux","Architecture":"amd64"}]', stderr="")
                if args[:2] == ["docker", "run"]:
                    return subprocess.CompletedProcess(args, 1, stdout="", stderr="created then failed")
                return subprocess.CompletedProcess(args, 0, stdout="ok\n", stderr="")

            case = {
                "case_id": "tcp-review",
                "docker_artifacts": {
                    "image_name": "demo/tcp:local",
                    "ports": ["19999:9999"],
                    "service_protocol": "tcp",
                },
            }
            with mock.patch.object(review.subprocess, "run", side_effect=fake_run):
                with mock.patch.object(review, "is_host_port_available", return_value=True):
                    evidence = review.execute_docker_review(case, tmp_path / "quality", startup_wait=0)

        self.assertEqual(evidence["summary"]["status"], "fail")
        self.assertTrue(any(args[:3] == ["docker", "rm", "-f"] for args in calls))
        self.assertFalse(any(str(item.get("url", "")).startswith("http://") for item in evidence["probes"]))

    def test_new_mcp_servers_list_expected_tools(self):
        servers = [
            (
                "cloversec_ctf_docker_mcp.py",
                ["cloversec_ctf_docker_plan", "cloversec_ctf_docker_validation_plan", "cloversec_ctf_docker_execute"],
            ),
            ("cloversec_ctf_archive_mcp.py", ["cloversec_ctf_archive_batch"]),
            ("cloversec_ctf_quality_runner_mcp.py", ["cloversec_ctf_quality_run", "cloversec_ctf_proof_pack"]),
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

            self.assertEqual(init["result"]["serverInfo"]["version"], "1.1.4")
            names = [item["name"] for item in tools["result"]["tools"]]
            for expected in expected_tools:
                self.assertIn(expected, names)


if __name__ == "__main__":
    unittest.main()
