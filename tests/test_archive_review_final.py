import json
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
import cloversec_ctf_docker as docker_runner
import cloversec_ctf_final as final
import cloversec_ctf_quality_runner as quality_runner
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
                    with mock.patch.object(review, "urlopen", return_value=Response()):
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
            plan = retag.create_retag_plan(case, "CTF-2026060001", tmp_path / "retagged")

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
            self.assertTrue((tmp_path / "archive" / "_batch" / "batch_archive_summary.json").exists())
            self.assertTrue((tmp_path / "archive" / "_batch" / "batch_archive_report.md").exists())
            self.assertTrue((tmp_path / "ctf_cases.archived.jsonl").exists())
            self.assertTrue((tmp_path / "final" / "archive.xlsx").exists())

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
                    with mock.patch.object(docker_runner, "urlopen", return_value=Response()):
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

    def test_new_mcp_servers_list_expected_tools(self):
        servers = [
            ("cloversec_ctf_docker_mcp.py", ["cloversec_ctf_docker_plan", "cloversec_ctf_docker_execute"]),
            ("cloversec_ctf_archive_mcp.py", ["cloversec_ctf_archive_batch"]),
            ("cloversec_ctf_quality_runner_mcp.py", ["cloversec_ctf_quality_run"]),
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

            self.assertEqual(init["result"]["serverInfo"]["version"], "0.3.1")
            names = [item["name"] for item in tools["result"]["tools"]]
            for expected in expected_tools:
                self.assertIn(expected, names)


if __name__ == "__main__":
    unittest.main()
