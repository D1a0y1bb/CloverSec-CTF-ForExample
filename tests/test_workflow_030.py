import json
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import cloversec_ctf_workflow as workflow


class Workflow030Tests(unittest.TestCase):
    def test_init_workflow_creates_standard_run_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            payload = workflow.init_workflow(
                event="IrisCTF",
                years=[2025],
                categories=["web"],
                limit=2,
                out_dir=out,
                allow_browser_search=True,
            )

            self.assertEqual(payload["workdir"], out.as_posix())
            self.assertTrue((out / "task_plan.json").exists())
            self.assertTrue((out / "workflow_state.json").exists())
            self.assertTrue((out / "ctf_cases.jsonl").exists())
            self.assertTrue((out / "logs").is_dir())
            self.assertTrue((out / "evidence").is_dir())
            self.assertTrue((out / "snapshots").is_dir())
            self.assertTrue((out / "classification").is_dir())
            plan = json.loads((out / "task_plan.json").read_text(encoding="utf-8"))
            self.assertEqual(plan["request"]["categories"], ["web"])
            self.assertTrue(any("IrisCTF 2025 web writeup" == item["query"] for item in plan["search_tasks"]))

    def test_init_cli_accepts_workdir_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            output = Path(tmp) / "init.json"

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "cloversec_ctf_workflow.py"),
                    "init",
                    "--event",
                    "CrateCTF",
                    "--year",
                    "2024",
                    "--category",
                    "pwn",
                    "--limit",
                    "1",
                    "--workdir",
                    str(out),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((out / "task_plan.json").exists())
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["workdir"], out.as_posix())

    def test_research_stage_rejects_empty_cases_and_regenerates_from_search_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            out.mkdir()
            (out / "ctf_cases.jsonl").write_text("", encoding="utf-8")
            search_manifest = {
                "query": "CrateCTF 2024 JSFS",
                "years": [2024],
                "results": [
                    {
                        "title": "CrateCTF 2024 JSFS writeup",
                        "url": "https://example.com/jsfs",
                        "source_url": "https://example.com/jsfs",
                        "layer": "confirmed_challenge",
                        "score": 80,
                        "source_type": "writeup",
                        "metadata": {"event": "CrateCTF", "year": "2024", "category": "Pwn", "challenge": "JSFS"},
                    }
                ],
            }
            workflow.write_json(out / "search_results.json", search_manifest)

            result = workflow.execute_stage_research(out, max_search_tasks=0, search_limit=5, sources=[])

            self.assertEqual(result["status"], "ok")
            self.assertTrue((out / "ctf_cases.jsonl").read_text(encoding="utf-8").strip())

    def test_download_accept_uses_existing_safe_preview_after_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            sandbox = out / "downloads_sandbox"
            sandbox.mkdir(parents=True)
            downloaded = sandbox / "0001-challenge.zip"
            downloaded.write_bytes(b"zip")
            workflow.write_json(
                out / "download_preview.json",
                {
                    "records": [{"safety_status": "safe", "local_path": downloaded.as_posix()}],
                    "summary": {"total": 1, "safe": 1, "needs_review": 0, "blocked": 0, "accepted": 0},
                },
            )

            result = workflow.execute_stage_download_accept(out, allow_download_accept=True)

            self.assertEqual(result["status"], "ok")
            self.assertTrue((out / "downloads_accepted" / "0001-challenge.zip").exists())

    def test_delivery_output_dir_does_not_select_parent_outputs_when_workdir_is_inside_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            outputs = Path(tmp) / "outputs"
            workdir = outputs / "jsfs-cratectf-2024-platform"
            workdir.mkdir(parents=True)

            selected = workflow.delivery_output_dir_for_workdir(workdir)

            self.assertEqual(selected, workdir / "最终交付")

    def test_auto_collect_next_action_matches_recommended_skill(self):
        writeup_action = workflow.auto_collect_next_action(
            [{"recommended_next": {"skill": "cloversec-ctf-writeup-scaffold"}}]
        )
        dockerizer_action = workflow.auto_collect_next_action(
            [{"recommended_next": {"skill": "cloversec-ctf-build-dockerizer"}}]
        )

        self.assertIn("生成手册", writeup_action)
        self.assertNotIn("Dockerizer 交接表", writeup_action)
        self.assertIn("Dockerizer 交接表", dockerizer_action)

    def test_batch_orchestrate_apply_tracks_per_case_state_and_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            workflow.init_workflow(event="DemoCTF", years=[2026], categories=["misc"], limit=1, out_dir=out)
            cases = [
                {
                    "case_id": "case-1",
                    "metadata": {"名称": "A", "分类": "Misc"},
                    "flag": {"value": "", "type": "unknown", "sensitive": True},
                    "evidence": [{"source_url": "https://example.com/a", "title": "A writeup"}],
                },
                {
                    "case_id": "case-2",
                    "metadata": {"名称": "B", "分类": "Misc"},
                    "flag": {"value": "", "type": "unknown", "sensitive": True},
                    "evidence": [{"source_url": "https://example.com/b", "title": "B writeup"}],
                },
            ]
            workflow.write_jsonl(out / "ctf_cases.jsonl", cases)

            first = workflow.batch_orchestrate(workdir=out, stage="research", mode="apply")
            second = workflow.batch_orchestrate(workdir=out, stage="research", mode="apply", resume=True)

            self.assertEqual(first["completed"], ["case-1", "case-2"])
            self.assertEqual(second["skipped"], ["case-1", "case-2"])
            state = json.loads((out / "workflow_state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["stages"]["research"]["status"], "completed")
            self.assertEqual(len(state["cases"]), 2)

    def test_batch_apply_does_not_complete_without_real_stage_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            workflow.init_workflow(event="DemoCTF", years=[2026], categories=["misc"], limit=1, out_dir=out)
            workflow.write_jsonl(
                out / "ctf_cases.jsonl",
                [{"case_id": "case-1", "metadata": {"名称": "A", "分类": "Misc"}}],
            )

            result = workflow.batch_orchestrate(workdir=out, stage="research", mode="apply")

            self.assertEqual(result["completed"], [])
            self.assertEqual(result["incomplete"], ["case-1"])
            self.assertIn("缺少 source_url", result["errors"][0]["message"])
            state = json.loads((out / "workflow_state.json").read_text(encoding="utf-8"))
            self.assertNotEqual(state["stages"]["research"]["status"], "completed")

    def test_archive_stage_blocks_when_cases_only_have_writeup_leads(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            workflow.init_workflow(event="DemoCTF", years=[2026], categories=["misc"], limit=1, out_dir=out)
            workflow.write_jsonl(
                out / "ctf_cases.jsonl",
                [
                    {
                        "case_id": "lead-only",
                        "metadata": {"名称": "Only WP", "分类": "Misc", "验证状态": "未验证", "是否通过": "否"},
                        "research": {"gate": "cannot_continue", "blocking_rule": "writeup_without_attachment"},
                        "evidence": [{"source_url": "https://example.com/wp", "title": "Only WP writeup"}],
                    }
                ],
            )

            result = workflow.execute_stage_archive(out)

            self.assertEqual(result["status"], "blocked")
            self.assertIn("没有可归档的本地材料", result["errors"][0]["message"])

    def test_archive_stage_syncs_existing_dockerizer_rendered_materials(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            workflow.init_workflow(event="DemoCTF", years=[2026], categories=["web"], limit=1, out_dir=out)
            workflow.write_jsonl(
                out / "ctf_cases.jsonl",
                [
                    {
                        "case_id": "case-rendered",
                        "metadata": {"名称": "Rendered", "分类": "Web", "验证状态": "未验证", "是否通过": "否"},
                        "flag": {"value": "flag{demo}", "type": "static", "sensitive": True},
                        "source_files": [],
                        "attachments": [],
                        "docker_artifacts": {},
                        "writeup": {},
                    }
                ],
            )
            rendered = out / "materials" / "case-rendered" / ".ctfbuild" / "rendered"
            rendered.mkdir(parents=True)
            (rendered / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            (rendered / "start.sh").write_text("#!/bin/bash\nsleep 1\n", encoding="utf-8")
            summary = rendered.parent / "validate-summary.json"
            summary.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "code": "CONTRACT_VALIDATION_PASSED",
                        "summary": "无 ERROR",
                        "counts": {"errors": 0, "warnings": 0},
                        "verification": {"level": "static"},
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            result = workflow.execute_stage_archive(out)
            cases = workflow.data.load_cases(out / "ctf_cases.jsonl")
            error_text = "\n".join(str(item.get("message") or "") for item in result.get("errors", []))

            self.assertNotIn("没有可归档的本地材料", error_text)
            self.assertEqual(cases[0]["docker_artifacts"]["project_dir"], rendered.resolve().as_posix())
            self.assertEqual(cases[0]["docker_artifacts"]["validation_level"], "static")
            self.assertFalse(cases[0]["docker_artifacts"]["run_verified"])
            self.assertTrue((out / "case_material_sync.json").exists())

    def test_case_material_sync_does_not_write_multi_case_without_unique_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            out.mkdir()
            workflow.write_jsonl(
                out / "ctf_cases.jsonl",
                [
                    {"case_id": "case-a", "metadata": {"名称": "Alpha"}, "docker_artifacts": {}},
                    {"case_id": "case-b", "metadata": {"名称": "Beta"}, "docker_artifacts": {}},
                ],
            )
            rendered = out / "materials" / "shared" / ".ctfbuild" / "rendered"
            rendered.mkdir(parents=True)
            (rendered / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")

            payload = workflow.sync_cases_with_workflow_materials(out)
            cases = workflow.data.load_cases(out / "ctf_cases.jsonl")

            self.assertEqual(payload["status"], "unchanged")
            self.assertEqual(cases[0]["docker_artifacts"], {})
            self.assertEqual(cases[1]["docker_artifacts"], {})
            self.assertGreaterEqual(len(payload["unmatched_materials"]), 1)

    def test_archive_completion_rejects_manifest_with_issues(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            manifest_dir = out / "归档" / "_cache" / "case"
            manifest_dir.mkdir(parents=True)
            manifest = manifest_dir / "archive_manifest.json"
            workflow.write_json(
                manifest,
                {
                    "case_id": "case-1",
                    "summary": {"file_count": 1},
                    "files": [{"relative_path": "题目手册/题目解题手册.md"}],
                    "issues": ["missing source: /tmp/missing"],
                },
            )

            result = workflow.check_archive_completion(out, {}, "case-1")

            self.assertEqual(result["status"], "incomplete")
            self.assertIn("仍有问题", result["errors"][0]["message"])

    def test_batch_apply_blocks_when_previous_stage_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            workflow.init_workflow(event="DemoCTF", years=[2026], categories=["misc"], limit=1, out_dir=out)
            workflow.write_jsonl(
                out / "ctf_cases.jsonl",
                [
                    {
                        "case_id": "case-1",
                        "metadata": {"名称": "A", "分类": "Misc"},
                        "evidence": [{"source_url": "https://example.com/a", "title": "A writeup"}],
                    }
                ],
            )

            result = workflow.batch_orchestrate(workdir=out, stage="archive", mode="apply")

            self.assertEqual(result["completed"], [])
            self.assertEqual(result["blocked"], ["case-1"])
            self.assertEqual(result["errors"][0]["missing_dependency"], "download_accept")

    def test_batch_apply_force_records_forced_but_still_checks_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            workflow.init_workflow(event="DemoCTF", years=[2026], categories=["misc"], limit=1, out_dir=out)
            workflow.write_jsonl(
                out / "ctf_cases.jsonl",
                [
                    {
                        "case_id": "case-1",
                        "metadata": {"名称": "A", "分类": "Misc"},
                        "evidence": [{"source_url": "https://example.com/a", "title": "A writeup"}],
                    }
                ],
            )
            final_dir = out / "最终交付"
            final_dir.mkdir()
            (final_dir / "最终归档表.xlsx").write_bytes(b"xlsx")
            (final_dir / "语雀粘贴表.md").write_text("| 名称 |\n|---|\n", encoding="utf-8")
            (final_dir / "交付说明.md").write_text("# 交付说明\n", encoding="utf-8")
            (final_dir / "待处理问题.md").write_text("# 待处理问题\n", encoding="utf-8")
            (final_dir / "质量检查报告.md").write_text("# 质量检查报告\n", encoding="utf-8")

            result = workflow.batch_orchestrate(workdir=out, stage="final_report", mode="apply", force=True)

            self.assertEqual(result["completed"], ["case-1"])
            state = json.loads((out / "workflow_state.json").read_text(encoding="utf-8"))
            self.assertTrue(state["cases"][0]["stages"]["final_report"]["forced"])

    def test_github_doctor_masks_token_and_reports_failures(self):
        def fake_run(command, capture_output, text, check, timeout):
            joined = " ".join(command)
            if "auth token" in joined:
                return FakeCompleted(0, "ghp_abcdef123456\n", "")
            if "auth status" in joined:
                return FakeCompleted(0, "Logged in\n", "")
            if "/search/repositories" in joined:
                return FakeCompleted(0, '{"total_count":1}', "")
            if "/search/code" in joined:
                return FakeCompleted(1, "", "requires authentication")
            if "rate_limit" in joined:
                return FakeCompleted(0, '{"resources":{"search":{"limit":30,"remaining":29,"reset":1,"used":1}}}', "")
            return FakeCompleted(0, "", "")

        with mock.patch.object(workflow.shutil, "which", return_value="/usr/local/bin/gh"):
            with mock.patch.object(workflow.subprocess, "run", side_effect=fake_run):
                report = workflow.github_doctor(sample_query="IrisCTF")

        token_check = next(item for item in report["checks"] if item["name"] == "gh auth token")
        self.assertIn("***", token_check["stdout"])
        self.assertIn("github-repository-search", report["available_sources"])
        self.assertNotIn("github-code-search", report["available_sources"])
        self.assertEqual(report["rate_limit"]["search"]["remaining"], 29)

    def test_dedupe_candidates_and_apply_approved_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases_path = root / "cases.jsonl"
            candidates_path = root / "dedupe.json"
            merged_path = root / "merged.jsonl"
            cases = [
                {
                    "case_id": "case-a",
                    "metadata": {"赛事来源": "IrisCTF 2025", "名称": "KittyCrypt", "分类": "Crypto"},
                    "flag": {"value": "flag{a}", "type": "static", "sensitive": True},
                    "evidence": [{"source_url": "https://example.com/iris/kittycrypt", "title": "KittyCrypt writeup"}],
                },
                {
                    "case_id": "case-b",
                    "metadata": {"赛事来源": "IrisCTF 2025", "名称": "KittyCrypt", "分类": "crypto"},
                    "flag": {"value": "", "type": "unknown", "sensitive": True},
                    "evidence": [{"source_url": "https://example.com/iris/kittycrypt?utm=1", "title": "KittyCrypt writeup"}],
                },
            ]
            workflow.write_jsonl(cases_path, cases)
            payload = workflow.dedupe_cases(cases_path=cases_path, output_path=candidates_path)
            payload["candidates"][0]["approved"] = True
            workflow.write_json(candidates_path, payload)

            result = workflow.apply_dedupe(cases_path=cases_path, candidates_path=candidates_path, output_path=merged_path)
            merged = [json.loads(line) for line in merged_path.read_text(encoding="utf-8").splitlines() if line.strip()]

        self.assertEqual(result["summary"]["merged_groups"], 1)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["flag"]["value"], "flag{a}")
        self.assertEqual(set(merged[0]["research"]["merged_from"]), {"case-a", "case-b"})

    def test_download_sandbox_blocks_private_url_and_previews_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            zip_path = root / "challenge.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("README.md", "# demo\n")
            with LocalServer(root) as server:
                def fake_block_reason(url):
                    return "blocked private IP address" if "private.zip" in url else ""

                with mock.patch.object(workflow, "blocked_url_reason", side_effect=fake_block_reason):
                    payload = workflow.download_sandbox(
                        urls=[f"{server.url}/challenge.zip", "http://127.0.0.1/private.zip"],
                        output_dir=root / "out",
                        accept=True,
                        max_file_size=1024 * 1024,
                    )

        self.assertEqual(payload["summary"]["total"], 2)
        self.assertEqual(payload["records"][0]["safety_status"], "safe")
        self.assertTrue(payload["records"][0]["accepted_path"])
        self.assertEqual(payload["records"][1]["safety_status"], "blocked")

    def test_download_sandbox_limits_redirects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            zip_path = root / "challenge.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("README.md", "# redirect demo\n")
            with RedirectServer(root) as server:
                with mock.patch.object(workflow, "blocked_url_reason", return_value=""):
                    allowed = workflow.download_sandbox(
                        urls=[f"{server.url}/r1"],
                        output_dir=root / "allowed",
                        accept=False,
                        max_file_size=1024 * 1024,
                        max_redirects=2,
                    )
                    blocked = workflow.download_sandbox(
                        urls=[f"{server.url}/r1"],
                        output_dir=root / "blocked",
                        accept=False,
                        max_file_size=1024 * 1024,
                        max_redirects=1,
                    )

        self.assertEqual(allowed["records"][0]["safety_status"], "safe")
        self.assertEqual(allowed["records"][0]["redirect_count"], 2)
        self.assertEqual(blocked["records"][0]["safety_status"], "blocked")
        self.assertIn("max_redirects=1", blocked["records"][0]["issues"][0])

    def test_source_evidence_writes_snapshot_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "page.html").write_text("<html><title>Demo</title><body>ok</body></html>", encoding="utf-8")
            with LocalServer(root) as server:
                manifest = {
                    "results": [
                        {
                            "title": "Demo CTF writeup",
                            "url": f"{server.url}/page.html",
                            "summary": "writeup",
                            "provider": "local",
                            "layer": "writeup_candidate",
                            "confidence": "medium",
                            "score": 10,
                        }
                    ]
                }
                manifest_path = root / "manifest.json"
                workflow.write_json(manifest_path, manifest)
                payload = workflow.record_source_evidence(
                    manifest_path=manifest_path,
                    evidence_dir=root / "evidence",
                    snapshots_dir=root / "snapshots",
                    fetch_snapshots=True,
                )

                self.assertEqual(payload["summary"]["records"], 1)
                self.assertEqual(payload["summary"]["snapshots"], 1)
                self.assertTrue(Path(payload["records"][0]["snapshot_metadata_path"]).exists())

    def test_source_evidence_marks_http_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with ForbiddenServer() as server:
                manifest = {
                    "results": [
                        {
                            "title": "Blocked writeup",
                            "url": f"{server.url}/blocked",
                            "summary": "writeup",
                            "provider": "local",
                            "layer": "writeup_candidate",
                            "confidence": "medium",
                            "score": 10,
                        }
                    ]
                }
                manifest_path = root / "manifest.json"
                workflow.write_json(manifest_path, manifest)
                payload = workflow.record_source_evidence(
                    manifest_path=manifest_path,
                    evidence_dir=root / "evidence",
                    snapshots_dir=root / "snapshots",
                    fetch_snapshots=True,
                )

                self.assertEqual(payload["summary"]["records"], 1)
                self.assertEqual(payload["summary"]["errors"], 1)
                self.assertEqual(payload["records"][0]["http_status"], 403)
                self.assertIn("http_status=403", payload["records"][0]["missing_reason"])

    def test_execute_search_tasks_writes_cases_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / "run"
            workflow.init_workflow(event="DemoCTF", years=[2026], categories=["web"], limit=1, out_dir=run)

            def fake_search_plus(*args, **kwargs):  # noqa: ARG001
                return {
                    "results": [
                        {
                            "provider": "fake",
                            "kind": "writeup",
                            "title": "DemoCTF 2026 web hello writeup",
                            "url": "https://example.com/DemoCTF-2026-web-hello-writeup",
                            "source_url": "https://example.com/DemoCTF-2026-web-hello-writeup",
                            "summary": "DemoCTF 2026 web challenge writeup and source hints.",
                            "source_type": "public_web",
                            "confidence": "medium",
                            "metadata": {},
                        }
                    ],
                    "errors": [],
                    "summary": {"total_results": 1},
                    "decision_required": [],
                }

            with mock.patch.object(workflow.search_plus, "search_plus", side_effect=fake_search_plus):
                payload = workflow.execute_search_tasks(workdir=run, max_tasks=1, fetch_snapshots=False)

            self.assertEqual(payload["summary"]["cases"], 1)
            self.assertTrue((run / "search_results.json").exists())
            self.assertTrue((run / "ctf_cases.jsonl").exists())
            self.assertTrue((run / "evidence" / "source_evidence.json").exists())
            cases = [json.loads(line) for line in (run / "ctf_cases.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(cases[0]["metadata"]["分类"], "Web")

    def test_execute_search_tasks_prefers_github_tree_over_writeup_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / "run"
            workflow.init_workflow(event="IrisCTF", years=[2025], categories=["web"], limit=1, out_dir=run)

            def fake_search_plus(*args, **kwargs):  # noqa: ARG001
                return {
                    "results": [
                        {
                            "provider": "duckduckgo",
                            "kind": "writeup",
                            "title": "IrisCTF 2025 bad todo writeup",
                            "url": "https://example.com/irisctf-2025-bad-todo-writeup",
                            "summary": "A public writeup with no official handout.",
                            "source_type": "public_web",
                            "confidence": "medium",
                            "metadata": {},
                        },
                        {
                            "provider": "github",
                            "kind": "repository",
                            "title": "IrisCTF 2025 bad-todo official challenge directory",
                            "url": "https://github.com/IrisSec/IrisCTF-2025-Challenges/tree/main/bad-todo",
                            "summary": "Official source directory for the bad-todo web challenge.",
                            "source_type": "github",
                            "confidence": "high",
                            "metadata": {},
                        },
                    ],
                    "errors": [],
                    "summary": {"total_results": 2},
                    "decision_required": [],
                }

            with mock.patch.object(workflow.search_plus, "search_plus", side_effect=fake_search_plus):
                payload = workflow.execute_search_tasks(workdir=run, max_tasks=1, fetch_snapshots=False)

            self.assertEqual(payload["summary"]["cases"], 1)
            cases = [json.loads(line) for line in (run / "ctf_cases.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(cases[0]["evidence"][0]["source_url"], "https://github.com/IrisSec/IrisCTF-2025-Challenges/tree/main/bad-todo")
            self.assertEqual(cases[0]["research"]["gate"], "needs_human_download")
            self.assertNotEqual(cases[0]["metadata"]["材料状态"], "公开 WP 线索")

    def test_execute_search_tasks_prefers_official_github_repo_over_writeup_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / "run"
            workflow.init_workflow(event="IrisCTF", years=[2025], categories=["web"], limit=1, out_dir=run)

            def fake_search_plus(*args, **kwargs):  # noqa: ARG001
                return {
                    "results": [
                        {
                            "provider": "duckduckgo",
                            "kind": "writeup",
                            "title": "irisctf 2025 Web Writeups - ireland.re",
                            "url": "https://ireland.re/posts/irisctf_2025/",
                            "summary": "A public writeup collection.",
                            "source_type": "public_web",
                            "confidence": "medium",
                            "metadata": {},
                        },
                        {
                            "provider": "github",
                            "kind": "repository",
                            "title": "IrisSec/IrisCTF-2025-Challenges",
                            "url": "https://github.com/IrisSec/IrisCTF-2025-Challenges",
                            "summary": "Official challenges for IrisCTF 2025.",
                            "source_type": "github",
                            "confidence": "high",
                            "metadata": {},
                        },
                    ],
                    "errors": [],
                    "summary": {"total_results": 2},
                    "decision_required": [],
                }

            with mock.patch.object(workflow.search_plus, "search_plus", side_effect=fake_search_plus):
                payload = workflow.execute_search_tasks(workdir=run, max_tasks=1, fetch_snapshots=False)

            self.assertEqual(payload["summary"]["cases"], 1)
            cases = [json.loads(line) for line in (run / "ctf_cases.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(cases[0]["evidence"][0]["source_url"], "https://github.com/IrisSec/IrisCTF-2025-Challenges")
            self.assertEqual(cases[0]["metadata"]["分类"], "Web")
            self.assertEqual(cases[0]["research"]["material_level"], "official_challenge_repository")
            self.assertEqual(cases[0]["research"]["gate"], "needs_human_download")
            self.assertNotEqual(cases[0]["metadata"]["材料状态"], "公开 WP 线索")

    def test_execute_search_tasks_marks_writeup_only_as_not_continuable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / "run"
            workflow.init_workflow(event="IrisCTF", years=[2025], categories=["web"], limit=1, out_dir=run)

            def fake_search_plus(*args, **kwargs):  # noqa: ARG001
                return {
                    "results": [
                        {
                            "provider": "duckduckgo",
                            "kind": "writeup",
                            "title": "IrisCTF 2025 Web Writeups",
                            "url": "https://example.com/irisctf-2025-web-writeups",
                            "summary": "Public writeup collection without official handout.",
                            "source_type": "public_web",
                            "confidence": "medium",
                            "metadata": {},
                        }
                    ],
                    "errors": [],
                    "summary": {"total_results": 1},
                    "decision_required": [],
                }

            with mock.patch.object(workflow.search_plus, "search_plus", side_effect=fake_search_plus):
                payload = workflow.execute_search_tasks(workdir=run, max_tasks=1, fetch_snapshots=False)

            self.assertEqual(payload["summary"]["continuable_cases"], 0)
            self.assertEqual(payload["summary"]["material_candidate_results"], 0)
            state = json.loads((run / "workflow_state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["stages"]["research"]["status"], "pending_user")
            self.assertIn("没有形成可交付题目", (run / "当前状态.md").read_text(encoding="utf-8"))

    def test_workflow_engine_stops_after_writeup_only_research(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / "run"
            workflow.init_workflow(event="IrisCTF", years=[2025], categories=["web"], limit=1, out_dir=run)

            def fake_search_plus(*args, **kwargs):  # noqa: ARG001
                return {
                    "results": [
                        {
                            "provider": "github",
                            "kind": "raw_file",
                            "title": "IrisCTF 2025 web writeup README",
                            "url": "https://raw.githubusercontent.com/example/writeups/main/README.md",
                            "summary": "README with writeup only.",
                            "source_type": "github",
                            "confidence": "medium",
                            "metadata": {"repository": "example/writeups", "path": "README.md"},
                        }
                    ],
                    "errors": [],
                    "summary": {"total_results": 1},
                    "decision_required": [],
                }

            with mock.patch.object(workflow.search_plus, "search_plus", side_effect=fake_search_plus):
                payload = workflow.run_workflow_engine(workdir=run, max_search_tasks=1)

            self.assertEqual(payload["status"], "pending_user")
            self.assertEqual([item["stage"] for item in payload["stages"]], ["research"])
            self.assertFalse((run / "auto_collect_and_route.json").exists())
            self.assertFalse(any(path.is_file() for path in (run / "downloads_accepted").rglob("*")))

    def test_download_accept_blocks_writeup_only_case_even_with_safe_preview(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            sandbox = out / "downloads_sandbox"
            sandbox.mkdir(parents=True)
            downloaded = sandbox / "0001-README.md"
            downloaded.write_text("# writeup only\n", encoding="utf-8")
            workflow.write_jsonl(
                out / "ctf_cases.jsonl",
                [
                    {
                        "case_id": "wp-only",
                        "metadata": {"名称": "WP Only", "分类": "Web"},
                        "research": {"gate": "cannot_continue", "blocking_rule": "writeup_without_attachment"},
                        "evidence": [{"source_url": "https://example.com/wp", "title": "writeup"}],
                    }
                ],
            )
            workflow.write_json(
                out / "download_preview.json",
                {
                    "records": [{"safety_status": "safe", "local_path": downloaded.as_posix()}],
                    "summary": {"total": 1, "safe": 1, "needs_review": 0, "blocked": 0, "accepted": 0},
                },
            )

            result = workflow.execute_stage_download_accept(out, allow_download_accept=True)

            self.assertEqual(result["status"], "blocked")
            self.assertFalse((out / "downloads_accepted" / "0001-README.md").exists())

    def test_collect_materials_skips_writeup_repo_readme(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {
                "results": [
                    {
                        "provider": "github",
                        "kind": "raw_file",
                        "title": "DemoCTF writeup README",
                        "url": "https://raw.githubusercontent.com/example/writeups/main/README.md",
                        "summary": "writeup only",
                        "layer": "writeup_candidate",
                        "metadata": {"repository": "example/writeups", "path": "README.md"},
                    }
                ]
            }
            manifest_path = root / "search_results.json"
            workflow.write_json(manifest_path, manifest)

            payload = workflow.collect_materials(manifest_path=manifest_path, output_dir=root)

            self.assertEqual(payload["summary"]["material_candidate_results"], 0)
            self.assertEqual(payload["summary"]["direct_asset_urls"], 0)
            self.assertEqual(payload["summary"]["github_repositories"], 0)
            self.assertFalse((root / "download_preview.json").exists())

    def test_collect_materials_downloads_direct_assets_and_previews_github(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            zip_path = root / "challenge.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("README.md", "# demo\n")
            with LocalServer(root) as server:
                manifest = {
                    "results": [
                        {"title": "asset", "url": f"{server.url}/challenge.zip", "metadata": {}},
                        {"title": "repo", "url": "https://github.com/example/democtf", "metadata": {"repository": "example/democtf"}},
                    ]
                }
                manifest_path = root / "search_results.json"
                workflow.write_json(manifest_path, manifest)
                with mock.patch.object(workflow, "blocked_url_reason", return_value=""):
                    with mock.patch.object(workflow.search, "github_release_assets", return_value=[]):
                        with mock.patch.object(
                            workflow.search,
                            "github_tree_files",
                            return_value=[
                                {"title": "example/democtf/Dockerfile", "metadata": {"path": "Dockerfile"}},
                                {"title": "example/democtf/challenge.zip", "metadata": {"path": "challenge.zip"}},
                            ],
                        ):
                            payload = workflow.collect_materials(manifest_path=manifest_path, output_dir=root / "out")

            self.assertEqual(payload["summary"]["direct_asset_urls"], 1)
            self.assertEqual(payload["summary"]["github_repositories"], 1)
            self.assertTrue((root / "out" / "download_preview.json").exists())
            self.assertIn("Dockerfile", payload["repo_previews"][0]["summary"]["docker_hints"])
            self.assertEqual(payload["resource_candidates"][0]["next_skill"], "cloversec-ctf-attachment-packager")

    def test_direct_asset_detection_includes_ctf_source_database_and_traffic_files(self):
        for suffix in [".py", ".db", ".sqlite3", ".sql", ".pcap", ".pcapng", ".elf", ".so", ".wasm", ".jar"]:
            self.assertTrue(workflow.search.looks_direct_asset_url(f"https://example.com/challenge{suffix}"), suffix)

    def test_download_sandbox_merges_existing_preview_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "solve.py").write_text("print('ok')\n", encoding="utf-8")
            (root / "users.db").write_bytes(b"sqlite-data")
            out = root / "out"

            with LocalServer(root) as server:
                with mock.patch.object(workflow, "blocked_url_reason", return_value=""):
                    workflow.download_sandbox(urls=[f"{server.url}/solve.py"], output_dir=out)
                    payload = workflow.download_sandbox(urls=[f"{server.url}/users.db"], output_dir=out)

            preview = json.loads((out / "download_preview.json").read_text(encoding="utf-8"))
            self.assertEqual(preview["summary"]["total"], 2)
            self.assertEqual(payload["preview_write"]["mode"], "merge")
            self.assertEqual([Path(item["local_path"]).name for item in preview["records"]], ["0001-solve.py", "0002-users.db"])

    def test_download_sandbox_manifest_accepts_bom_and_ctf_file_extensions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "solve.py").write_text("print('ok')\n", encoding="utf-8")
            (root / "users.db").write_bytes(b"sqlite-data")
            out = root / "out"

            with LocalServer(root) as server:
                manifest = {
                    "results": [
                        {"url": f"{server.url}/solve.py", "layer": "attachment_candidate", "metadata": {}},
                        {"url": f"{server.url}/users.db", "layer": "attachment_candidate", "metadata": {}},
                    ]
                }
                manifest_path = root / "search_results.json"
                manifest_path.write_bytes(b"\xef\xbb\xbf" + json.dumps(manifest, ensure_ascii=False).encode("utf-8"))
                with mock.patch.object(workflow, "blocked_url_reason", return_value=""):
                    payload = workflow.download_sandbox_from_manifest(manifest_path=manifest_path, output_dir=out)

            self.assertEqual(payload["summary"]["total"], 2)
            self.assertEqual({item["asset_type"] for item in payload["records"]}, {"source", "database"})

    def test_auto_collect_routes_github_tree_preview_to_dockerizer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {
                "results": [
                    {
                        "title": "IrisCTF 2025 bad-todo official challenge directory",
                        "url": "https://github.com/IrisSec/IrisCTF-2025-Challenges/tree/main/bad-todo",
                        "metadata": {},
                    }
                ]
            }
            manifest_path = root / "search_results.json"
            workflow.write_json(manifest_path, manifest)

            def fake_download_tree(repo, output_dir, **kwargs):  # noqa: ARG001
                target = Path(output_dir)
                target.mkdir(parents=True, exist_ok=True)
                (target / "Dockerfile").write_text("FROM node:20\n", encoding="utf-8")
                (target / "app.js").write_text("console.log('demo')\n", encoding="utf-8")
                return {
                    "repository": repo,
                    "ref": kwargs.get("ref", "main"),
                    "path_prefix": kwargs.get("path_prefix", ""),
                    "output_dir": target.as_posix(),
                    "downloads": [{"path": (target / "Dockerfile").as_posix()}],
                    "issues": [],
                    "summary": {"downloaded": 2, "issues": 0},
                }

            with mock.patch.object(workflow.search, "github_release_assets", return_value=[]):
                with mock.patch.object(
                    workflow.search,
                    "github_tree_files",
                    return_value=[
                        {"title": "Dockerfile", "metadata": {"path": "bad-todo/Dockerfile"}},
                        {"title": "app.js", "metadata": {"path": "bad-todo/app.js"}},
                    ],
                ):
                    with mock.patch.object(workflow.search, "download_github_tree", side_effect=fake_download_tree):
                        payload = workflow.auto_collect_and_route(manifest_path=manifest_path, output_dir=root / "out")

            self.assertEqual(payload["summary"]["github_repositories"], 1)
            self.assertEqual(payload["summary"]["routes"], 1)
            route = payload["routes"][0]
            self.assertEqual(route["recommended_next"]["skill"], "cloversec-ctf-build-dockerizer")
            self.assertEqual(route["gate"]["blocking_rule"], "github_tree_preview")

    def test_direct_asset_urls_convert_github_blob_to_raw_before_download(self):
        results = [
            {
                "title": "challenge",
                "url": "https://github.com/example/demo/blob/main/challenge.zip",
                "metadata": {},
            }
        ]

        urls = workflow.direct_asset_urls_from_results(results)

        self.assertEqual(urls, ["https://raw.githubusercontent.com/example/demo/main/challenge.zip"])

    def test_workflow_case_filter_skips_event_writeup_summary_pages(self):
        self.assertFalse(
            workflow.usable_case_result(
                {
                    "title": "CTFtime.org / IrisCTF 2025 tasks and writeups",
                    "url": "https://ctftime.org/event/2503/tasks/",
                    "layer": "writeup_candidate",
                    "score": 85,
                    "quality_issues": [],
                }
            )
        )
        self.assertFalse(
            workflow.usable_case_result(
                {
                    "title": "GitHub - juliancasaburi/irisctf-2025: Write-ups and solve scripts for IrisCTF 2025",
                    "url": "https://github.com/juliancasaburi/irisctf-2025",
                    "layer": "writeup_candidate",
                    "score": 85,
                    "quality_issues": [],
                }
            )
        )
        self.assertFalse(
            workflow.usable_case_result(
                {
                    "title": "IrisCTF 2025 Writeups - pwoofy - welcome!!",
                    "url": "https://pwoofy.me/IrisCTF_Writeups_2025/",
                    "layer": "writeup_candidate",
                    "score": 85,
                    "quality_issues": [],
                }
            )
        )
        self.assertFalse(
            workflow.usable_case_result(
                {
                    "title": "salty-byte/ctf/writeup/2025/IrisCTF 2025/README.md",
                    "url": "https://github.com/salty-byte/ctf/blob/main/writeup/2025/IrisCTF%202025/README.md",
                    "layer": "writeup_candidate",
                    "score": 85,
                    "quality_issues": [],
                    "metadata": {"path": "writeup/2025/IrisCTF 2025/README.md"},
                }
            )
        )
        self.assertFalse(
            workflow.usable_case_result(
                {
                    "title": "Seraphin-/ctf/2025/irisctf/README.md",
                    "url": "https://github.com/Seraphin-/ctf/blob/main/2025/irisctf/README.md",
                    "layer": "writeup_candidate",
                    "score": 85,
                    "quality_issues": [],
                    "metadata": {"path": "2025/irisctf/README.md"},
                }
            )
        )
        self.assertFalse(
            workflow.usable_case_result(
                {
                    "title": "ctf/2025/irisctf/README.md at master · Seraphin-/ctf · GitHub",
                    "url": "https://github.com/Seraphin-/ctf/blob/master/2025/irisctf/README.md",
                    "layer": "writeup_candidate",
                    "score": 67,
                    "quality_issues": [],
                }
            )
        )
        self.assertFalse(
            workflow.usable_case_result(
                {
                    "title": "Home : IrisCTF 2025 - CTF fun for hackers of all skill levels",
                    "url": "https://2025.irisc.tf/home",
                    "layer": "writeup_candidate",
                    "score": 67,
                    "quality_issues": [],
                }
            )
        )
        self.assertFalse(
            workflow.usable_case_result(
                {
                    "title": "irisCTF 2025 - josangeorge.vercel.app",
                    "url": "https://josangeorge.vercel.app/irisCTF%202025",
                    "layer": "writeup_candidate",
                    "score": 67,
                    "quality_issues": [],
                }
            )
        )
        self.assertFalse(
            workflow.usable_case_result(
                {
                    "title": "Iris CTF 2025 Writeup. My write-up on the challenges I… | by ... - Medium",
                    "url": "https://medium.com/@Cyb3r_Fr0g/iris-ctf-2025-write-up-2565debb1020",
                    "layer": "writeup_candidate",
                    "score": 85,
                    "quality_issues": [],
                }
            )
        )
        self.assertFalse(
            workflow.usable_case_result(
                {
                    "title": "IrisCTF 2025 Write Up - blog.whale-tw.com",
                    "url": "http://blog.whale-tw.com/2025/01/06/irisctf-2025/",
                    "layer": "writeup_candidate",
                    "score": 67,
                    "quality_issues": [],
                }
            )
        )
        self.assertFalse(
            workflow.usable_case_result(
                {
                    "title": "Challenges : IrisCTF 2025 - CTF fun for hackers of all skill levels",
                    "url": "https://2025.irisc.tf/challenges-category-Cryptography.html",
                    "layer": "writeup_candidate",
                    "score": 67,
                    "quality_issues": [],
                }
            )
        )
        self.assertFalse(
            workflow.usable_case_result(
                {
                    "title": "repo/ctf/2025/irisctf/crypto/windy-day/README.md",
                    "url": "https://github.com/example/ctf/blob/main/2025/irisctf/crypto/windy-day/README.md",
                    "layer": "writeup_candidate",
                    "score": 85,
                    "quality_issues": [],
                    "metadata": {"path": "2025/irisctf/crypto/windy-day/README.md"},
                }
            )
        )
        self.assertFalse(
            workflow.usable_case_result(
                {
                    "title": "CTFtime.org / IrisCTF 2025 / Crispy Kelp / Writeup",
                    "url": "https://ctftime.org/writeup/39761",
                    "layer": "writeup_candidate",
                    "score": 85,
                    "quality_issues": [],
                }
            )
        )

    def test_route_resource_creates_dockerizer_handoff_for_dockerfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            challenge = root / "challenge_source"
            challenge.mkdir()
            (challenge / "Dockerfile").write_text("FROM oven/bun:latest\nEXPOSE 41236\nCMD [\"bun\", \"index.js\"]\n", encoding="utf-8")
            (challenge / "index.js").write_text("console.log(Bun.env.FLAG); Bun.listen({ port: 41236, socket: { data() {} } });\n", encoding="utf-8")

            payload = workflow.route_resource(root=root, output_dir=root / "classification")
            docker_rows = [
                json.loads(line)
                for line in (root / "classification" / "Dockerizer交接表.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]

            self.assertEqual(payload["recommended_next"]["skill"], "cloversec-ctf-build-dockerizer")
            self.assertEqual(payload["dockerizer_handoff"]["required_skill"], "cloversec-ctf-build-dockerizer")
            self.assertEqual(payload["dockerizer_handoff"]["auto_action"], "manual_review")
            self.assertFalse(payload["dockerizer_handoff"]["can_auto_render"])
            self.assertTrue(payload["dockerizer_handoff"]["manual_required"])
            self.assertIn("intake", payload["dockerizer_handoff"]["recommended_command"])
            self.assertIn((root / "challenge_source").as_posix(), payload["dockerizer_handoff"]["recommended_command"])
            self.assertIn("intake", payload["dockerizer_handoff"]["input_prompt"])
            self.assertNotIn("auto-render", payload["dockerizer_handoff"]["input_prompt"])
            self.assertIn("required_user_inputs", payload["dockerizer_handoff"]["input_prompt"])
            self.assertIn("challenge.yaml", payload["dockerizer_handoff"]["required_user_inputs"])
            self.assertIn("challenge_source/Dockerfile", payload["dockerizer_handoff"]["existing_dockerfiles"])
            self.assertIn("41236", ",".join(payload["dockerizer_handoff"]["port_hints"]))
            self.assertEqual(docker_rows[0]["入口目录"], (root / "challenge_source").as_posix())
            self.assertEqual(docker_rows[0]["服务协议"], "tcp")
            self.assertIn("41236:41236", docker_rows[0]["端口线索"])
            self.assertIn("需要适配平台 /flag", docker_rows[0]["运行时Flag"])
            self.assertTrue((root / "classification" / "resource_route.json").exists())


class FakeCompleted:
    def __init__(self, returncode, stdout, stderr):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        return


class LocalServer:
    def __init__(self, root: Path):
        self.root = root
        self.httpd = None
        self.thread = None
        self.url = ""

    def __enter__(self):
        root = self.root

        class Handler(QuietHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=root.as_posix(), **kwargs)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=5)


class RedirectServer:
    def __init__(self, root: Path):
        self.root = root
        self.httpd = None
        self.thread = None
        self.url = ""

    def __enter__(self):
        root = self.root

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path == "/r1":
                    self.send_response(302)
                    self.send_header("Location", "/r2")
                    self.end_headers()
                    return
                if self.path == "/r2":
                    self.send_response(302)
                    self.send_header("Location", "/challenge.zip")
                    self.end_headers()
                    return
                if self.path == "/challenge.zip":
                    body = (root / "challenge.zip").read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/zip")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

            def log_message(self, format, *args):  # noqa: A002
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=5)


class ForbiddenServer:
    def __init__(self):
        self.httpd = None
        self.thread = None
        self.url = ""

    def __enter__(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                body = b"blocked"
                self.send_response(403)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):  # noqa: A002
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
