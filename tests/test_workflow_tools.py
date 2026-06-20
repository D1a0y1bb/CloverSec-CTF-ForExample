import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
sys.path.insert(0, str(PLUGIN_SCRIPTS))

import cloversec_ctf_i18n as i18n
import cloversec_ctf_workflow as workflow
import cloversec_ctf_handoff as handoff


class WorkflowToolTests(unittest.TestCase):
    def test_migrate_show_progress_and_authorize_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_path = root / "workflow_state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "run_id": "demo",
                        "cases": [
                            {
                                "case_id": "case-1",
                                "stages": {
                                    "research": {"status": "completed"},
                                    "quality": {"status": "failed"},
                                },
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            cases_path = root / "ctf_cases.jsonl"
            cases_path.write_text(
                json.dumps({"title": "Old Case", "category": "Web", "event": "DemoCTF 2026", "source_url": "https://example.com"}, ensure_ascii=False)
                + "\n",
                encoding="utf-8",
            )

            subprocess.run([sys.executable, str(ROOT / "scripts" / "migrate_workflow_state.py"), str(state_path), "--cases", str(cases_path)], check=True)
            show = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "show_progress.py"), str(state_path), "--json", "--watch", "--iterations", "1"],
                check=True,
                capture_output=True,
                text=True,
            )
            human_show = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "show_progress.py"), str(state_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            table_show = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "show_progress.py"), str(state_path), "--table"],
                check=True,
                capture_output=True,
                text=True,
            )
            plugin_show = subprocess.run(
                [sys.executable, str(PLUGIN_SCRIPTS / "show_progress.py"), str(state_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            auth = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "authorize_batch.py"),
                    "--workdir",
                    str(root),
                    "--action",
                    "docker_build",
                    "--case-id",
                    "case-1",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            progress = json.loads(show.stdout)
            auth_payload = json.loads(auth.stdout)
            self.assertEqual(progress["rows"][0]["research"], "completed")
            self.assertEqual(progress["rows"][0]["quality"], "failed")
            self.assertEqual(progress["totals"]["needs_attention"], 1)
            self.assertIn("# 当前批次进度", human_show.stdout)
            self.assertIn("需要处理：1", human_show.stdout)
            self.assertIn("case-1", human_show.stdout)
            self.assertIn("case-1", plugin_show.stdout)
            self.assertIn("# 当前批次进度", plugin_show.stdout)
            self.assertIn("case_id", table_show.stdout)
            self.assertTrue(Path(auth_payload["authorization_path"]).exists())
            migrated = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(migrated["schema_version"], "cloversec.ctf.workflow.state.v1")
            self.assertTrue(migrated["authorizations"])
            migrated_case = json.loads(cases_path.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(migrated_case["schema_version"], "cloversec.ctf.case.v1")
            self.assertEqual(migrated_case["metadata"]["名称"], "Old Case")

    def test_current_status_markdown_is_user_readable_chinese(self):
        text = workflow.render_current_status(
            {
                "run_id": "demo",
                "event": "DemoCTF",
                "years": [2026],
                "categories": ["web"],
                "status": "已完成搜索，等待材料识别",
                "cases": 3,
                "missing_material": 1,
                "pending_user": 1,
                "failed": 1,
                "output": "/tmp/demo",
                "recommended_next_stage": "archive",
                "recent_timing": {"stage": "quality", "duration_ms": 90500},
                "pending_issue_count": 2,
            }
        )

        self.assertIn("## 批次", text)
        self.assertIn("## 进度", text)
        self.assertIn("## 下一步", text)
        self.assertIn("推荐处理阶段：生成题目归档", text)
        self.assertIn("最近阶段：质量检查", text)
        self.assertIn("最近耗时：1.5 分钟", text)
        self.assertIn("待处理问题：2 项", text)
        self.assertIn("失败：1 题", text)
        self.assertIn("缺材料的题目需要继续搜索", text)

    def test_write_current_status_also_writes_pending_issues_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = workflow.initial_workflow_state("demo", "DemoCTF", [2026], ["web"], 1, root)
            state["stages"]["quality"] = {
                "status": "failed",
                "errors": [{"case_id": "case-1", "status": "failed", "message": "截图缺失"}],
            }
            (root / "workflow_state.json").write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
            (root / "ctf_cases.jsonl").write_text(
                json.dumps(
                    {
                        "case_id": "case-1",
                        "metadata": {"名称": "Demo", "分类": "Web", "题目类型": "环境型", "Flag类型": "动态Flag", "验证状态": "部分通过", "问题": "截图未完成"},
                        "flag": {"value": "flag{demo}", "type": "dynamic", "sensitive": True},
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )

            workflow.write_current_status_from_state(root)
            status_text = (root / "当前状态.md").read_text(encoding="utf-8")
            issues_text = (root / "待处理问题.md").read_text(encoding="utf-8")

        self.assertIn("待处理问题：", status_text)
        self.assertIn("截图缺失", issues_text)
        self.assertIn("截图未完成", issues_text)

    def test_stage_timing_is_recorded_for_engine_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event = {"stage": "quality", "status": "completed", "finished_at": "2026-06-20T00:00:00Z", "duration_ms": 30000}

            workflow.append_stage_timing(root, event)
            latest = workflow.latest_stage_timing(root)

            self.assertEqual(latest["stage"], "quality")
            self.assertEqual(latest["duration_text"], "30.0 秒")
            self.assertTrue((root / "cache" / "workflow_timing.jsonl").exists())

    def test_authorize_batch_rejects_hub_final_submit(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "authorize_batch.py"),
                    "--workdir",
                    tmp,
                    "--action",
                    "hub_final_submit",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Hub 最终提交不能批量预授权", result.stderr)

    def test_doctor_json_reports_capabilities(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "doctor.py"), "--json", "--installed"],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(result.stdout)
        self.assertIn("capabilities", payload)
        self.assertIn("dockerizer", payload["capabilities"])
        self.assertEqual(payload["capabilities"]["installed_package"], "available")
        self.assertTrue(any(item["id"] == "show_progress" and item["status"] == "ok" for item in payload["checks"]))

    def test_i18n_catalog_loads_key_user_messages(self):
        self.assertIn("Hub 最终提交", i18n.text("hub.final_submit_batch_forbidden"))
        self.assertIn("docker_build", i18n.text("docker.missing_batch_authorization", actions="docker_build"))

    def test_search_recall_benchmark_evaluates_verified_resource_hits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            validation = root / "validation"
            validation.mkdir()
            benchmark = root / "benchmark.json"
            benchmark.write_text(
                json.dumps(
                    {
                        "schema_version": "cloversec.ctf.search_recall_benchmark.v1",
                        "cases": [
                            {
                                "id": "hit-case",
                                "query": "Demo CTF",
                                "expected_resources": [
                                    {"id": "demo", "type": "github_repo", "value": "demo-org/demo-repo", "required": True}
                                ],
                            },
                            {
                                "id": "miss-case",
                                "query": "Missing CTF",
                                "expected_resources": [
                                    {"id": "missing", "type": "github_repo", "value": "demo-org/missing-repo", "required": True}
                                ],
                            },
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (validation / "hit-case.compact.json").write_text(
                json.dumps(
                    {
                        "query": "Demo CTF",
                        "summary": {"provider_counts": {"github-code": 1}, "layer_counts": {"writeup_candidate": 1}},
                        "top_results": [
                            {
                                "title": "demo-org/demo-repo/README.md",
                                "source_url": "https://github.com/demo-org/demo-repo/blob/main/README.md",
                                "provider": "github-code",
                                "layer": "writeup_candidate",
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (validation / "miss-case.compact.json").write_text(
                json.dumps({"query": "Missing CTF", "summary": {}, "top_results": []}, ensure_ascii=False),
                encoding="utf-8",
            )
            output = root / "benchmark.md"
            json_output = root / "benchmark.json.out"

            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "search_recall_benchmark.py"),
                    "--benchmark",
                    str(benchmark),
                    "--input-dir",
                    str(validation),
                    "--output",
                    str(output),
                    "--json-output",
                    str(json_output),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            text = output.read_text(encoding="utf-8")
            payload = json.loads(json_output.read_text(encoding="utf-8"))
            self.assertIn("resource_recall", text)
            self.assertIn("demo-org/demo-repo", text)
            self.assertIn("demo-org/missing-repo", text)
            self.assertEqual(payload["summary"]["required_resources"], 2)
            self.assertEqual(payload["summary"]["matched_required_resources"], 1)
            self.assertEqual(payload["cases"][0]["status"], "pass")
            self.assertEqual(payload["cases"][1]["status"], "needs_review")

    def test_handoff_tables_write_collection_xlsx_jsonl_and_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = {
                "case_id": "case-1",
                "metadata": {"年份": "2026", "赛事来源": "DemoCTF", "名称": "baby sql", "分类": "Web", "材料状态": "公开 WP 线索"},
                "research": {
                    "material_level": "writeup_candidate",
                    "reproducibility_status": "writeup_only",
                    "source_url": "https://example.com/wp",
                    "source_title": "baby sql writeup",
                    "next_action": "继续搜索附件",
                },
                "asset_collection": {"writeup_candidates": [{"url": "https://example.com/wp"}]},
                "confidence": "medium",
                "requires_user_confirmation": True,
                "missing_reason": "只有题解线索，缺官方附件或源码",
                "evidence": [{"source_url": "https://example.com/wp"}],
            }

            payload = handoff.write_collection_handoff([case], root)
            rows = [json.loads(line) for line in Path(payload["jsonl"]).read_text(encoding="utf-8").splitlines()]
            xlsx_exists = Path(payload["xlsx"]).exists()
            schema_exists = Path(payload["schema"]).exists()
            schema = json.loads(Path(payload["schema"]).read_text(encoding="utf-8"))

        self.assertTrue(xlsx_exists)
        self.assertTrue(schema_exists)
        self.assertEqual(schema["title"], "赛事题目信息收集表")
        self.assertEqual([item["name"] for item in schema["fields"]], handoff.COLLECTION_FIELDS)
        self.assertEqual(rows[0]["case_id"], "case-1")
        self.assertEqual(rows[0]["xlsx_fields"]["材料状态"], "公开 WP 线索")
        self.assertEqual(rows[0]["asset_collection"]["writeup_candidates"][0]["url"], "https://example.com/wp")

    def test_network_requests_are_centralized_in_http_helper(self):
        scripts = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
        offenders = []
        for path in scripts.glob("cloversec_ctf_*.py"):
            if path.name == "cloversec_ctf_http.py":
                continue
            text = path.read_text(encoding="utf-8")
            if "urlopen(" in text or "from urllib.request import" in text:
                offenders.append(path.name)

        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
