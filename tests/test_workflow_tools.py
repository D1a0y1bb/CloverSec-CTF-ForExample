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


class WorkflowToolTests(unittest.TestCase):
    def test_migrate_show_progress_and_authorize_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_path = root / "workflow_state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "run_id": "demo",
                        "cases": [{"case_id": "case-1", "stages": {"research": {"status": "completed"}}}],
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
            self.assertTrue(Path(auth_payload["authorization_path"]).exists())
            migrated = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(migrated["schema_version"], "cloversec.ctf.workflow.state.v1")
            self.assertTrue(migrated["authorizations"])
            migrated_case = json.loads(cases_path.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(migrated_case["schema_version"], "cloversec.ctf.case.v1")
            self.assertEqual(migrated_case["metadata"]["名称"], "Old Case")

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
            [sys.executable, str(ROOT / "scripts" / "doctor.py"), "--json"],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(result.stdout)
        self.assertIn("capabilities", payload)
        self.assertIn("dockerizer", payload["capabilities"])

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
