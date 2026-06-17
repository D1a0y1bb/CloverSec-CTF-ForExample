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

    def test_search_recall_benchmark_writes_rate_and_false_positives(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            validation = root / "validation"
            validation.mkdir()
            sample = {
                "query": "IrisCTF 2025 web writeup attachment source",
                "summary": {
                    "provider_counts": {"duckduckgo": 2},
                    "layer_counts": {"writeup_candidate": 3, "noise": 1},
                },
                "decision_required": [],
                "top_results": [
                    {"title": "IrisCTF 2025 Web writeup", "url": "https://example.com/iris", "layer": "writeup_candidate"},
                    {"title": "Other CTF writeup", "url": "https://example.com/other", "layer": "noise"},
                ],
            }
            for name in [
                "search-irisctf-2025-web.compact.json",
                "search-lactf-2024-pwn.compact.json",
                "search-xiangyunbei-2024-pwn.compact.json",
            ]:
                (validation / name).write_text(json.dumps(sample, ensure_ascii=False), encoding="utf-8")
            output = root / "benchmark.md"

            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "search_recall_benchmark.py"),
                    "--input-dir",
                    str(validation),
                    "--output",
                    str(output),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            text = output.read_text(encoding="utf-8")
            self.assertIn("recall_rate", text)
            self.assertIn("明显误报", text)
            self.assertIn("Other CTF writeup", text)

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
