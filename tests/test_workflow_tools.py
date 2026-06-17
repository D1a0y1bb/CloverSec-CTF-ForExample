import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


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

            subprocess.run([sys.executable, str(ROOT / "scripts" / "migrate_workflow_state.py"), str(state_path)], check=True)
            show = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "show_progress.py"), str(state_path), "--json"],
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


if __name__ == "__main__":
    unittest.main()
