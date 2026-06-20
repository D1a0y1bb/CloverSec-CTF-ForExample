import json
import builtins
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
DOCKERIZER = ROOT / "plugins" / "cloversec-ctf-forexample" / "skills" / "cloversec-ctf-build-dockerizer"
sys.path.insert(0, str(SCRIPTS))

import cloversec_ctf_archive_runner as archive_runner
import cloversec_ctf_quality_runner as quality_runner
import cloversec_ctf_workflow as workflow


class EndToEndTests(unittest.TestCase):
    def test_dockerizer_missing_pyyaml_error_mentions_install_command(self):
        spec = importlib.util.spec_from_file_location("dockerizer_utils_for_test", DOCKERIZER / "scripts" / "utils.py")
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        original_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "yaml":
                raise ModuleNotFoundError("missing yaml")
            return original_import(name, *args, **kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            yaml_path = Path(tmp) / "demo.yaml"
            yaml_path.write_text("a: 1\n", encoding="utf-8")
            builtins.__import__ = fake_import
            try:
                with self.assertRaises(module.ConfigError) as ctx:
                    module.load_yaml_file(yaml_path)
            finally:
                builtins.__import__ = original_import

        self.assertIn("PyYAML", str(ctx.exception))
        self.assertIn("pip install", str(ctx.exception))

    def test_attachment_case_reaches_quality_archive_and_final_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "challenge.zip"
            with zipfile.ZipFile(attachment, "w") as archive:
                archive.writestr("README.md", "demo")
            manual = root / "题目解题手册.md"
            manual.write_text("# 题目解题手册\n\n## 解题步骤\n\n得到 flag{demo}\n", encoding="utf-8")
            screenshot = root / "solve.png"
            screenshot.write_bytes(b"png")
            cases_path = root / "ctf_cases.jsonl"
            case = {
                "case_id": "case-attachment",
                "metadata": {
                    "赛事来源": "DemoCTF 2026",
                    "题目来源": "DemoCTF 2026",
                    "名称": "Attachment Demo",
                    "分类": "Misc",
                    "题目类型": "附件型",
                    "Flag类型": "静态Flag",
                    "Flag": "flag{demo}",
                    "验证状态": "通过",
                    "是否通过": "是",
                    "解题工具": "python",
                },
                "flag": {"value": "flag{demo}", "type": "static", "sensitive": True},
                "attachments": [{"path": attachment.as_posix(), "name": "challenge.zip"}],
                "writeup": {"formal_manual_path": manual.as_posix()},
                "archive": {"screenshots": [{"path": screenshot.as_posix(), "name": "solve.png"}]},
                "evidence": [{"source_url": "https://example.com/demo", "title": "Demo source"}],
            }
            workflow.write_jsonl(cases_path, [case])

            quality = quality_runner.run_quality_batch(cases_path=cases_path, output_dir=root / "quality")
            archive_payload = archive_runner.run_archive_workflow(
                cases_path=quality["paths"]["output_cases"],
                output_root=root / "archive",
                copy_files=True,
            )

            self.assertTrue(Path(quality["paths"]["summary_json"]).exists())
            self.assertTrue(Path(archive_payload["summary"]["final_xlsx"]).exists())
            self.assertTrue(Path(archive_payload["summary"]["yuque_table"]).exists())
            self.assertTrue(Path(archive_payload["summary"]["final_report"]).exists())
            self.assertEqual(archive_payload["summary"]["cases"], 1)

    def test_workflow_engine_executes_archive_quality_and_final_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "challenge.zip"
            with zipfile.ZipFile(attachment, "w") as archive:
                archive.writestr("README.md", "demo")
            manual = root / "题目解题手册.md"
            manual.write_text("# 题目解题手册\n\n## 题目说明\nDemo\n\n## 解题步骤\n得到 flag{demo}\n", encoding="utf-8")
            cases_path = root / "ctf_cases.jsonl"
            workflow.write_jsonl(
                cases_path,
                [
                    {
                        "case_id": "case-engine",
                        "metadata": {
                            "赛事来源": "DemoCTF 2026",
                            "题目来源": "DemoCTF 2026",
                            "名称": "Engine Demo",
                            "分类": "Misc",
                            "题目类型": "附件型",
                            "Flag类型": "静态Flag",
                            "Flag": "flag{demo}",
                            "验证状态": "通过",
                            "是否通过": "是",
                            "解题工具": "python",
                        },
                        "flag": {"value": "flag{demo}", "type": "static", "sensitive": True},
                        "attachments": [{"path": attachment.as_posix(), "name": "challenge.zip"}],
                        "writeup": {"formal_manual_path": manual.as_posix()},
                        "evidence": [{"source_url": "https://example.com/demo", "title": "Demo source"}],
                    }
                ],
            )

            payload = workflow.run_workflow_engine(
                workdir=root,
                stages=["archive", "quality", "final_report"],
                force=True,
            )

            self.assertIn(payload["status"], {"completed", "partial"})
            self.assertTrue((root / "workflow_engine_run.json").exists())
            self.assertTrue((root / "logs" / "workflow_engine.jsonl").exists())
            self.assertTrue((root / "归档" / "_cache" / "archive_workflow.json").exists())
            self.assertTrue((root / "质量检查" / "quality_summary.json").exists())
            self.assertTrue((root / "最终交付" / "交付说明.md").exists())
            self.assertTrue((root / "最终交付" / "待处理问题.md").exists())
            self.assertTrue((root / "最终交付" / "质量检查报告.md").exists())
            self.assertTrue((root / "_cache" / "final_report" / "最终报告.md").exists())
            self.assertFalse((root / "最终交付" / "最终报告.md").exists())
            state = json.loads((root / "workflow_state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["stages"]["final_report"]["status"], "completed")

    def test_dockerizer_static_chain_on_python_flask_example(self):
        try:
            import yaml  # noqa: F401
        except ModuleNotFoundError:
            self.skipTest("PyYAML not installed; Dockerizer YAML path is unavailable")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = DOCKERIZER / "examples" / "python-flask-basic"
            project = root / "python-flask-basic"
            shutil.copytree(source, project)
            derived = root / "derived.json"
            rendered = root / "rendered"
            summary = root / "validate.json"

            subprocess.run(
                [
                    sys.executable,
                    str(DOCKERIZER / "scripts" / "derive_config.py"),
                    "--project-dir",
                    str(project),
                    "--output",
                    str(derived),
                    "--pretty",
                ],
                check=True,
                cwd=ROOT,
            )
            subprocess.run(
                [
                    sys.executable,
                    str(DOCKERIZER / "scripts" / "render.py"),
                    "--config",
                    str(project / "challenge.yaml"),
                    "--output",
                    str(rendered),
                    "--manual",
                    "--reason",
                    "fixture static E2E",
                ],
                check=True,
                cwd=ROOT,
            )
            subprocess.run(
                [
                    "bash",
                    str(DOCKERIZER / "scripts" / "validate.sh"),
                    "--static-only",
                    "--json-summary",
                    str(summary),
                    str(rendered / "Dockerfile"),
                    str(rendered / "start.sh"),
                    str(project / "challenge.yaml"),
                ],
                check=True,
                cwd=ROOT,
            )

            self.assertTrue(derived.exists())
            self.assertTrue((rendered / "Dockerfile").exists())
            self.assertTrue((rendered / "start.sh").exists())
            self.assertTrue(summary.exists())
            data = json.loads(summary.read_text(encoding="utf-8"))
            self.assertNotEqual(data.get("status"), "error")

    def test_dockerizer_auto_render_validates_python_flask_example(self):
        try:
            import yaml  # noqa: F401
        except ModuleNotFoundError:
            self.skipTest("PyYAML not installed; Dockerizer YAML path is unavailable")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = DOCKERIZER / "examples" / "python-flask-basic"
            project = root / "python-flask-basic"
            shutil.copytree(source, project)
            rendered = root / "auto-rendered"
            summary = root / "auto-validate.json"

            result = subprocess.run(
                [
                    sys.executable,
                    str(DOCKERIZER / "scripts" / "workflow.py"),
                    "auto-render",
                    "--project-dir",
                    str(project),
                    "--output",
                    str(rendered),
                    "--json-summary",
                    str(summary),
                    "--format",
                    "json",
                ],
                cwd=DOCKERIZER,
                capture_output=True,
                text=True,
                check=False,
            )
            session = json.loads((project / ".ctfbuild" / "session.json").read_text(encoding="utf-8"))

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(session["stage"], "auto_render_validated")
            self.assertTrue((rendered / "Dockerfile").exists())
            self.assertTrue((rendered / "start.sh").exists())
            self.assertTrue(summary.exists())

    def test_dockerizer_auto_render_blocks_compose_project(self):
        try:
            import yaml  # noqa: F401
        except ModuleNotFoundError:
            self.skipTest("PyYAML not installed; Dockerizer YAML path is unavailable")

        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "compose-case"
            project.mkdir()
            (project / "docker-compose.yml").write_text("services:\n  web:\n    image: nginx\n", encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(DOCKERIZER / "scripts" / "workflow.py"),
                    "auto-render",
                    "--project-dir",
                    str(project),
                    "--format",
                    "json",
                ],
                cwd=DOCKERIZER,
                capture_output=True,
                text=True,
                check=False,
            )
            session = json.loads((project / ".ctfbuild" / "session.json").read_text(encoding="utf-8"))

            self.assertEqual(result.returncode, 2)
            self.assertEqual(session["stage"], "auto_render_blocked")
            self.assertIn("compose", result.stdout)


if __name__ == "__main__":
    unittest.main()
