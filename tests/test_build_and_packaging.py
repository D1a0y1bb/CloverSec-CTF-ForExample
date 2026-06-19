import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import cloversec_ctf_build as build
import cloversec_ctf_package as package


class BuildWorkflowTests(unittest.TestCase):
    def test_create_docker_plan_generates_amd64_commands_and_xlsx_fields(self):
        plan = build.create_docker_plan(
            project_dir=Path("/tmp/challenge"),
            image_name="cloversec/example:local",
            tar_path=Path("/tmp/example.tar"),
            ports=["18080:80"],
            start_command="/start.sh",
        )

        self.assertEqual(plan["docker_artifacts"]["platform"], "linux/amd64")
        self.assertEqual(plan["docker_artifacts"]["tar_path"], "/tmp/example.tar")
        self.assertIn("--platform linux/amd64", plan["docker_artifacts"]["build_command"])
        self.assertIn("-p 18080:80", plan["docker_artifacts"]["run_command"])
        self.assertEqual(plan["environment"]["exposed_ports"], ["80"])
        self.assertEqual(plan["xlsx_fields"]["开放端口"], "80")
        self.assertEqual(plan["xlsx_fields"]["构建状态"], "未开始")

    def test_validate_platform_rejects_arm64_inspect(self):
        inspect_json = [{"Os": "linux", "Architecture": "arm64"}]

        platform = build.platform_from_inspect(inspect_json)
        issues = build.validate_docker_artifacts({"platform": platform})

        self.assertEqual(platform, "linux/arm64")
        self.assertTrue(any("platform must be linux/amd64" in issue for issue in issues))

    def test_update_case_with_docker_outputs_sets_environment_and_xlsx_fields(self):
        case = {"metadata": {"名称": "Example"}}
        plan = build.create_docker_plan(
            project_dir=Path("/tmp/challenge"),
            image_name="cloversec/example:local",
            tar_path=Path("/tmp/example.tar"),
            ports=["18080:80"],
        )

        updated = build.apply_docker_outputs(case, plan)

        self.assertEqual(updated["docker_artifacts"]["image_name"], "cloversec/example:local")
        self.assertEqual(updated["environment"]["platform"], "linux/amd64")
        self.assertEqual(updated["metadata"]["开放端口"], "80")
        self.assertEqual(updated["metadata"]["构建状态"], "未开始")


class AttachmentPackagingTests(unittest.TestCase):
    def test_inspect_zip_attachment_lists_files_and_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "challenge.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("README.md", "# challenge\n")
                zf.writestr("data/payload.bin", b"payload")

            manifest = package.inspect_attachment_package(archive)

        self.assertEqual(manifest["package_type"], "zip")
        self.assertTrue(manifest["can_extract"])
        self.assertEqual(manifest["entry_count"], 2)
        self.assertEqual([entry["path"] for entry in manifest["entries"]], ["README.md", "data/payload.bin"])
        self.assertEqual(manifest["status"], "ok")
        self.assertEqual(len(manifest["sha256"]), 64)

    def test_inspect_zip_attachment_reports_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "unsafe.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("../escape.txt", "bad")

            manifest = package.inspect_attachment_package(archive)

        self.assertFalse(manifest["can_extract"])
        self.assertEqual(manifest["status"], "unsafe")
        self.assertTrue(any("unsafe path" in issue for issue in manifest["issues"]))

    def test_build_attachment_manifest_updates_xlsx_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "challenge.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("README.md", "# challenge\n")

            manifest = package.build_attachment_manifest([archive])

        self.assertEqual(manifest["summary"]["total_packages"], 1)
        self.assertEqual(manifest["summary"]["ok_packages"], 1)
        self.assertEqual(manifest["xlsx_fields"]["题目类型"], "附件型")
        self.assertEqual(manifest["xlsx_fields"]["材料状态"], "只存在附件/源码线索")


if __name__ == "__main__":
    unittest.main()
