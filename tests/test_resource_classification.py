import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import cloversec_ctf_resource as resource


class ResourceClassificationTests(unittest.TestCase):
    def test_classifies_compose_project_and_recommends_dockerizer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docker-compose.yml").write_text("services:\n  web:\n    build: .\n    ports:\n      - '8080:80'\n", encoding="utf-8")
            (root / "Dockerfile").write_text("FROM python:3.12-slim\nCOPY app.py /app.py\n", encoding="utf-8")
            (root / "app.py").write_text("print('hello')\n", encoding="utf-8")
            (root / "writeup.md").write_text("# Writeup\nflag{demo}\n", encoding="utf-8")

            payload = resource.classify_resource_root(root)

            self.assertEqual(payload["root_classification"]["project_type"], "compose_project")
            self.assertEqual(payload["root_classification"]["recommended_next_skill"], "cloversec-ctf-build-dockerizer")
            self.assertTrue(payload["platform_contract_required"])
            self.assertTrue(payload["must_use_dockerizer"])
            self.assertTrue(payload["existing_docker_is_reference_only"])
            self.assertEqual(payload["final_delivery_skill"], "cloversec-ctf-build-dockerizer")
            self.assertTrue(payload["root_classification"]["platform_delivery"]["must_use_dockerizer"])
            self.assertTrue(payload["root_classification"]["platform_delivery"]["existing_docker_is_reference_only"])
            self.assertTrue(payload["root_classification"]["platform_delivery"]["blocking_until_confirmed"])
            self.assertEqual(payload["root_classification"]["platform_delivery"]["confirmation_action"], "dockerizer")
            self.assertIn("platform_conversion", {item["type"] for item in payload["recommendations"]})
            by_name = {item["name"]: item for item in payload["resources"]}
            self.assertEqual(by_name["docker-compose.yml"]["resource_type"], "compose_file")
            self.assertEqual(by_name["Dockerfile"]["resource_type"], "dockerfile")
            self.assertEqual(by_name["writeup.md"]["resource_type"], "writeup")

    def test_classifies_attachment_archive_with_source_hint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "challenge.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("src/Dockerfile", "FROM alpine\n")
                archive.writestr("src/server.php", "<?php echo 'ok';")

            payload = resource.classify_resource_root(root)
            record = payload["resources"][0]

        self.assertEqual(record["resource_type"], "source_archive")
        self.assertEqual(record["recommended_next_skill"], "cloversec-ctf-build-dockerizer")
        self.assertEqual(record["archive_preview"]["archive_type"], "zip")
        self.assertEqual(payload["root_classification"]["project_type"], "source_archive_bundle")

    def test_classifies_binary_pcap_and_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "vuln").write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 20)
            (root / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
            (root / "dump.sqlite").write_bytes(b"SQLite format 3\x00" + b"\x00" * 20)

            payload = resource.classify_resource_root(root)
            by_name = {item["name"]: item for item in payload["resources"]}

        self.assertEqual(by_name["vuln"]["resource_type"], "binary")
        self.assertEqual(by_name["capture.pcap"]["resource_type"], "pcap")
        self.assertEqual(by_name["dump.sqlite"]["resource_type"], "database_dump")
        self.assertEqual(payload["root_classification"]["recommended_next_skill"], "cloversec-ctf-attachment-packager")

    def test_classifies_ctf_manifest_sage_and_flag_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "challenge.yaml").write_text("name: Hill Hard\ncategory: crypto\n", encoding="utf-8")
            (root / "solve.sage").write_text("print('solve')\n", encoding="utf-8")
            (root / "flag.txt").write_text("lactf{demo}\n", encoding="utf-8")

            payload = resource.classify_resource_root(root)
            by_name = {item["name"]: item for item in payload["resources"]}

        self.assertEqual(by_name["challenge.yaml"]["resource_type"], "ctf_manifest")
        self.assertEqual(by_name["solve.sage"]["resource_type"], "solver_file")
        self.assertEqual(by_name["flag.txt"]["resource_type"], "flag_file")
        self.assertEqual(payload["root_classification"]["project_type"], "challenge_metadata_bundle")
        self.assertEqual(payload["root_classification"]["recommended_next_skill"], "cloversec-ctf-asset-collector")
        self.assertFalse(payload["must_use_dockerizer"])
        self.assertEqual(payload["root_classification"]["platform_delivery"]["status"], "needs_user_material")

    def test_classifies_docker_image_tar(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tar_path = root / "image.tar"
            with tarfile.open(tar_path, "w") as archive:
                add_tar_file(archive, "manifest.json", b"[]")
                add_tar_file(archive, "repositories", b"{}")
                add_tar_file(archive, "abcd/layer.tar", b"layer")

            payload = resource.classify_resource_root(root)
            record = payload["resources"][0]

        self.assertEqual(record["resource_type"], "docker_image_tar")
        self.assertEqual(record["recommended_next_skill"], "cloversec-ctf-build-dockerizer")
        self.assertEqual(payload["root_classification"]["project_type"], "docker_image_delivery")
        self.assertEqual(payload["root_classification"]["recommended_next_skill"], "cloversec-ctf-build-dockerizer")
        self.assertTrue(payload["root_classification"]["platform_delivery"]["requires_cloversec_contract"])
        self.assertTrue(payload["root_classification"]["platform_delivery"]["must_use_dockerizer"])
        self.assertIn("platform_conversion", {item["type"] for item in payload["recommendations"]})

    def test_cli_writes_classification_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "case"
            root.mkdir()
            (root / "README.md").write_text("# WP\nsolution\n", encoding="utf-8")
            output = Path(tmp) / "resource_classification.json"

            result = subprocess.run(
                [sys.executable, str(SCRIPTS / "cloversec_ctf_resource.py"), "classify", str(root), "--output", str(output)],
                capture_output=True,
                text=True,
                check=False,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload["summary"]["project_type"], "writeup_only")

    def test_workflow_mcp_lists_resource_classify_tool(self):
        server = SCRIPTS / "cloversec_ctf_workflow_mcp.py"
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "cloversec_ctf_platform_contract", "arguments": {}}},
        ]
        result = subprocess.run(
            [sys.executable, str(server)],
            input="\n".join(json.dumps(item) for item in messages) + "\n",
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        tools = [item["name"] for item in lines[1]["result"]["tools"]]
        contract = json.loads(lines[2]["result"]["content"][0]["text"])

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cloversec_ctf_resource_classify", tools)
        self.assertIn("cloversec_ctf_platform_contract", tools)
        self.assertEqual(contract["must_use_skill"], "cloversec-ctf-build-dockerizer")
        self.assertFalse(contract["blocking_fields"]["can_archive"])

    def test_workflow_mcp_init_does_not_hit_compact_shadowing_bug(self):
        server = SCRIPTS / "cloversec_ctf_workflow_mcp.py"
        with tempfile.TemporaryDirectory() as tmp:
            messages = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "cloversec_ctf_workflow_init",
                        "arguments": {
                            "event": "Fixture CTF",
                            "years": [2026],
                            "categories": ["web"],
                            "limit": 1,
                            "out_dir": str(Path(tmp) / "run"),
                        },
                    },
                },
            ]
            result = subprocess.run(
                [sys.executable, str(server)],
                input="\n".join(json.dumps(item) for item in messages) + "\n",
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
            )
            lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
            payload = json.loads(lines[1]["result"]["content"][0]["text"])
            workdir_exists = Path(payload["workdir"]).exists()
            status_exists = (Path(payload["workdir"]) / "当前状态.md").exists()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(workdir_exists)
        self.assertTrue(status_exists)


def add_tar_file(archive: tarfile.TarFile, name: str, body: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(body)
    import io

    archive.addfile(info, io.BytesIO(body))


if __name__ == "__main__":
    unittest.main()
