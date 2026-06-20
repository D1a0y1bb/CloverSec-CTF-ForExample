import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import cloversec_ctf_container as container
import cloversec_ctf_docker as docker_runner
import cloversec_ctf_proof as proof
import cloversec_ctf_resource as resource


class ContainerInferenceAndProofTests(unittest.TestCase):
    def test_infers_dockerfile_runtime_and_run_probe_level(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Dockerfile").write_text(
                "\n".join(
                    [
                        "FROM python:3.12-alpine",
                        "WORKDIR /app",
                        "ENV FLAG=flag{demo}",
                        "EXPOSE 8080",
                        'CMD ["python", "-m", "http.server", "8080"]',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "README.md").write_text("docker run -p 18080:8080 demo\n", encoding="utf-8")
            classification = resource.classify_resource_root(root)
            payload = container.infer_container_project(root, resource_classification=classification)

        self.assertEqual(payload["summary"]["project_type"], "container_project")
        self.assertEqual(payload["summary"]["recommended_validation_level"], "run_probe")
        self.assertTrue(payload["summary"]["platform_contract_required"])
        self.assertTrue(payload["summary"]["must_use_dockerizer"])
        self.assertTrue(payload["platform_contract_required"])
        self.assertTrue(payload["must_use_dockerizer"])
        self.assertTrue(payload["existing_docker_is_reference_only"])
        self.assertEqual(payload["final_delivery_skill"], "cloversec-ctf-build-dockerizer")
        self.assertTrue(payload["platform_delivery"]["existing_docker_is_reference_only"])
        self.assertFalse(payload["platform_delivery"]["blocking_until_confirmed"])
        self.assertEqual(payload["platform_delivery"]["auto_dockerizer"], "must_use_dockerizer")
        self.assertIn("cloversec-ctf-build-dockerizer", " ".join(payload["next_actions"]))
        self.assertIn("18080:8080", payload["summary"]["ports"])
        self.assertEqual(payload["dockerfile"]["base_images"], ["python:3.12-alpine"])
        self.assertIn("http://127.0.0.1:18080/", payload["runtime"]["probe_urls"])

    def test_readme_error_port_is_not_treated_as_runtime_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Dockerfile").write_text("FROM python:3.12-alpine\nEXPOSE 8080\n", encoding="utf-8")
            (root / "README.md").write_text(
                "\n".join(
                    [
                        "docker run -p 18080:8080 demo",
                        "error: port 5000 address already in use",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            payload = container.infer_container_project(root)

        self.assertIn("18080:8080", payload["summary"]["ports"])
        self.assertIn("8080:8080", payload["summary"]["ports"])
        self.assertNotIn("5000:5000", payload["summary"]["ports"])

    def test_infers_tcp_service_from_nc_readme_and_flag_runtime_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Dockerfile").write_text(
                "\n".join(
                    [
                        "FROM oven/bun:latest",
                        "EXPOSE 9999",
                        'CMD ["bun", "server.js"]',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "server.js").write_text("console.log(Bun.env.FLAG)\n", encoding="utf-8")
            (root / "README.md").write_text("connect with: nc chall.example 9999\n", encoding="utf-8")

            payload = container.infer_container_project(root)

        self.assertEqual(payload["runtime"]["service_protocol"], "tcp")
        self.assertEqual(payload["runtime"]["probe_urls"], [])
        self.assertEqual(payload["runtime"]["tcp_probes"][0]["target"], "tcp://127.0.0.1:9999")
        self.assertTrue(payload["flag_runtime_policy"]["requires_platform_flag_file"])
        self.assertTrue(any("/flag" in warning for warning in payload["warnings"]))

    def test_infers_compose_service_and_ports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docker-compose.yml").write_text(
                "\n".join(
                    [
                        "services:",
                        "  web:",
                        "    build: .",
                        "    image: cloversec/web-demo:local",
                        "    ports:",
                        '      - "18081:80"',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            payload = container.infer_container_project(root)

        self.assertEqual(payload["summary"]["project_type"], "compose_project")
        self.assertEqual(payload["summary"]["service_count"], 1)
        self.assertEqual(payload["compose"]["services"][0]["name"], "web")
        self.assertIn("18081:80", payload["summary"]["ports"])

    def test_image_tar_inference_still_requires_dockerizer_conversion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = root / "image.tar"
            image.write_bytes(b"not-a-real-docker-tar")
            classification = {
                "summary": {"by_resource_type": {"docker_image_tar": 1}},
                "root_classification": {"project_type": "docker_image_delivery"},
                "resources": [{"resource_type": "docker_image_tar", "relative_path": "image.tar"}],
            }

            payload = container.infer_container_project(root, resource_classification=classification)

        self.assertEqual(payload["summary"]["project_type"], "docker_image_delivery")
        self.assertTrue(payload["platform_contract_required"])
        self.assertTrue(payload["must_use_dockerizer"])
        self.assertEqual(payload["final_delivery_skill"], "cloversec-ctf-build-dockerizer")
        self.assertEqual(payload["platform_delivery"]["auto_dockerizer"], "must_use_dockerizer")
        self.assertIn("cloversec-ctf-build-dockerizer", " ".join(payload["next_actions"]))

    def test_docker_validation_levels_select_expected_operations(self):
        self.assertEqual(docker_runner.operations_for_validation_level("static_only"), [])
        self.assertEqual(docker_runner.operations_for_validation_level("inspect_only"), ["inspect"])
        self.assertEqual(docker_runner.operations_for_validation_level("inspect_only", tar_path="image.tar"), ["load", "inspect"])
        self.assertEqual(docker_runner.operations_for_validation_level("build_only"), ["build", "inspect"])
        self.assertEqual(docker_runner.operations_for_validation_level("run_probe"), ["build", "inspect", "run", "logs", "stop"])

    def test_docker_plan_rewrites_unavailable_host_port_before_run(self):
        plan = {
            "operations": ["run"],
            "ports": ["18080:80"],
            "commands": {"run": ["docker", "run", "-d", "--name", "demo", "-p", "18080:80", "image:local"]},
        }
        with mock.patch.object(docker_runner, "is_host_port_available", return_value=False), mock.patch.object(docker_runner, "find_available_port", return_value="49152"):
            docker_runner.rewrite_ports_to_available(plan)

        self.assertEqual(plan["ports"], ["49152:80"])
        self.assertEqual(plan["port_rewrites"][0]["from"], "18080:80")
        self.assertIn("49152:80", plan["commands"]["run"])
        self.assertNotIn("18080:80", plan["commands"]["run"])

    def test_static_only_execute_writes_skip_without_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = docker_runner.execute_docker_workflow(
                case={"case_id": "static-001"},
                output_dir=Path(tmp) / "docker",
                validation_level="static_only",
            )

        self.assertEqual(evidence["summary"]["status"], "skip")
        self.assertEqual(evidence["plan"]["operations"], [])
        self.assertEqual(evidence["steps"], [])

    def test_docker_execute_requires_batch_authorization_for_real_operations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            (project / "Dockerfile").write_text("FROM busybox:1.36\n", encoding="utf-8")

            evidence = docker_runner.execute_docker_workflow(
                case={"case_id": "auth-001"},
                output_dir=root / "docker",
                project_dir=project,
                image_name="cloversec/auth-test:local",
                dockerfile="Dockerfile",
                operations=["build"],
            )

        self.assertEqual(evidence["summary"]["status"], "fail")
        self.assertIn("docker_build", "; ".join(evidence["summary"]["issues"]))
        self.assertEqual(evidence["steps"], [])

    def test_docker_execute_uses_batch_authorization_to_continue(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            (project / "Dockerfile").write_text("FROM busybox:1.36\n", encoding="utf-8")
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "authorize_batch.py"),
                    "--workdir",
                    str(root),
                    "--action",
                    "docker_build",
                    "--case-id",
                    "auth-002",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            with mock.patch.object(docker_runner, "run_command", return_value={"id": "docker-build", "status": "pass", "exit_code": 0, "message": "ok"}):
                evidence = docker_runner.execute_docker_workflow(
                    case={"case_id": "auth-002"},
                    output_dir=root / "docker",
                    project_dir=project,
                    image_name="cloversec/auth-test:local",
                    dockerfile="Dockerfile",
                    operations=["build"],
                    authorization_workdir=root,
                )

        self.assertEqual(evidence["summary"]["status"], "pass")
        self.assertEqual(evidence["steps"][0]["id"], "docker-build")

    def test_docker_plan_accepts_container_inference_runtime(self):
        inference = {
            "runtime": {
                "image_name": "cloversec/demo:local",
                "build_context": "/tmp/demo",
                "dockerfile": "Dockerfile",
                "ports": ["18080:80"],
                "validation_level": "run_probe",
            }
        }
        plan = docker_runner.create_docker_validation_plan(
            case={"case_id": "docker-plan-001"},
            container_inference=inference,
        )

        self.assertEqual(plan["validation_level"], "run_probe")
        self.assertEqual(plan["operations"], ["build", "inspect", "run", "logs", "stop"])
        self.assertEqual(plan["image_name"], "cloversec/demo:local")
        self.assertEqual(plan["ports"], ["18080:80"])

    def test_proof_package_copies_evidence_and_writes_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = {
                "case_id": "proof-001",
                "metadata": {"名称": "Demo", "分类": "Web"},
                "flag": {"value": "flag{demo}"},
            }
            case_path = root / "ctf_case.json"
            resource_path = root / "resource_classification.json"
            container_path = root / "container_inference.json"
            docker_path = root / "docker_evidence.json"
            quality_path = root / "quality_review.json"
            case_path.write_text(json.dumps(case, ensure_ascii=False), encoding="utf-8")
            resource_path.write_text(json.dumps({"root_classification": {"project_type": "container_project"}}, ensure_ascii=False), encoding="utf-8")
            container_path.write_text(json.dumps({"summary": {"project_type": "container_project"}}, ensure_ascii=False), encoding="utf-8")
            docker_path.write_text(
                json.dumps({"summary": {"status": "pass", "validation_level": "run_probe", "run_verified": True}}, ensure_ascii=False),
                encoding="utf-8",
            )
            quality_path.write_text(
                json.dumps({"case_id": "proof-001", "summary": {"status": "通过"}, "checks": []}, ensure_ascii=False),
                encoding="utf-8",
            )
            payload = proof.create_proof_package(
                output_dir=root / "proof",
                case_json=case_path,
                resource_classification_path=resource_path,
                container_inference_path=container_path,
                docker_evidence_path=docker_path,
                quality_review_path=quality_path,
            )

            self.assertTrue(Path(payload["paths"]["manifest"]).exists())
            self.assertTrue(Path(payload["paths"]["report"]).exists())
            self.assertTrue(Path(payload["paths"]["hashes"]).exists())
            self.assertEqual(payload["summary"]["docker_validation_level"], "run_probe")
            self.assertTrue(payload["summary"]["flag_present"])
            self.assertGreaterEqual(len(payload["copied_evidence"]), 5)
            self.assertGreaterEqual(len(payload["hashes"]), 1)

    def test_mcp_servers_expose_container_and_proof_tools(self):
        expectations = {
            "cloversec_ctf_workflow_mcp.py": ["cloversec_ctf_container_infer"],
            "cloversec_ctf_docker_mcp.py": ["cloversec_ctf_docker_validation_plan"],
            "cloversec_ctf_quality_runner_mcp.py": ["cloversec_ctf_proof_pack"],
        }
        for script, expected_tools in expectations.items():
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / script)],
                input="\n".join(
                    [
                        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
                    ]
                )
                + "\n",
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
            )
            lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
            tools = [item["name"] for item in lines[1]["result"]["tools"]]

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(lines[0]["result"]["serverInfo"]["version"], "1.0.2")
            for expected in expected_tools:
                self.assertIn(expected, tools)


if __name__ == "__main__":
    unittest.main()
