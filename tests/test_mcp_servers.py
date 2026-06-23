import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"


class McpServerProtocolTests(unittest.TestCase):
    def test_plugin_manifest_declares_all_mcp_servers_with_existing_scripts(self):
        plugin_dir = ROOT / "plugins" / "cloversec-ctf-forexample"
        plugin_json = json.loads((plugin_dir / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        mcp_config = json.loads((plugin_dir / ".mcp.json").read_text(encoding="utf-8"))
        servers = mcp_config["mcpServers"]

        self.assertEqual(plugin_json["mcpServers"], "./.mcp.json")
        self.assertEqual(len(servers), 8)
        self.assertIn("cloversec-ctf-workflow", servers)
        for name, server in servers.items():
            self.assertEqual(server["command"], "node")
            self.assertEqual(server["args"][0], "./scripts/mcp_python_launcher.mjs")
            launcher = plugin_dir / server["args"][0]
            script = plugin_dir / server["args"][1]
            self.assertTrue(launcher.exists(), f"{name} launcher missing: {launcher}")
            self.assertTrue(script.exists(), f"{name} script missing: {script}")
            self.assertEqual(server["env"]["PYTHONUNBUFFERED"], "1")
            self.assertEqual(server["env"]["PYTHONUTF8"], "1")
            self.assertEqual(server["env"]["PYTHONIOENCODING"], "utf-8")

    def test_manifest_mcp_servers_initialize_and_list_tools_through_node_launcher(self):
        plugin_dir = ROOT / "plugins" / "cloversec-ctf-forexample"
        mcp_config = json.loads((plugin_dir / ".mcp.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            runtime_dir = Path(tmp) / "mcp-runtime"
            for name, server in mcp_config["mcpServers"].items():
                with self.subTest(server=name):
                    responses = call_mcp_server_from_manifest(plugin_dir, server, runtime_dir=runtime_dir / name)
                    self.assertEqual(responses[0]["result"]["capabilities"], {"tools": {}})
                    self.assertGreater(len(responses[1]["result"]["tools"]), 0)

    def test_workflow_mcp_stdout_is_utf8_when_local_encoding_is_cp936(self):
        plugin_dir = ROOT / "plugins" / "cloversec-ctf-forexample"
        mcp_config = json.loads((plugin_dir / ".mcp.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            server = mcp_config["mcpServers"]["cloversec-ctf-workflow"]
            responses = call_mcp_server_from_manifest(
                plugin_dir,
                server,
                runtime_dir=Path(tmp) / "mcp-runtime",
                extra_env={"PYTHONIOENCODING": "cp936"},
                decode_as_utf8=True,
            )
        tools_text = json.dumps(responses[1], ensure_ascii=False)
        self.assertIn("Hub提交材料", tools_text)

    def test_doctor_installed_reports_mcp_command_and_smoke_checks(self):
        doctor = SCRIPTS / "cloversec_ctf_doctor.py"
        proc = subprocess.run(
            [sys.executable, str(doctor), "--installed", "--json"],
            cwd=SCRIPTS,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        by_id = {item["id"]: item for item in report["checks"]}

        self.assertEqual(report["capabilities"]["mcp_runtime"], "available")
        self.assertEqual(by_id["mcp_command_cloversec-ctf-workflow"]["status"], "ok")
        self.assertEqual(by_id["mcp_encoding_cloversec-ctf-workflow"]["status"], "ok")
        self.assertEqual(by_id["mcp_smoke_cloversec-ctf-workflow"]["status"], "ok")

    def test_all_mcp_servers_support_list_and_representative_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            runtime_dir = tmp_path / "mcp-runtime"
            cases = [
                (
                    "cloversec_ctf_search_mcp.py",
                    "cloversec_ctf_import_agent_web_results",
                    {"query": "DemoCTF 2026 web", "results": [], "provider": "unit-test"},
                ),
                (
                    "cloversec_ctf_search_plus_mcp.py",
                    "cloversec_ctf_search_plus",
                    {"query": "DemoCTF 2026 web", "sources": ["seeds"], "limit": 1, "compact": True},
                ),
                (
                    "cloversec_ctf_browser_search_mcp.py",
                    "cloversec_ctf_browser_search_plan",
                    {"query": "DemoCTF 2026 web", "engine": "google", "open_browser": False},
                ),
                (
                    "cloversec_ctf_workflow_mcp.py",
                    "cloversec_ctf_platform_contract",
                    {},
                ),
                (
                    "cloversec_ctf_docker_mcp.py",
                    "cloversec_ctf_docker_validation_plan",
                    {"case": {"case_id": "case-1"}, "project_dir": tmp, "validation_level": "static_only"},
                ),
                (
                    "cloversec_ctf_archive_mcp.py",
                    "cloversec_ctf_archive_preview",
                    {"case": {"case_id": "case-1", "metadata": {"名称": "Demo"}}, "output_dir": (tmp_path / "archive-preview").as_posix()},
                ),
                (
                    "cloversec_ctf_quality_runner_mcp.py",
                    "cloversec_ctf_batch_status_report",
                    {"cases": [], "output_dir": (tmp_path / "status").as_posix()},
                ),
                (
                    "cloversec_ctf_hub_assistant_mcp.py",
                    "cloversec_ctf_hub_validate_manifest",
                    {"manifest": {"hub_fields": {}}},
                ),
            ]
            for script_name, tool_name, arguments in cases:
                with self.subTest(script=script_name):
                    responses = call_mcp_server(SCRIPTS / script_name, tool_name, arguments, runtime_dir=runtime_dir)
                    self.assertEqual(responses[0]["result"]["capabilities"], {"tools": {}})
                    tools = responses[1]["result"]["tools"]
                    self.assertTrue(any(tool["name"] == tool_name for tool in tools))
                    self.assertIn("result", responses[2], responses[2])
                    content = responses[2]["result"].get("content", [])
                    self.assertEqual(content[0]["type"], "text")
                    json.loads(content[0]["text"])
            logs = list(runtime_dir.glob("*.jsonl"))
            self.assertGreaterEqual(len(logs), len(cases))
            for log in logs:
                rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
                self.assertTrue(rows)
                self.assertTrue(all(row["status"] == "ok" for row in rows))

    def test_workflow_mcp_handoff_tables_from_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            runtime_dir = tmp_path / "mcp-runtime"
            cases_path = tmp_path / "ctf_cases.jsonl"
            output_dir = tmp_path / "交接表"
            case = {
                "case_id": "case-demo-0001",
                "metadata": {"年份": "2026", "赛事来源": "Demo CTF", "分类": "Web", "名称": "baby sql"},
                "research": {"reproducibility_status": "writeup_only", "source_url": "https://example.com/wp"},
                "asset_collection": {"writeup_candidates": [{"url": "https://example.com/wp"}]},
            }
            cases_path.write_text(json.dumps(case, ensure_ascii=False) + "\n", encoding="utf-8")

            responses = call_mcp_server(
                SCRIPTS / "cloversec_ctf_workflow_mcp.py",
                "cloversec_ctf_handoff_tables",
                {"cases_path": cases_path.as_posix(), "output_dir": output_dir.as_posix()},
                runtime_dir=runtime_dir,
            )
            payload = json.loads(responses[2]["result"]["content"][0]["text"])
            rows = [
                json.loads(line)
                for line in (output_dir / "collection_machine.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            xlsx_exists = (output_dir / "赛事题目信息收集表.xlsx").exists()

        self.assertEqual(payload["collection"]["rows"], 1)
        self.assertTrue(xlsx_exists)
        self.assertEqual(rows[0]["case_id"], "case-demo-0001")
        self.assertEqual(rows[0]["xlsx_fields"]["名称"], "baby sql")

    def test_workflow_run_tool_description_points_to_natural_complete_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            responses = call_mcp_server(
                SCRIPTS / "cloversec_ctf_workflow_mcp.py",
                "cloversec_ctf_platform_contract",
                {},
                runtime_dir=Path(tmp) / "mcp-runtime",
            )
            tools = responses[1]["result"]["tools"]
            workflow_run = next(tool for tool in tools if tool["name"] == "cloversec_ctf_workflow_run")

        description = workflow_run["description"]
        self.assertIn("complete one CTF challenge collection", description)
        self.assertIn("final_report", description)
        self.assertIn("Chinese final delivery folder", description)

    def test_workflow_mcp_delivery_package_normalizes_raw_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            raw_output = tmp_path / "raw-output"
            archive_dir = raw_output / "archive" / "Pwn-JSFS"
            (archive_dir / "题目源码").mkdir(parents=True)
            (archive_dir / "题目镜像").mkdir()
            (archive_dir / "题目手册" / "Hub提交材料").mkdir(parents=True)
            (archive_dir / "题目源码" / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            (archive_dir / "题目镜像" / "jsfs.tar").write_bytes(b"tar")
            (archive_dir / "题目手册" / "PWN-JSFS.md").write_text("# JSFS\n", encoding="utf-8")
            (archive_dir / "题目手册" / "Hub提交材料" / "hub_fields.json").write_text("{}", encoding="utf-8")
            (raw_output / "最终归档表.xlsx").write_bytes(b"xlsx")
            (raw_output / "语雀粘贴表.md").write_text("| 题目 |\n", encoding="utf-8")

            delivery_dir = tmp_path / "最终交付"
            responses = call_mcp_server(
                SCRIPTS / "cloversec_ctf_workflow_mcp.py",
                "cloversec_ctf_delivery_package",
                {
                    "workdir": raw_output.as_posix(),
                    "outputs_dir": raw_output.as_posix(),
                    "output_dir": delivery_dir.as_posix(),
                },
                runtime_dir=tmp_path / "mcp-runtime",
            )
            payload = json.loads(responses[2]["result"]["content"][0]["text"])

            self.assertEqual(payload["package_issues"], [])
            self.assertTrue((delivery_dir / "交付说明.md").exists())
            self.assertTrue((delivery_dir / "Pwn-JSFS" / "题目手册" / "题目解题手册.md").exists())
            self.assertFalse((delivery_dir / "Pwn-JSFS" / "题目手册" / "Hub提交材料").exists())


def call_mcp_server(script: Path, tool_name: str, arguments: dict, *, runtime_dir: Path) -> list[dict]:
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": tool_name, "arguments": arguments}},
    ]
    proc = subprocess.run(
        [sys.executable, str(script)],
        input="\n".join(json.dumps(item) for item in requests) + "\n",
        capture_output=True,
        text=True,
        timeout=20,
        cwd=SCRIPTS,
        env={**os.environ, "CLOVERSEC_CTF_MCP_STATE_DIR": runtime_dir.as_posix()},
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(f"{script.name} exited {proc.returncode}: {proc.stderr}")
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if len(lines) != 3:
        raise AssertionError(f"{script.name} returned {len(lines)} lines: stdout={proc.stdout!r} stderr={proc.stderr!r}")
    return [json.loads(line) for line in lines]


def call_mcp_server_from_manifest(
    plugin_dir: Path,
    server: dict,
    *,
    runtime_dir: Path,
    extra_env: dict[str, str] | None = None,
    decode_as_utf8: bool = False,
) -> list[dict]:
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    env = {
        **os.environ,
        **{str(key): str(value) for key, value in server.get("env", {}).items()},
        **(extra_env or {}),
        "CLOVERSEC_CTF_MCP_STATE_DIR": runtime_dir.as_posix(),
    }
    proc = subprocess.run(
        [server["command"], *server["args"]],
        input=("\n".join(json.dumps(item) for item in requests) + "\n").encode("utf-8"),
        capture_output=True,
        timeout=20,
        cwd=plugin_dir / server.get("cwd", "."),
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace")
        raise AssertionError(f"{server['command']} exited {proc.returncode}: {stderr}")
    stdout = proc.stdout.decode("utf-8")
    if decode_as_utf8:
        proc.stderr.decode("utf-8")
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) != 2:
        raise AssertionError(f"manifest server returned {len(lines)} lines: stdout={stdout!r}")
    return [json.loads(line) for line in lines]


if __name__ == "__main__":
    unittest.main()
