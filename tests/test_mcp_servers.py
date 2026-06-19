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


if __name__ == "__main__":
    unittest.main()
