import json
import sys
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import cloversec_ctf_workflow as workflow


class Workflow030Tests(unittest.TestCase):
    def test_init_workflow_creates_standard_run_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            payload = workflow.init_workflow(
                event="IrisCTF",
                years=[2025],
                categories=["web"],
                limit=2,
                out_dir=out,
                allow_browser_search=True,
            )

            self.assertEqual(payload["workdir"], out.as_posix())
            self.assertTrue((out / "task_plan.json").exists())
            self.assertTrue((out / "workflow_state.json").exists())
            self.assertTrue((out / "ctf_cases.jsonl").exists())
            self.assertTrue((out / "logs").is_dir())
            self.assertTrue((out / "evidence").is_dir())
            self.assertTrue((out / "snapshots").is_dir())
            self.assertTrue((out / "classification").is_dir())
            plan = json.loads((out / "task_plan.json").read_text(encoding="utf-8"))
            self.assertEqual(plan["request"]["categories"], ["web"])
            self.assertTrue(any("IrisCTF 2025 web writeup" == item["query"] for item in plan["search_tasks"]))

    def test_batch_orchestrate_apply_tracks_per_case_state_and_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            workflow.init_workflow(event="DemoCTF", years=[2026], categories=["misc"], limit=1, out_dir=out)
            cases = [
                {"case_id": "case-1", "metadata": {"名称": "A", "分类": "Misc"}, "flag": {"value": "", "type": "unknown", "sensitive": True}},
                {"case_id": "case-2", "metadata": {"名称": "B", "分类": "Misc"}, "flag": {"value": "", "type": "unknown", "sensitive": True}},
            ]
            workflow.write_jsonl(out / "ctf_cases.jsonl", cases)

            first = workflow.batch_orchestrate(workdir=out, stage="research", mode="apply")
            second = workflow.batch_orchestrate(workdir=out, stage="research", mode="apply", resume=True)

            self.assertEqual(first["completed"], ["case-1", "case-2"])
            self.assertEqual(second["skipped"], ["case-1", "case-2"])
            state = json.loads((out / "workflow_state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["stages"]["research"]["status"], "completed")
            self.assertEqual(len(state["cases"]), 2)

    def test_github_doctor_masks_token_and_reports_failures(self):
        def fake_run(command, capture_output, text, check, timeout):
            joined = " ".join(command)
            if "auth token" in joined:
                return FakeCompleted(0, "ghp_abcdef123456\n", "")
            if "auth status" in joined:
                return FakeCompleted(0, "Logged in\n", "")
            if "/search/repositories" in joined:
                return FakeCompleted(0, '{"total_count":1}', "")
            if "/search/code" in joined:
                return FakeCompleted(1, "", "requires authentication")
            if "rate_limit" in joined:
                return FakeCompleted(0, '{"resources":{"search":{"limit":30,"remaining":29,"reset":1,"used":1}}}', "")
            return FakeCompleted(0, "", "")

        with mock.patch.object(workflow.shutil, "which", return_value="/usr/local/bin/gh"):
            with mock.patch.object(workflow.subprocess, "run", side_effect=fake_run):
                report = workflow.github_doctor(sample_query="IrisCTF")

        token_check = next(item for item in report["checks"] if item["name"] == "gh auth token")
        self.assertIn("***", token_check["stdout"])
        self.assertIn("github-repository-search", report["available_sources"])
        self.assertNotIn("github-code-search", report["available_sources"])
        self.assertEqual(report["rate_limit"]["search"]["remaining"], 29)

    def test_dedupe_candidates_and_apply_approved_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases_path = root / "cases.jsonl"
            candidates_path = root / "dedupe.json"
            merged_path = root / "merged.jsonl"
            cases = [
                {
                    "case_id": "case-a",
                    "metadata": {"赛事来源": "IrisCTF 2025", "名称": "KittyCrypt", "分类": "Crypto"},
                    "flag": {"value": "flag{a}", "type": "static", "sensitive": True},
                    "evidence": [{"source_url": "https://example.com/iris/kittycrypt", "title": "KittyCrypt writeup"}],
                },
                {
                    "case_id": "case-b",
                    "metadata": {"赛事来源": "IrisCTF 2025", "名称": "KittyCrypt", "分类": "crypto"},
                    "flag": {"value": "", "type": "unknown", "sensitive": True},
                    "evidence": [{"source_url": "https://example.com/iris/kittycrypt?utm=1", "title": "KittyCrypt writeup"}],
                },
            ]
            workflow.write_jsonl(cases_path, cases)
            payload = workflow.dedupe_cases(cases_path=cases_path, output_path=candidates_path)
            payload["candidates"][0]["approved"] = True
            workflow.write_json(candidates_path, payload)

            result = workflow.apply_dedupe(cases_path=cases_path, candidates_path=candidates_path, output_path=merged_path)
            merged = [json.loads(line) for line in merged_path.read_text(encoding="utf-8").splitlines() if line.strip()]

        self.assertEqual(result["summary"]["merged_groups"], 1)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["flag"]["value"], "flag{a}")
        self.assertEqual(set(merged[0]["research"]["merged_from"]), {"case-a", "case-b"})

    def test_download_sandbox_blocks_private_url_and_previews_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            zip_path = root / "challenge.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("README.md", "# demo\n")
            with LocalServer(root) as server:
                def fake_block_reason(url):
                    return "blocked private IP address" if "private.zip" in url else ""

                with mock.patch.object(workflow, "blocked_url_reason", side_effect=fake_block_reason):
                    payload = workflow.download_sandbox(
                        urls=[f"{server.url}/challenge.zip", "http://127.0.0.1/private.zip"],
                        output_dir=root / "out",
                        accept=True,
                        max_file_size=1024 * 1024,
                    )

        self.assertEqual(payload["summary"]["total"], 2)
        self.assertEqual(payload["records"][0]["safety_status"], "safe")
        self.assertTrue(payload["records"][0]["accepted_path"])
        self.assertEqual(payload["records"][1]["safety_status"], "blocked")

    def test_download_sandbox_limits_redirects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            zip_path = root / "challenge.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("README.md", "# redirect demo\n")
            with RedirectServer(root) as server:
                with mock.patch.object(workflow, "blocked_url_reason", return_value=""):
                    allowed = workflow.download_sandbox(
                        urls=[f"{server.url}/r1"],
                        output_dir=root / "allowed",
                        accept=False,
                        max_file_size=1024 * 1024,
                        max_redirects=2,
                    )
                    blocked = workflow.download_sandbox(
                        urls=[f"{server.url}/r1"],
                        output_dir=root / "blocked",
                        accept=False,
                        max_file_size=1024 * 1024,
                        max_redirects=1,
                    )

        self.assertEqual(allowed["records"][0]["safety_status"], "safe")
        self.assertEqual(allowed["records"][0]["redirect_count"], 2)
        self.assertEqual(blocked["records"][0]["safety_status"], "blocked")
        self.assertIn("max_redirects=1", blocked["records"][0]["issues"][0])

    def test_source_evidence_writes_snapshot_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "page.html").write_text("<html><title>Demo</title><body>ok</body></html>", encoding="utf-8")
            with LocalServer(root) as server:
                manifest = {
                    "results": [
                        {
                            "title": "Demo CTF writeup",
                            "url": f"{server.url}/page.html",
                            "summary": "writeup",
                            "provider": "local",
                            "layer": "writeup_candidate",
                            "confidence": "medium",
                            "score": 10,
                        }
                    ]
                }
                manifest_path = root / "manifest.json"
                workflow.write_json(manifest_path, manifest)
                payload = workflow.record_source_evidence(
                    manifest_path=manifest_path,
                    evidence_dir=root / "evidence",
                    snapshots_dir=root / "snapshots",
                    fetch_snapshots=True,
                )

                self.assertEqual(payload["summary"]["records"], 1)
                self.assertEqual(payload["summary"]["snapshots"], 1)
                self.assertTrue(Path(payload["records"][0]["snapshot_metadata_path"]).exists())

    def test_source_evidence_marks_http_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with ForbiddenServer() as server:
                manifest = {
                    "results": [
                        {
                            "title": "Blocked writeup",
                            "url": f"{server.url}/blocked",
                            "summary": "writeup",
                            "provider": "local",
                            "layer": "writeup_candidate",
                            "confidence": "medium",
                            "score": 10,
                        }
                    ]
                }
                manifest_path = root / "manifest.json"
                workflow.write_json(manifest_path, manifest)
                payload = workflow.record_source_evidence(
                    manifest_path=manifest_path,
                    evidence_dir=root / "evidence",
                    snapshots_dir=root / "snapshots",
                    fetch_snapshots=True,
                )

                self.assertEqual(payload["summary"]["records"], 1)
                self.assertEqual(payload["summary"]["errors"], 1)
                self.assertEqual(payload["records"][0]["http_status"], 403)
                self.assertIn("http_status=403", payload["records"][0]["missing_reason"])


class FakeCompleted:
    def __init__(self, returncode, stdout, stderr):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        return


class LocalServer:
    def __init__(self, root: Path):
        self.root = root
        self.httpd = None
        self.thread = None
        self.url = ""

    def __enter__(self):
        root = self.root

        class Handler(QuietHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=root.as_posix(), **kwargs)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=5)


class RedirectServer:
    def __init__(self, root: Path):
        self.root = root
        self.httpd = None
        self.thread = None
        self.url = ""

    def __enter__(self):
        root = self.root

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path == "/r1":
                    self.send_response(302)
                    self.send_header("Location", "/r2")
                    self.end_headers()
                    return
                if self.path == "/r2":
                    self.send_response(302)
                    self.send_header("Location", "/challenge.zip")
                    self.end_headers()
                    return
                if self.path == "/challenge.zip":
                    body = (root / "challenge.zip").read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/zip")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

            def log_message(self, format, *args):  # noqa: A002
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=5)


class ForbiddenServer:
    def __init__(self):
        self.httpd = None
        self.thread = None
        self.url = ""

    def __enter__(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                body = b"blocked"
                self.send_response(403)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):  # noqa: A002
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
