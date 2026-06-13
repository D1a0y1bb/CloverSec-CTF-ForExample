import json
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from unittest import mock
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import cloversec_ctf_search as search


class SearchEngineTests(unittest.TestCase):
    def test_parse_ctftime_writeups_extracts_links(self):
        html = """
        <html><body>
        <a href="/writeup/40461">Announce Your Name</a>
        <a href="/writeup/37172">cross-site-python</a>
        </body></html>
        """

        results = search.parse_ctftime_writeups(html, limit=10)

        self.assertEqual([item["title"] for item in results], ["Announce Your Name", "cross-site-python"])
        self.assertEqual(results[0]["url"], "https://ctftime.org/writeup/40461")
        self.assertEqual(results[0]["provider"], "ctftime")

    def test_seed_discover_returns_archive_sources_without_key(self):
        payload = search.discover("google ctf archive", sources=["seeds"], limit=10)

        urls = [item["url"] for item in payload["results"]]

        self.assertIn("https://github.com/google/google-ctf", urls)
        self.assertEqual(payload["summary"]["errors"], 0)

    def test_platform_seed_discover_returns_ctf_platforms(self):
        payload = search.discover("ctf platform", sources=["ctf-platforms"], limit=10)

        urls = [item["url"] for item in payload["results"]]

        self.assertIn("https://ctftime.org/", urls)
        self.assertTrue(any(item["provider"] == "ctf-platforms" for item in payload["results"]))

    def test_site_profile_search_marks_profile_and_query(self):
        result = search.normalize_result(
            provider="duckduckgo",
            kind="web",
            title="CSDN writeup",
            url="https://blog.csdn.net/example/article/details/1",
            summary="DuckDuckGo HTML result",
            source_type="public_web",
            confidence="low",
        )
        with mock.patch.object(search, "search_duckduckgo", return_value=[result]) as ddg:
            payload = search.discover("IrisCTF 2025", sources=["csdn"], limit=5)

        self.assertEqual(payload["results"][0]["provider"], "csdn")
        self.assertEqual(payload["results"][0]["metadata"]["search_provider"], "duckduckgo")
        self.assertIn("site:blog.csdn.net", payload["results"][0]["metadata"]["profile_query"])
        ddg.assert_called()

    def test_results_to_cases_preserves_evidence_url(self):
        manifest = {
            "query": "LA CTF archive",
            "results": [
                {
                    "provider": "seed",
                    "title": "uclaacm/lactf-archive",
                    "url": "https://github.com/uclaacm/lactf-archive",
                    "summary": "Past LA CTF challenges.",
                    "source_type": "github",
                    "confidence": "high",
                }
            ],
        }

        cases = search.results_to_cases(manifest)

        self.assertEqual(cases[0]["metadata"]["名称"], "uclaacm/lactf-archive")
        self.assertEqual(cases[0]["evidence"][0]["source_url"], "https://github.com/uclaacm/lactf-archive")
        self.assertEqual(cases[0]["metadata"]["材料状态"], "收集中")

    def test_fetch_and_download_url_against_local_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "index.html").write_text("<html><title>Local CTF</title><body>ok</body></html>", encoding="utf-8")
            (root / "challenge.zip").write_bytes(b"zip bytes")
            with LocalServer(root) as server:
                fetched = search.fetch_url(f"{server.url}/index.html")
                downloaded = search.download_url(f"{server.url}/challenge.zip", root / "downloads")

            self.assertEqual(fetched["status"], 200)
            self.assertEqual(fetched["title"], "Local CTF")
            self.assertEqual(downloaded["asset_type"], "attachment")
            self.assertTrue(Path(downloaded["local_path"]).exists())

    def test_fetch_url_rejects_non_http_scheme(self):
        with self.assertRaises(ValueError):
            search.fetch_url("file:///etc/passwd")

    def test_download_url_does_not_write_http_error_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            downloads = root / "downloads"
            with LocalServer(root) as server:
                result = search.download_url(f"{server.url}/missing.zip", downloads)

            self.assertEqual(result["status"], 404)
            self.assertEqual(result["error"], "HTTP 404")
            self.assertNotIn("local_path", result)
            self.assertFalse((downloads / "missing.zip").exists())

    def test_download_from_manifest_records_http_errors_as_issues(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {"results": []}
            with LocalServer(root) as server:
                manifest["results"].append({"url": f"{server.url}/missing.zip"})
                result = search.download_from_manifest(manifest, root / "downloads")

            self.assertEqual(result["summary"]["downloaded"], 0)
            self.assertEqual(result["summary"]["issues"], 1)
            self.assertEqual(result["issues"][0]["error"], "HTTP 404")

    def test_github_source_keeps_repository_results_when_code_search_is_skipped(self):
        repo_result = search.normalize_result(
            provider="github",
            kind="repository",
            title="example/ctf-archive",
            url="https://github.com/example/ctf-archive",
            summary="Archive",
            source_type="github",
            confidence="medium",
        )
        with mock.patch.object(search, "search_github_repositories", return_value=[repo_result]):
            with mock.patch.object(search, "search_github_code", side_effect=search.SearchSkipped("token missing")):
                payload = search.discover("example ctf", sources=["github"], limit=5)

        self.assertEqual(payload["results"][0]["url"], "https://github.com/example/ctf-archive")
        self.assertEqual(payload["summary"]["provider_counts"]["github"], 1)
        self.assertEqual(payload["errors"][0]["provider"], "github-code")
        self.assertEqual(payload["errors"][0]["status"], "skipped")

    def test_github_token_does_not_read_gh_auth_by_default(self):
        with mock.patch.dict(search.os.environ, {}, clear=True):
            with mock.patch.object(search.subprocess, "run") as run:
                token = search.github_token()

        self.assertEqual(token, "")
        run.assert_not_called()

    def test_github_token_reads_gh_auth_only_when_enabled(self):
        result = subprocess.CompletedProcess(["gh", "auth", "token"], 0, stdout="abc123\n", stderr="")

        with mock.patch.dict(search.os.environ, {"CLOVERSEC_USE_GH_AUTH_TOKEN": "1"}, clear=True):
            with mock.patch.object(search.subprocess, "run", return_value=result) as run:
                token = search.github_token()

        self.assertEqual(token, "abc123")
        run.assert_called_once()

    def test_github_release_assets_extracts_download_urls(self):
        payload = [
            {
                "tag_name": "v1.0.0",
                "name": "Release v1",
                "assets": [
                    {
                        "name": "challenge.zip",
                        "browser_download_url": "https://github.com/example/repo/releases/download/v1.0.0/challenge.zip",
                        "size": 123,
                        "content_type": "application/zip",
                        "download_count": 7,
                    }
                ],
            }
        ]

        with mock.patch.object(search, "github_json", return_value=payload):
            results = search.github_release_assets("example/repo")

        self.assertEqual(results[0]["provider"], "github-release")
        self.assertEqual(results[0]["metadata"]["asset_name"], "challenge.zip")
        self.assertEqual(results[0]["metadata"]["tag"], "v1.0.0")

    def test_github_release_assets_cli_writes_structured_provider_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "release_assets.json"
            with mock.patch.object(search, "github_release_assets", side_effect=RuntimeError("rate limited")):
                code = search.main([
                    "github-release-assets",
                    "--repo",
                    "example/repo",
                    "--output",
                    str(output),
                ])

            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(code, 0)
        self.assertEqual(payload["results"], [])
        self.assertEqual(payload["summary"]["errors"], 1)
        self.assertEqual(payload["errors"][0]["provider"], "github-release")
        self.assertIn("rate limited", payload["errors"][0]["error"])

    def test_download_github_release_assets_records_listing_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(search, "github_release_assets", side_effect=RuntimeError("rate limited")):
                payload = search.download_github_release_assets("example/repo", Path(tmp) / "downloads")

        self.assertEqual(payload["summary"]["downloaded"], 0)
        self.assertEqual(payload["summary"]["issues"], 1)
        self.assertEqual(payload["issues"][0]["provider"], "github-release")

    def test_github_blob_to_raw_url(self):
        raw_url = search.github_blob_to_raw_url("https://github.com/example/repo/blob/main/challenges/web/app.py")

        self.assertEqual(raw_url, "https://raw.githubusercontent.com/example/repo/main/challenges/web/app.py")

    def test_download_github_tree_preserves_relative_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "challenge.zip").write_bytes(b"zip bytes")
            with LocalServer(root) as server:
                item = search.normalize_result(
                    provider="github-tree",
                    kind="raw_file",
                    title="example/repo/challenges/web/challenge.zip",
                    url="https://github.com/example/repo/blob/main/challenges/web/challenge.zip",
                    summary="GitHub repository file from recursive tree",
                    source_type="github",
                    confidence="high",
                    metadata={
                        "repository": "example/repo",
                        "ref": "main",
                        "path": "challenges/web/challenge.zip",
                        "raw_url": f"{server.url}/challenge.zip",
                    },
                )
                with mock.patch.object(search, "github_tree_files", return_value=[item]):
                    result = search.download_github_tree(
                        "example/repo",
                        root / "downloads",
                        ref="main",
                        path_prefix="challenges",
                        max_files=5,
                    )

            self.assertEqual(result["summary"]["downloaded"], 1)
            local_path = Path(result["downloads"][0]["local_path"])
            self.assertEqual(local_path.name, "challenge.zip")
            self.assertEqual(local_path.parent.name, "web")
            self.assertTrue(local_path.exists())

    def test_preview_archive_flags_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "challenge.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("safe/readme.txt", "ok")
                archive.writestr("../evil.txt", "bad")

            preview = search.preview_archive(archive_path)

        self.assertEqual(preview["archive_type"], "zip")
        self.assertEqual(preview["summary"]["issues"], 1)
        self.assertTrue(any(entry["unsafe_path"] for entry in preview["entries"]))

    def test_mcp_tools_list_and_discover(self):
        process = subprocess.Popen(
            [sys.executable, str(SCRIPTS / "cloversec_ctf_search_mcp.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert process.stdin is not None
            assert process.stdout is not None
            process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
            process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n")
            process.stdin.write(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "cloversec_ctf_discover",
                            "arguments": {"query": "google ctf archive", "sources": ["seeds"], "limit": 5},
                        },
                    }
                )
                + "\n"
            )
            process.stdin.flush()
            init = json.loads(process.stdout.readline())
            tools = json.loads(process.stdout.readline())
            call = json.loads(process.stdout.readline())
        finally:
            if process.stdin:
                process.stdin.close()
            if process.stdout:
                process.stdout.close()
            process.terminate()
            process.wait(timeout=5)

        self.assertEqual(init["result"]["serverInfo"]["name"], "cloversec-ctf-search")
        self.assertTrue(any(item["name"] == "cloversec_ctf_discover" for item in tools["result"]["tools"]))
        self.assertIn("google/google-ctf", call["result"]["content"][0]["text"])


class LocalServer:
    def __init__(self, root):
        self.root = Path(root)
        self.server = None
        self.thread = None
        self.url = ""

    def __enter__(self):
        root = self.root

        class Handler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(root), **kwargs)

            def log_message(self, format, *args):
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        host, port = self.server.server_address
        self.url = f"http://{host}:{port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
