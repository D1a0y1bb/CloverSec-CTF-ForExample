import json
import subprocess
import sys
import tempfile
import threading
import unittest
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
