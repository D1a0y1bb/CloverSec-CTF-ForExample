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
from urllib.error import URLError


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import cloversec_ctf_search as search
import cloversec_ctf_browser_search as browser_search
import cloversec_ctf_search_plus as search_plus
import cloversec_ctf_http as http


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

    def test_github_repository_query_variants_relax_descriptive_words(self):
        variants = search.github_repository_query_variants("HGame 2024 Writeup Vidar Team")

        self.assertIn("HGame 2024", variants)
        self.assertIn("HGame", variants)
        self.assertIn("HGame 2024 Writeup Vidar Team", variants)

    def test_discover_uses_source_cache_when_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = search.discover("google ctf archive", sources=["seeds"], limit=3, cache_dir=tmp)
            with mock.patch.object(search, "seed_results", side_effect=AssertionError("cache was not used")):
                second = search.discover("google ctf archive", sources=["seeds"], limit=3, cache_dir=tmp)

        self.assertGreater(first["summary"]["total_results"], 0)
        self.assertGreater(second["summary"]["total_results"], 0)
        self.assertTrue(any(item.get("cache_hit") for item in second["results"]))

    def test_shared_http_get_retries_transient_url_errors(self):
        response = FakeHttpResponse(status=200, body=b"ok")
        with mock.patch.object(http, "urlopen", side_effect=[URLError("timed out"), response]):
            payload = http.http_get("https://example.com/demo", retries=1, backoff=0)

        self.assertEqual(payload["status"], 200)
        self.assertEqual(payload["body"], b"ok")
        self.assertEqual(payload["attempts"], 2)

    def test_platform_seed_discover_returns_ctf_platforms(self):
        payload = search.discover("ctf platform", sources=["ctf-platforms"], limit=10)

        urls = [item["url"] for item in payload["results"]]

        self.assertIn("https://ctftime.org/", urls)
        self.assertTrue(any(item["provider"] == "ctf-platforms" for item in payload["results"]))
        self.assertTrue(all(item["layer"] == "platform_lead" for item in payload["results"]))
        self.assertTrue(all(item["lead_only"] for item in payload["results"]))

    def test_site_profile_search_marks_profile_and_query(self):
        result = search.normalize_result(
            provider="duckduckgo",
            kind="web",
            title="IrisCTF 2025 CSDN writeup",
            url="https://blog.csdn.net/example/article/details/1",
            summary="IrisCTF 2025 web challenge writeup",
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
        self.assertEqual(cases[0]["metadata"]["材料状态"], "缺失材料,待人工确认")

    def test_results_to_cases_extracts_challenge_name_from_github_tree_path(self):
        result = search.normalize_result(
            provider="github-tree",
            kind="raw_file",
            title="demo/demo/challenges/web/baby-sql/challenge.yml",
            url="https://github.com/demo/demo/blob/main/challenges/web/baby-sql/challenge.yml",
            summary="GitHub repository file from recursive tree",
            source_type="github",
            confidence="high",
            metadata={"path": "challenges/web/baby-sql/challenge.yml"},
        )
        result["layer"] = "confirmed_challenge"
        result["score"] = 90
        manifest = {"query": "DemoCTF 2026 web", "years": [2026], "results": [result]}

        cases = search.results_to_cases(manifest)

        self.assertEqual(cases[0]["metadata"]["名称"], "baby sql")
        self.assertEqual(cases[0]["metadata"]["分类"], "Web")

    def test_results_to_cases_writes_search_gap_leads_when_no_case_matches(self):
        manifest = {
            "query": "祥云杯 2024 pwn writeup",
            "years": [2024],
            "results": [
                {
                    "provider": "duckduckgo",
                    "title": "【pwn】2022 祥云杯 部分wp - CSDN博客",
                    "url": "https://blog.csdn.net/example/article/details/1",
                    "summary": "DuckDuckGo HTML result",
                    "source_type": "public_web",
                    "confidence": "low",
                    "layer": "noise",
                    "score": 32,
                    "quality_issues": ["year mismatch: 2022"],
                }
            ],
        }

        cases = search.results_to_cases(manifest)

        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["research"]["material_level"], "search_gap")
        self.assertEqual(cases[0]["metadata"]["材料状态"], "缺失材料,待人工确认")
        self.assertEqual(cases[0]["metadata"]["是否通过"], "否")
        self.assertEqual(cases[0]["metadata"]["是否归档"], "否")
        self.assertTrue(cases[0]["requires_user_confirmation"])
        self.assertIn("待人工确认线索", cases[0]["notes"])

    def test_results_to_cases_does_not_promote_platform_homepage(self):
        manifest = {
            "query": "CTFTime 2026 web",
            "results": [
                {
                    "provider": "ctf-platforms",
                    "title": "CTFTime",
                    "url": "https://ctftime.org/",
                    "summary": "CTF platform homepage",
                    "source_type": "public_web",
                    "confidence": "low",
                    "layer": "platform_lead",
                    "lead_only": True,
                    "score": 10,
                    "quality_issues": ["platform homepage is not a confirmed challenge"],
                }
            ],
        }

        cases = search.results_to_cases(manifest)

        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["research"]["material_level"], "search_gap")
        self.assertEqual(cases[0]["metadata"]["材料状态"], "缺失材料,待人工确认")
        self.assertTrue(cases[0]["requires_user_confirmation"])

    def test_ctftime_task_page_is_not_a_continuable_case(self):
        result = search.normalize_result(
            provider="ctftime",
            kind="writeup",
            title="Demo CTF 2026 baby web writeup",
            url="https://ctftime.org/writeup/40461",
            summary="Demo CTF 2026 baby web writeup",
            source_type="ctftime",
            confidence="medium",
        )
        enriched = search.enrich_results([result], query="Demo CTF 2026 baby web", years=[2026])[0]

        self.assertEqual(enriched["layer"], "ctftime_task_lead")
        cases = search.results_to_cases({"query": "Demo CTF 2026 baby web", "years": [2026], "results": [enriched]})
        self.assertEqual(cases[0]["research"]["gate"], "cannot_continue")
        self.assertEqual(cases[0]["metadata"]["材料状态"], "缺失材料,待人工确认")

    def test_writeup_only_case_is_visible_but_not_continuable(self):
        result = {
            "provider": "agent-web-search",
            "kind": "web",
            "title": "Demo CTF 2026 baby web writeup",
            "url": "https://example.com/demo-ctf-2026-baby-web-writeup",
            "summary": "Demo CTF 2026 baby web writeup",
            "source_type": "agent_web_search",
            "confidence": "medium",
            "layer": "writeup_candidate",
            "score": 70,
            "quality_issues": [],
        }

        cases = search.results_to_cases({"query": "Demo CTF 2026 baby web", "years": [2026], "results": [result]})

        self.assertEqual(cases[0]["metadata"]["材料状态"], "公开 WP 线索")
        self.assertEqual(cases[0]["research"]["gate"], "cannot_continue")
        self.assertEqual(cases[0]["research"]["blocking_rule"], "writeup_without_attachment")

    def test_official_challenge_page_is_not_downgraded_to_writeup_only(self):
        result = {
            "provider": "agent-web-search",
            "kind": "web",
            "title": "IrisCTF 2025 Password Manager challenge",
            "url": "https://2025.irisc.tf/challenge/password-manager",
            "summary": "Official challenge page for IrisCTF 2025 Password Manager, web category.",
            "source_type": "agent_web_search",
            "confidence": "medium",
            "layer": "writeup_candidate",
            "score": 70,
            "quality_issues": [],
        }

        cases = search.results_to_cases({"query": "IrisCTF 2025 Password Manager", "years": [2025], "results": [result]})

        self.assertEqual(cases[0]["research"]["gate"], "needs_human_download")
        self.assertEqual(cases[0]["research"]["blocking_rule"], "official_page_needs_material")
        self.assertNotEqual(cases[0]["metadata"]["材料状态"], "公开 WP 线索")

    def test_github_tree_case_requires_download_before_building(self):
        result = {
            "provider": "github-tree",
            "kind": "raw_file",
            "title": "demo/demo/challenges/web/baby-sql",
            "url": "https://github.com/demo/demo/tree/main/challenges/web/baby-sql",
            "summary": "Demo CTF 2026 baby sql challenge directory",
            "source_type": "github",
            "confidence": "high",
            "layer": "confirmed_challenge",
            "score": 90,
            "quality_issues": [],
        }

        cases = search.results_to_cases({"query": "Demo CTF 2026 baby sql", "years": [2026], "results": [result]})

        self.assertEqual(cases[0]["research"]["gate"], "needs_human_download")
        self.assertEqual(cases[0]["asset_collection"]["blocking_rule"], "github_dir_unverified")

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

    def test_github_token_can_disable_gh_auth_lookup(self):
        with mock.patch.dict(search.os.environ, {"CLOVERSEC_DISABLE_GH_AUTH_TOKEN": "1"}, clear=True):
            with mock.patch.object(search.subprocess, "run") as run:
                token = search.github_token()

        self.assertEqual(token, "")
        run.assert_not_called()

    def test_github_token_reads_gh_auth_by_default(self):
        result = subprocess.CompletedProcess(["gh", "auth", "token"], 0, stdout="abc123\n", stderr="")

        with mock.patch.dict(search.os.environ, {}, clear=True):
            with mock.patch.object(search.subprocess, "run", return_value=result) as run:
                token = search.github_token()

        self.assertEqual(token, "abc123")
        run.assert_called_once()

    def test_default_discover_sources_are_free_sources(self):
        self.assertIn("github", search.DEFAULT_DISCOVER_SOURCES)
        self.assertIn("ctftime", search.DEFAULT_DISCOVER_SOURCES)
        self.assertIn("duckduckgo", search.DEFAULT_DISCOVER_SOURCES)
        self.assertIn("ctf-platforms", search.DEFAULT_DISCOVER_SOURCES)
        self.assertIn("csdn", search.DEFAULT_DISCOVER_SOURCES)
        self.assertIn("cnblogs", search.DEFAULT_DISCOVER_SOURCES)
        self.assertIn("yuque", search.DEFAULT_DISCOVER_SOURCES)
        self.assertNotIn("brave", search.DEFAULT_DISCOVER_SOURCES)
        self.assertNotIn("bing", search.DEFAULT_DISCOVER_SOURCES)
        self.assertNotIn("brave", search.SEARCH_SOURCES)
        self.assertNotIn("bing", search.SEARCH_SOURCES)

    def test_agent_search_import_scores_and_filters_wrong_event(self):
        payload = search.import_agent_search_results(
            [
                {
                    "rank": 1,
                    "title": "IrisCTF 2025 web writeup",
                    "url": "https://example.com/irisctf-2025-web-writeup",
                    "snippet": "IrisCTF 2025 web challenge writeup with source",
                },
                {
                    "rank": 2,
                    "title": "NepCTF 2025 web writeup",
                    "url": "https://blog.csdn.net/nepctf/article/details/1",
                    "snippet": "NepCTF web writeup",
                },
                {
                    "rank": 3,
                    "title": "DuckDuckGo",
                    "url": "https://duckduckgo.com/?q=IrisCTF+2025",
                    "snippet": "Search page",
                },
            ],
            query="IrisCTF 2025 web writeup",
        )

        layers_by_title = {item["title"]: item["layer"] for item in payload["results"]}
        self.assertEqual(layers_by_title["IrisCTF 2025 web writeup"], "writeup_candidate")
        self.assertEqual(layers_by_title["NepCTF 2025 web writeup"], "noise")
        self.assertEqual(layers_by_title["DuckDuckGo"], "noise")
        self.assertEqual(payload["results"][0]["provider"], "agent-web-search")
        self.assertEqual(payload["results"][0]["source_url"], "https://example.com/irisctf-2025-web-writeup")

    def test_specific_challenge_query_can_be_confirmed(self):
        payload = search.import_agent_search_results(
            [
                {
                    "rank": 1,
                    "title": "IrisCTF 2025 kittycrypt writeup",
                    "url": "https://example.com/irisctf-2025-kittycrypt",
                    "snippet": "IrisCTF 2025 crypto kittycrypt challenge writeup",
                }
            ],
            query="IrisCTF 2025 kittycrypt crypto writeup",
        )

        self.assertEqual(payload["results"][0]["layer"], "confirmed_challenge")

    def test_explicit_category_mismatch_is_downgraded(self):
        payload = search.import_agent_search_results(
            [
                {
                    "rank": 1,
                    "title": "picoCTF 2024 Forensics Writeup",
                    "url": "https://example.com/picoctf-2024-forensics",
                    "snippet": "picoCTF 2024 forensics writeup",
                },
                {
                    "rank": 2,
                    "title": "PicoCTF2024 Web Writeup_picoctf web-CSDN博客",
                    "url": "https://blog.csdn.net/example/picoctf-web",
                    "snippet": "picoCTF 2024 web writeup",
                },
                {
                    "rank": 3,
                    "title": "picoCTF 2024: NoSQL Injection - Writeup - CSDN博客",
                    "url": "https://blog.csdn.net/example/nosql-injection",
                    "snippet": "picoCTF 2024 NoSQL injection writeup",
                },
            ],
            query="picoCTF 2024 forensics writeup",
        )

        by_title = {item["title"]: item for item in payload["results"]}
        forensics = by_title["picoCTF 2024 Forensics Writeup"]
        web = by_title["PicoCTF2024 Web Writeup_picoctf web-CSDN博客"]
        nosql = by_title["picoCTF 2024: NoSQL Injection - Writeup - CSDN博客"]

        self.assertGreater(forensics["score"], web["score"])
        self.assertIn("category mismatch: web", web["quality_issues"])
        self.assertGreater(forensics["score"], nosql["score"])
        self.assertIn("category mismatch: web", nosql["quality_issues"])

    def test_wrong_year_result_is_not_counted_as_candidate(self):
        result = search.normalize_result(
            provider="duckduckgo",
            kind="web",
            title="2021 祥云杯 pwn PassWordBox_ProVersion - CSDN博客",
            url="https://example.com/xiangyunbei-2021-pwn",
            summary="祥云杯 pwn writeup",
            source_type="public_web",
            confidence="low",
        )

        enriched = search.enrich_results([result], query="祥云杯 2024 pwn writeup", years=[2024])

        self.assertEqual(enriched[0]["layer"], "noise")
        self.assertTrue(any(issue.startswith("year mismatch") for issue in enriched[0]["quality_issues"]))
        self.assertEqual(search.candidate_count(enriched), 0)

    def test_spaced_event_name_filters_other_ctfs(self):
        payload = search.import_agent_search_results(
            [
                {
                    "rank": 1,
                    "title": "LA CTF 2024 purell web writeup",
                    "url": "https://example.com/lactf-2024-purell",
                    "snippet": "LA CTF 2024 purell web challenge writeup",
                },
                {
                    "rank": 2,
                    "title": "HKCERT 2024 web writeup",
                    "url": "https://example.com/hkcert-2024-web",
                    "snippet": "HKCERT 2024 web writeup",
                },
                {
                    "rank": 3,
                    "title": "NewStarCTF 2024 week one writeup",
                    "url": "https://example.com/newstarctf",
                    "snippet": "NewStarCTF writeup",
                },
            ],
            query="LA CTF 2024 purell web writeup",
        )

        layers_by_title = {item["title"]: item["layer"] for item in payload["results"]}
        self.assertEqual(layers_by_title["LA CTF 2024 purell web writeup"], "confirmed_challenge")
        self.assertEqual(layers_by_title["HKCERT 2024 web writeup"], "noise")
        self.assertEqual(layers_by_title["NewStarCTF 2024 week one writeup"], "noise")

    def test_chinese_event_name_filters_other_contests(self):
        payload = search.import_agent_search_results(
            [
                {
                    "rank": 1,
                    "title": "第九届强网杯 2025 babyweb writeup",
                    "url": "https://example.com/qwb-2025-babyweb",
                    "snippet": "强网杯 2025 线上赛 Web babyweb 题解",
                },
                {
                    "rank": 2,
                    "title": "蓝桥杯 2025 web writeup",
                    "url": "https://example.com/lanqiao-2025-web",
                    "snippet": "蓝桥杯 2025 web 题解",
                },
            ],
            query="强网杯 2025 babyweb web writeup",
        )

        layers_by_title = {item["title"]: item["layer"] for item in payload["results"]}
        self.assertEqual(layers_by_title["第九届强网杯 2025 babyweb writeup"], "confirmed_challenge")
        self.assertEqual(layers_by_title["蓝桥杯 2025 web writeup"], "noise")
        issues_by_title = {item["title"]: item["quality_issues"] for item in payload["results"]}
        self.assertFalse(issues_by_title["第九届强网杯 2025 babyweb writeup"])

    def test_year_prefixed_event_token_is_same_event(self):
        payload = search.import_agent_search_results(
            [
                {
                    "rank": 1,
                    "title": "SUCTF2025 Writeup",
                    "url": "https://example.com/suctf2025",
                    "snippet": "SUCTF 2025 web writeup",
                },
                {
                    "rank": 2,
                    "title": "2025-SUCTF个人wp",
                    "url": "https://example.com/2025-suctf",
                    "snippet": "2025 SUCTF web wp",
                },
                {
                    "rank": 3,
                    "title": "2025 SUCTF 官方WriteUp&Docker",
                    "url": "https://example.com/2025-suctf-official-writeup-docker",
                    "snippet": "SUCTF official writeup and docker files",
                },
            ],
            query="SUCTF 2025 web writeup",
        )

        issues_by_title = {item["title"]: item["quality_issues"] for item in payload["results"]}
        self.assertFalse(issues_by_title["SUCTF2025 Writeup"])
        self.assertFalse(issues_by_title["2025-SUCTF个人wp"])
        self.assertFalse(issues_by_title["2025 SUCTF 官方WriteUp&Docker"])

    def test_kubectf_is_not_treated_as_other_event(self):
        result = search.normalize_result(
            provider="direct-url",
            kind="challenge_metadata",
            title="File Upload",
            url="https://raw.githubusercontent.com/UofTCTF/uoftctf-2026-chals-public/main/fileupload/challenge.yml",
            summary="Challenge metadata type kubectf",
            source_type="direct_url",
            confidence="medium",
            metadata={
                "challenge_metadata": {
                    "name": "File Upload",
                    "category": "Misc",
                    "type": "kubectf",
                    "files": ["dist/fileupload.zip"],
                    "question_type": "容器题",
                }
            },
        )

        enriched = search.enrich_results([result], query="UofTCTF 2026 File Upload", years=[2026])[0]

        self.assertEqual(enriched["layer"], "confirmed_challenge")
        self.assertFalse(any("kubectf" in item for item in enriched["quality_issues"]))

    def test_broad_tutorial_pages_are_noise(self):
        payload = search.import_agent_search_results(
            [
                {
                    "rank": 1,
                    "title": "2025年全国CTF夺旗赛-从零基础入门到竞赛_suctf 2025 writeup",
                    "url": "https://blog.csdn.net/example",
                    "snippet": "从零基础入门到竞赛，看这一篇",
                }
            ],
            query="SUCTF 2025 web writeup",
        )

        self.assertEqual(payload["results"][0]["layer"], "noise")
        self.assertIn("broad tutorial page", payload["results"][0]["quality_issues"])

    def test_weak_recall_recovery_adds_relaxed_queries(self):
        recovered = search.normalize_result(
            provider="duckduckgo",
            kind="web",
            title="2022_祥云杯_pwn 部分wp",
            url="https://example.com/xiangyun-pwn-wp",
            summary="祥云杯 pwn writeup",
            source_type="public_web",
            confidence="low",
        )

        def fake_duckduckgo(query, *, limit=20):
            if query == "祥云杯 2024 pwn writeup":
                return []
            if "祥云杯 pwn" in query:
                return [recovered]
            return []

        with mock.patch.object(search, "search_duckduckgo", side_effect=fake_duckduckgo):
            payload = search.discover("祥云杯 2024 pwn writeup", years=[2024], sources=["duckduckgo"], limit=5)

        self.assertEqual(payload["recall_recovery"]["status"], "will_run")
        self.assertGreaterEqual(len(payload["recall_recovery"]["agent_web_search_queries"]), 1)
        self.assertEqual(payload["results"][0]["url"], "https://example.com/xiangyun-pwn-wp")
        self.assertTrue(payload["results"][0]["year_relaxed"])
        self.assertEqual(payload["results"][0]["metadata"]["recovery_reason"], "weak_recall")
        self.assertEqual(payload["results"][0]["layer"], "noise")
        self.assertTrue(any(issue.startswith("year mismatch") for issue in payload["results"][0]["quality_issues"]))
        self.assertEqual(payload["recall_recovery"]["after_recovery"]["candidate_count"], 0)

    def test_search_plus_requires_decision_when_recall_stays_weak(self):
        wrong_year = search.normalize_result(
            provider="duckduckgo",
            kind="web",
            title="2021 祥云杯 pwn writeup",
            url="https://example.com/xiangyunbei-2021-pwn",
            summary="祥云杯 pwn writeup",
            source_type="public_web",
            confidence="low",
        )
        base_manifest = {
            "query": "祥云杯 2024 pwn writeup",
            "years": [2024],
            "generated_at": search.utc_now(),
            "sources": ["duckduckgo"],
            "results": [wrong_year],
            "recall_recovery": {
                "status": "will_run",
                "should_run": True,
                "minimum_candidates": 3,
                "agent_web_search_queries": ["祥云杯 pwn writeup"],
                "browser_search_queries": [{"engine": "google", "query": "祥云杯 pwn writeup"}],
            },
            "summary": {"total_results": 1, "errors": 0},
            "errors": [],
        }

        with mock.patch.object(search, "discover", return_value=base_manifest):
            payload = search_plus.search_plus(
                "祥云杯 2024 pwn writeup",
                years=[2024],
                sources=["duckduckgo"],
                compact=True,
            )

        self.assertEqual(payload["summary"]["layer_counts"]["noise"], 1)
        self.assertEqual(payload["decision_required"][0]["type"], "weak_recall")
        self.assertTrue(any("Agent 联网搜索" in action for action in payload["next_actions"]))

    def test_recall_recovery_not_needed_when_enough_candidates(self):
        candidates = [
            search.normalize_result(
                provider="duckduckgo",
                kind="web",
                title=f"IrisCTF 2025 web writeup {index}",
                url=f"https://example.com/iris-{index}",
                summary="IrisCTF 2025 web writeup",
                source_type="public_web",
                confidence="low",
            )
            for index in range(3)
        ]
        with mock.patch.object(search, "search_duckduckgo", return_value=candidates):
            payload = search.discover("IrisCTF 2025 web writeup", years=[2025], sources=["duckduckgo"], limit=5)

        self.assertEqual(payload["recall_recovery"]["status"], "not_needed")
        self.assertFalse(payload["recall_recovery"]["should_run"])
        self.assertEqual(payload["recall_recovery"]["agent_web_search_queries"], [])
        self.assertEqual(payload["recall_recovery"]["browser_search_queries"], [])

    def test_markdown_writeup_is_not_attachment_candidate(self):
        result = search.normalize_result(
            provider="github-code",
            kind="code",
            title="salty-byte/ctf/writeup/2025/IrisCTF 2025/README.md",
            url="https://github.com/salty-byte/ctf/blob/main/writeup/2025/IrisCTF%202025/README.md",
            summary="IrisCTF 2025 web writeup source notes",
            source_type="github",
            confidence="high",
        )

        enriched = search.enrich_results([result], query="IrisCTF 2025 web writeup", years=[2025])[0]

        self.assertNotEqual(enriched["layer"], "attachment_candidate")

    def test_github_release_assets_extracts_download_urls(self):
        payload = [
            {
                "tag_name": "v1.0.5",
                "name": "Release v1",
                "assets": [
                    {
                        "name": "challenge.zip",
                        "browser_download_url": "https://github.com/example/repo/releases/download/v1.0.5/challenge.zip",
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
        self.assertEqual(results[0]["metadata"]["tag"], "v1.0.5")

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

    def test_browser_search_plan_and_visible_import(self):
        plan = browser_search.create_browser_search_plan("IrisCTF 2025 web writeup", engine="google")
        self.assertIn("https://www.google.com/search?", plan["search_url"])
        self.assertIn("IrisCTF+2025+web+writeup", plan["search_url"])
        self.assertFalse(plan["opened"])
        self.assertTrue(any("Cookie" in item for item in plan["privacy_boundary"]))

        payload = browser_search.normalize_visible_results(
            {
                "results": [
                    {
                        "rank": 1,
                        "title": "IrisCTF 2025 web writeup",
                        "url": "https://example.com/irisctf-2025-web",
                        "snippet": "IrisCTF 2025 web challenge writeup source",
                    },
                    {
                        "rank": 2,
                        "title": "Compfest CTF 2025 writeup",
                        "url": "https://example.com/compfest",
                        "snippet": "Compfest CTF",
                    },
                ]
            },
            query="IrisCTF 2025 web writeup",
            engine="google",
        )
        layers_by_title = {item["title"]: item["layer"] for item in payload["results"]}
        self.assertEqual(layers_by_title["IrisCTF 2025 web writeup"], "writeup_candidate")
        self.assertEqual(layers_by_title["Compfest CTF 2025 writeup"], "noise")

    def test_browser_search_blocked_result_is_structured(self):
        payload = browser_search.normalize_visible_results(
            {"blocked_by_captcha": True, "blocked_reason": "captcha page"},
            query="IrisCTF 2025",
            engine="baidu",
        )

        self.assertEqual(payload["errors"][0]["status"], "blocked_by_captcha")
        self.assertEqual(payload["results"], [])

    def test_browser_dom_to_visible_writes_visible_results_and_scores(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "visible_results.json"
            payload = browser_search.dom_to_visible_bundle(
                {
                    "links": [
                        {
                            "text": "IrisCTF 2025 web writeup",
                            "href": "https://example.com/irisctf-2025-web",
                            "snippet": "IrisCTF 2025 web challenge writeup source",
                        },
                        {
                            "text": "DuckDuckGo",
                            "href": "https://duckduckgo.com/?q=IrisCTF+2025",
                        },
                    ]
                },
                query="IrisCTF 2025 web writeup",
                engine="google",
                page_url="https://www.google.com/search?q=IrisCTF+2025+web+writeup",
                output_path=output,
            )
            visible = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(visible["schema_version"], "cloversec.ctf.visible_results.v1")
        self.assertEqual(len(visible["results"]), 2)
        self.assertEqual(payload["visible_results_path"], str(output))
        layers_by_title = {item["title"]: item["layer"] for item in payload["top_results"]}
        self.assertEqual(layers_by_title["IrisCTF 2025 web writeup"], "writeup_candidate")
        self.assertEqual(layers_by_title["DuckDuckGo"], "noise")

    def test_search_plus_compact_merges_sources_and_writes_full_output(self):
        base_result = search.normalize_result(
            provider="seed",
            kind="challenge_archive",
            title="google/google-ctf",
            url="https://github.com/google/google-ctf",
            summary="Google CTF challenge archive",
            source_type="github",
            confidence="high",
        )
        base_manifest = {
            "query": "IrisCTF 2025 web writeup",
            "years": [2025],
            "generated_at": search.utc_now(),
            "sources": ["seeds"],
            "results": [base_result],
            "recall_recovery": {"status": "not_needed", "should_run": False},
            "summary": {"total_results": 1, "errors": 0},
            "errors": [],
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "challenge.zip").write_bytes(b"zip bytes")
            full_output = root / "full_search_plus.json"
            with LocalServer(root) as server:
                with mock.patch.object(search, "discover", return_value=base_manifest):
                    payload = search_plus.search_plus(
                        "IrisCTF 2025 web writeup",
                        years=[2025],
                        sources=["seeds"],
                        agent_results=[
                            {
                                "rank": 1,
                                "title": "IrisCTF 2025 web writeup",
                                "url": "https://example.com/irisctf-2025-web",
                                "snippet": "IrisCTF 2025 web challenge writeup source",
                            }
                        ],
                        direct_urls=[f"{server.url}/challenge.zip"],
                        output_path=full_output,
                        compact=True,
                    )

            full = json.loads(full_output.read_text(encoding="utf-8"))

        self.assertEqual(payload["schema_version"], "cloversec.ctf.search_plus.compact.v1")
        self.assertEqual(payload["full_output_path"], str(full_output))
        self.assertEqual(full["schema_version"], "cloversec.ctf.search_plus.v1")
        self.assertEqual(full["summary"]["direct_urls_previewed"], 1)
        self.assertTrue(any(item["provider"] == "direct-url" for item in full["results"]))
        self.assertLessEqual(len(payload["top_results"]), search_plus.DEFAULT_COMPACT_RESULTS)

    def test_search_plus_challenge_metadata_becomes_case(self):
        base_manifest = {
            "query": "UofTCTF 2026 File Upload",
            "years": [2026],
            "generated_at": search.utc_now(),
            "sources": ["seeds"],
            "results": [],
            "recall_recovery": {"status": "not_needed", "should_run": False},
            "summary": {"total_results": 0, "errors": 0},
            "errors": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            challenge_dir = root / "UofTCTF" / "uoftctf-2026-chals-public" / "fileupload"
            (challenge_dir / "dist").mkdir(parents=True)
            (challenge_dir / "dist" / "fileupload.zip").write_bytes(b"zip bytes")
            (challenge_dir / "challenge.yml").write_text(
                "\n".join(
                    [
                        "name: File Upload",
                        "category: Misc",
                        "type: kubectf",
                        "value: 500",
                        "flag: UofTCTF{demo_flag}",
                        "files:",
                        "  - dist/fileupload.zip",
                    ]
                ),
                encoding="utf-8",
            )
            with LocalServer(root) as server:
                with mock.patch.object(search, "discover", return_value=base_manifest):
                    payload = search_plus.search_plus(
                        "UofTCTF 2026 File Upload",
                        years=[2026],
                        sources=["seeds"],
                        direct_urls=[f"{server.url}/UofTCTF/uoftctf-2026-chals-public/fileupload/challenge.yml"],
                        compact=False,
                    )

        top = payload["results"][0]
        self.assertEqual(top["kind"], "challenge_metadata")
        self.assertEqual(top["layer"], "confirmed_challenge")
        self.assertEqual(top["title"], "File Upload")
        cases = search.results_to_cases(payload)

        self.assertEqual(cases[0]["metadata"]["题目名称"], "File Upload")
        self.assertEqual(cases[0]["metadata"]["分类"], "Misc")
        self.assertEqual(cases[0]["metadata"]["题目类型"], "容器题")
        self.assertEqual(cases[0]["metadata"]["Flag"], "UofTCTF{demo_flag}")
        self.assertEqual(cases[0]["metadata"]["材料状态"], "存在源码/附件线索+官方题解线索")
        self.assertTrue(
            any(
                item["source_url"].endswith("/challenges/fileupload/dist/fileupload.zip")
                or item["source_url"].endswith("/UofTCTF/uoftctf-2026-chals-public/fileupload/dist/fileupload.zip")
                for item in cases[0]["asset_collection"]["attachment_candidates"]
            )
        )

    def test_search_plus_github_repo_accepts_url_and_path_args(self):
        with mock.patch.object(search, "github_release_assets", return_value=[]) as release_assets:
            with mock.patch.object(search, "github_tree_files", return_value=[]) as tree_files:
                payload = search_plus.collect_github_repo_sources(
                    [{"url": "https://github.com/UofTCTF/uoftctf-2026-chals-public", "path": "fileupload"}],
                    limit=5,
                )

        self.assertEqual(payload["summary"]["repositories"], 1)
        release_assets.assert_called_once_with("UofTCTF/uoftctf-2026-chals-public", limit=5)
        tree_files.assert_called_once_with(
            "UofTCTF/uoftctf-2026-chals-public",
            ref="main",
            path_prefix="fileupload",
            limit=5,
        )

    def test_search_plus_github_tree_parses_challenge_metadata(self):
        tree_item = search.normalize_result(
            provider="github-tree",
            kind="raw_file",
            title="UofTCTF/uoftctf-2026-chals-public/fileupload/challenge.yml",
            url="https://github.com/UofTCTF/uoftctf-2026-chals-public/blob/main/fileupload/challenge.yml",
            summary="GitHub repository file from recursive tree",
            source_type="github",
            confidence="high",
            metadata={
                "repository": "UofTCTF/uoftctf-2026-chals-public",
                "ref": "main",
                "path": "fileupload/challenge.yml",
                "raw_url": "https://raw.githubusercontent.com/UofTCTF/uoftctf-2026-chals-public/main/fileupload/challenge.yml",
            },
        )
        fetched = {
            "status": 200,
            "content_type": "text/plain; charset=utf-8",
            "size": 110,
            "truncated": False,
            "sha256": "demo",
            "title": "",
            "text": "\n".join(
                [
                    "name: File Upload",
                    "category: Misc",
                    "type: kubectf",
                    "files:",
                    "  - dist/fileupload.zip",
                ]
            ),
        }
        with mock.patch.object(search, "github_release_assets", return_value=[]):
            with mock.patch.object(search, "github_tree_files", return_value=[tree_item]):
                with mock.patch.object(search, "fetch_url", return_value=fetched):
                    payload = search_plus.collect_github_repo_sources(
                        [{"url": "https://github.com/UofTCTF/uoftctf-2026-chals-public", "path": "fileupload"}],
                        limit=5,
                    )

        self.assertEqual(payload["results"][0]["kind"], "challenge_metadata")
        self.assertEqual(payload["results"][0]["title"], "File Upload")
        self.assertEqual(payload["results"][0]["metadata"]["challenge_metadata"]["category"], "Misc")

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
        self.assertTrue(any(item["name"] == "cloversec_ctf_import_agent_web_results" for item in tools["result"]["tools"]))
        self.assertIn("google/google-ctf", call["result"]["content"][0]["text"])

    def test_browser_mcp_tools_list_and_import(self):
        process = subprocess.Popen(
            [sys.executable, str(SCRIPTS / "cloversec_ctf_browser_search_mcp.py")],
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
                            "name": "cloversec_ctf_browser_search_import_visible",
                            "arguments": {
                                "query": "IrisCTF 2025 web writeup",
                                "engine": "google",
                                "results": [
                                    {
                                        "rank": 1,
                                        "title": "IrisCTF 2025 web writeup",
                                        "url": "https://example.com/irisctf-2025-web",
                                        "snippet": "IrisCTF 2025 web challenge writeup source",
                                    }
                                ],
                            },
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

        self.assertEqual(init["result"]["serverInfo"]["name"], "cloversec-ctf-browser-search")
        self.assertTrue(any(item["name"] == "cloversec_ctf_browser_search_plan" for item in tools["result"]["tools"]))
        self.assertTrue(any(item["name"] == "cloversec_ctf_browser_search_dom_to_visible" for item in tools["result"]["tools"]))
        self.assertIn("browser-google", call["result"]["content"][0]["text"])
        self.assertIn("writeup_candidate", call["result"]["content"][0]["text"])

    def test_search_plus_mcp_tools_list_and_compact_call(self):
        process = subprocess.Popen(
            [sys.executable, str(SCRIPTS / "cloversec_ctf_search_plus_mcp.py")],
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
                            "name": "cloversec_ctf_search_plus",
                            "arguments": {
                                "query": "IrisCTF 2025 web writeup",
                                "sources": ["seeds"],
                                "agent_results": [
                                    {
                                        "rank": 1,
                                        "title": "IrisCTF 2025 web writeup",
                                        "url": "https://example.com/irisctf-2025-web",
                                        "snippet": "IrisCTF 2025 web challenge writeup source",
                                    }
                                ],
                            },
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

        self.assertEqual(init["result"]["serverInfo"]["name"], "cloversec-ctf-search-plus")
        self.assertTrue(any(item["name"] == "cloversec_ctf_search_plus" for item in tools["result"]["tools"]))
        self.assertIn("cloversec.ctf.search_plus.compact.v1", call["result"]["content"][0]["text"])


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


class FakeHttpResponse:
    def __init__(self, *, status: int, body: bytes):
        self.status = status
        self.body = body
        self.headers = {"content-type": "text/plain"}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, read_limit: int) -> bytes:
        return self.body[:read_limit]

    def geturl(self) -> str:
        return "https://example.com/demo"


if __name__ == "__main__":
    unittest.main()
