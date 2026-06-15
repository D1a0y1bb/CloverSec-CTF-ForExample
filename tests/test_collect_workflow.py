import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import cloversec_ctf_collect as collect
import cloversec_ctf_data as data


class CollectWorkflowTests(unittest.TestCase):
    def test_normalize_legacy_row_keeps_full_flag_when_present(self):
        row = {
            "HUB编号": "CTF-2026050001",
            "赛事来源": "2026 示例赛",
            "名称": "Only Picture Up",
            "分类": "web渗透",
            "提交用户名": "测试用户",
            "是否归档": "是",
            "Flag": "flag{legacy-full-flag}",
        }

        case = collect.legacy_row_to_case(row, row_number=2)

        self.assertEqual(case["case_id"], "legacy-000002")
        self.assertEqual(case["metadata"]["赛事来源"], "2026 示例赛")
        self.assertEqual(case["metadata"]["题目来源"], "2026 示例赛")
        self.assertEqual(case["metadata"]["题目类型"], "未知")
        self.assertEqual(case["flag"]["value"], "flag{legacy-full-flag}")

    def test_validate_evidence_reports_missing_source(self):
        case = {
            "case_id": "case-001",
            "metadata": {"名称": "No Source", "分类": "Misc"},
            "evidence": [{"summary": "只有描述，没有来源"}],
        }

        issues = collect.validate_collection_case(case)

        self.assertTrue(any("evidence[0].source_url" in issue for issue in issues))

    def test_validate_evidence_reports_empty_list_clearly(self):
        case = {
            "case_id": "case-empty",
            "metadata": {"名称": "No Evidence", "分类": "Web"},
            "evidence": [],
        }

        issues = collect.validate_collection_case(case)

        self.assertIn("case-empty: evidence 为空；至少需要一条 source_url 或 local_path", issues)

    def test_validate_evidence_accepts_agent_browser_and_download_statuses(self):
        case = {
            "case_id": "case-agent-evidence",
            "metadata": {"名称": "Agent Evidence", "分类": "Web"},
            "evidence": [
                {"source_url": "https://example.com/a", "source_type": "agent_web_search", "status": "found", "confidence": "medium"},
                {"source_url": "https://example.com/b", "source_type": "browser_visible", "status": "previewed", "confidence": "low"},
                {"source_url": "https://github.com/a/b/releases/download/v1/challenge.zip", "source_type": "github_release", "status": "downloaded", "confidence": "high"},
            ],
        }

        issues = collect.validate_collection_case(case)

        self.assertEqual(issues, [])

    def test_validate_collection_json_cli_reports_empty_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_path = Path(tmp) / "cases.jsonl"
            case_path.write_text(
                json.dumps(
                    {
                        "case_id": "case-empty",
                        "metadata": {"名称": "No Evidence", "分类": "Web"},
                        "evidence": [],
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "cloversec_ctf_collect.py"),
                    "validate-collection",
                    str(case_path),
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        payload = json.loads(result.stdout)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["valid"])
        self.assertIn("case-empty: evidence 为空；至少需要一条 source_url 或 local_path", payload["issues"])

    def test_build_asset_inventory_hashes_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "challenge.zip"
            writeup = root / "writeup.md"
            attachment.write_bytes(b"zip bytes")
            writeup.write_text("# Writeup\n", encoding="utf-8")

            manifest = collect.build_asset_inventory(root)

        by_name = {item["name"]: item for item in manifest["assets"]}
        self.assertEqual(by_name["challenge.zip"]["asset_type"], "attachment")
        self.assertEqual(by_name["writeup.md"]["asset_type"], "writeup")
        self.assertEqual(by_name["challenge.zip"]["sha256"], "5b7a2754b389130e138d57ba83f1eae7f05a41c66becacfa2dd2060143ae66db")
        self.assertEqual(manifest["summary"]["total_assets"], 2)

    def test_render_research_report_lists_missing_fields(self):
        cases = [
            {
                "case_id": "case-001",
                "metadata": {"赛事来源": "2026 示例赛", "名称": "Web 1", "分类": "Web"},
                "flag": {"value": "", "type": "unknown", "sensitive": True},
                "evidence": [{"source_url": "https://example.com/game", "summary": "赛事页", "confidence": "high"}],
            },
            {
                "case_id": "case-002",
                "metadata": {"赛事来源": "", "名称": "Unknown", "分类": ""},
                "flag": {"value": "", "type": "unknown", "sensitive": True},
                "evidence": [],
            },
        ]

        report = collect.render_research_report(cases, title="2026 赛题收集")

        self.assertIn("# 2026 赛题收集", report)
        self.assertIn("| case-002 |  | Unknown |  |", report)
        self.assertIn("case-002: 缺少 分类", report)

    def test_migrate_xlsx_to_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "legacy.xlsx"
            output = Path(tmp) / "cases.jsonl"
            data.write_rows_xlsx(
                [
                    {
                        "HUB编号": "CTF-2026050001",
                        "赛事来源": "2026 示例赛",
                        "名称": "Legacy Web",
                        "分类": "web",
                        "Flag": "flag{from-xlsx}",
                    }
                ],
                source,
            )

            collect.migrate_xlsx_to_jsonl(source, output)
            migrated = data.load_cases(output)

        self.assertEqual(migrated[0]["metadata"]["名称"], "Legacy Web")
        self.assertEqual(migrated[0]["flag"]["value"], "flag{from-xlsx}")

    def test_migrate_xlsx_reads_multiple_sheets_and_skips_standard_sheet(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "legacy-multi.xlsx"
            output = Path(tmp) / "cases.jsonl"
            write_two_sheet_workbook(source)

            collect.migrate_xlsx_to_jsonl(source, output)
            migrated = data.load_cases(output)

        self.assertEqual([case["metadata"]["名称"] for case in migrated], ["已有题目", "新增题目"])


def write_two_sheet_workbook(path):
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base.xlsx"
        data.write_rows_xlsx([{"名称": "已有题目", "分类": "Web", "Flag": "flag{one}"}], base)
        with zipfile.ZipFile(base) as original:
            files = {name: original.read(name) for name in original.namelist()}

    files["xl/workbook.xml"] = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<workbook xmlns="{data.NS_MAIN}" xmlns:r="{data.NS_REL}">'
        '<sheets>'
        '<sheet name="已有赛题列表" sheetId="1" r:id="rId1"/>'
        '<sheet name="新增竞赛题目列表" sheetId="2" r:id="rId2"/>'
        '<sheet name="赛题收集标准" sheetId="3" r:id="rId3"/>'
        '</sheets>'
        '</workbook>'
    ).encode()
    files["xl/_rels/workbook.xml.rels"] = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Relationships xmlns="{data.NS_PACKAGE_REL}">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>'
        '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet3.xml"/>'
        '</Relationships>'
    ).encode()
    files["xl/worksheets/sheet2.xml"] = data._worksheet_xml(
        [data.XLSX_FIELDS, ["", "2026 示例赛", "", "新增题目", "Misc", "", "", "flag{two}"]]
    ).encode()
    files["xl/worksheets/sheet3.xml"] = data._worksheet_xml([["序号", "素材审核要求"], ["1", "归档要求"]]).encode()

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)


if __name__ == "__main__":
    unittest.main()
