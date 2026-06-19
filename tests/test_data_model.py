import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "cloversec-ctf-forexample" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import cloversec_ctf_data as data


def sample_case(**overrides):
    case = {
        "case_id": "case-001",
        "metadata": {
            "HUB编号": "CTF-2026050001",
            "赛事来源": "2026 示例赛",
            "题目来源": "2026 示例赛",
            "名称": "拿不到的flag",
            "分类": "Web",
            "题目类型": "环境型",
            "难度编号": "2",
            "星级": "★",
            "分值": "100",
            "资源等级": "4",
            "提交时间": "2026-06-13",
            "开放端口": "80",
            "离线/在线解题": "在线",
            "解题工具": "dirsearch, python3",
            "提交用户名": "测试用户",
            "审核人": "",
            "是否通过": "否",
            "问题": "",
            "是否归档": "否",
            "材料状态": "只存在附件/源码线索",
            "构建状态": "已构建",
            "手册状态": "草稿",
            "验证状态": "部分通过",
            "归档目录": "archive/case-001",
            "环境包/附件包路径": "archive/case-001/image/case.tar",
            "备注": "web容器/映射端口80",
        },
        "flag": {
            "value": "flag{full-value-must-be-in-xlsx}",
            "type": "dynamic",
            "sensitive": True,
        },
        "confidence": "high",
        "source_files": [],
        "research": {},
        "asset_collection": {},
        "environment": {},
        "docker_artifacts": {},
        "attachments": [],
        "writeup": {},
        "hub_fields": {},
        "review": {},
        "archive": {},
        "evidence": [],
    }
    case.update(overrides)
    return case


class DataModelTests(unittest.TestCase):
    def test_validate_case_requires_full_flag(self):
        case = sample_case(flag={"value": "", "type": "dynamic", "sensitive": True})

        errors = data.validate_case(case)

        self.assertTrue(any("flag.value" in err for err in errors))

    def test_validate_case_rejects_invalid_status(self):
        case = sample_case()
        case["metadata"]["验证状态"] = "看起来可以"

        errors = data.validate_case(case)

        self.assertTrue(any("验证状态" in err for err in errors))

    def test_xlsx_round_trip_keeps_full_flag(self):
        case = sample_case()
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "archive.xlsx"

            data.write_xlsx([case], output)
            rows = data.read_xlsx(output)

        self.assertEqual(rows[0]["Flag"], "flag{full-value-must-be-in-xlsx}")
        self.assertEqual(rows[0]["名称"], "拿不到的flag")
        self.assertEqual(list(rows[0].keys()), data.XLSX_FIELDS)

    def test_case_to_xlsx_row_maps_internal_flag_type_to_display_value(self):
        dynamic_case = sample_case(metadata={**sample_case()["metadata"], "Flag类型": ""})
        static_case = sample_case(
            metadata={**sample_case()["metadata"], "Flag类型": ""},
            flag={"value": "flag{static}", "type": "static", "sensitive": True},
        )

        self.assertEqual(data.case_to_xlsx_row(dynamic_case)["Flag类型"], "动态Flag")
        self.assertEqual(data.case_to_xlsx_row(static_case)["Flag类型"], "静态Flag")

    def test_xlsx_stdlib_writer_switch_still_round_trips(self):
        case = sample_case()
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "archive.xlsx"
            old = os.environ.get("CLOVERSEC_XLSX_WRITER")
            os.environ["CLOVERSEC_XLSX_WRITER"] = "stdlib"
            try:
                data.write_xlsx([case], output)
            finally:
                if old is None:
                    os.environ.pop("CLOVERSEC_XLSX_WRITER", None)
                else:
                    os.environ["CLOVERSEC_XLSX_WRITER"] = old
            rows = data.read_xlsx(output)

        self.assertEqual(rows[0]["Flag"], "flag{full-value-must-be-in-xlsx}")
        self.assertEqual(rows[0]["名称"], "拿不到的flag")

    def test_load_jsonl_and_summary(self):
        ok_case = sample_case()
        missing_flag = sample_case(case_id="case-002", flag={"value": "", "type": "static", "sensitive": True})
        missing_flag["metadata"]["验证状态"] = "未验证"
        with tempfile.TemporaryDirectory() as tmp:
            jsonl = Path(tmp) / "ctf_cases.jsonl"
            jsonl.write_text(
                "\n".join(json.dumps(item, ensure_ascii=False) for item in [ok_case, missing_flag]),
                encoding="utf-8",
            )

            cases = data.load_cases(jsonl)
            summary = data.summarize_cases(cases)

        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["by_validation_status"], {"部分通过": 1, "未验证": 1})
        self.assertEqual(summary["missing_required_fields"]["Flag"], 1)


if __name__ == "__main__":
    unittest.main()
