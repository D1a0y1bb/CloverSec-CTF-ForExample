# Scripts

## `cloversec_ctf_data.py`

统一数据模型工具，使用 Python 标准库实现。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py validate-json ctf_case.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py export-xlsx ctf_cases.jsonl archive.xlsx
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py import-xlsx archive.xlsx
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py summary ctf_cases.jsonl
```

`export-xlsx` 会把完整 `Flag` 写入 xlsx 的 `Flag` 列。日志和错误信息不输出完整 Flag。

## `cloversec_ctf_collect.py`

收集与资料整理工具。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py migrate-xlsx 竞赛题目收集.xlsx ctf_cases.jsonl
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py asset-inventory challenge-dir asset_inventory.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py research-report ctf_cases.jsonl research_report.md
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py validate-collection ctf_cases.jsonl
```

`migrate-xlsx` 用于迁移旧表到中间 JSONL，会读取多个业务工作表，并跳过名称包含“标准”或“说明”的工作表。真实内部 xlsx 不应提交进公开仓库。
