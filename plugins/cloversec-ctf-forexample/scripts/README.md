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

