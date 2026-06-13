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

## `cloversec_ctf_build.py`

容器题目构建与归档元数据工具。当前命令生成 Docker 执行计划和校验 artifacts，不会自动运行 Docker。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_build.py plan \
  --project-dir challenge-dir \
  --image-name cloversec/example:local \
  --tar-path archive/example.tar \
  --port 18080:80 \
  --output docker_plan.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_build.py validate-artifacts docker_plan.json
```

计划中的 build 命令固定包含 `--platform linux/amd64`。真实执行 Docker 后，应把 `docker image inspect` 的平台结果写回 `docker_artifacts.platform`。

## `cloversec_ctf_package.py`

附件题压缩包检查工具。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_package.py inspect challenge.zip --output attachment_manifest.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_package.py manifest challenge.zip tools.zip --output attachment_manifest.json
```

检查项包括压缩包类型、是否可读取、目录项、大小、SHA256 和路径穿越风险。
