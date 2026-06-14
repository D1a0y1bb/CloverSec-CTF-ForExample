# CloverSec CTF Data Model

## 中间 JSON

每道题使用 `ctf_case.json` 保存完整流程状态。

```json
{
  "case_id": "",
  "source_files": [],
  "research": {},
  "asset_collection": {},
  "metadata": {},
  "flag": {
    "value": "",
    "type": "static|dynamic|unknown",
    "sensitive": true
  },
  "environment": {},
  "docker_artifacts": {},
  "attachments": [],
  "writeup": {},
  "hub_fields": {},
  "review": {},
  "archive": {},
  "evidence": [],
  "confidence": "high|medium|low"
}
```

## xlsx 字段

输出 xlsx 必须保留内部归档需要的人可读字段：

- `HUB编号`
- `赛事来源`
- `题目来源`
- `名称`
- `分类`
- `题目类型`
- `Flag类型`
- `Flag`
- `难度编号`
- `星级`
- `分值`
- `资源等级`
- `提交时间`
- `开放端口`
- `离线/在线解题`
- `解题工具`
- `提交用户名`
- `审核人`
- `是否通过`
- `问题`
- `是否归档`
- `材料状态`
- `构建状态`
- `手册状态`
- `验证状态`
- `归档目录`
- `环境包/附件包路径`
- `备注`

`Flag` 是 xlsx 必填字段。脚本在日志、错误输出、公开报告中避免打印完整 Flag。

## 批处理状态

0.3.0 起，批量采集任务使用 `workflow_state.json` 记录状态：

```json
{
  "schema_version": "cloversec.ctf.workflow.state.v1",
  "workflow_version": "0.3.1",
  "run_id": "",
  "status": "initialized",
  "workdir": "",
  "request": {
    "event": "",
    "years": [],
    "categories": [],
    "limit": 0
  },
  "stages": {},
  "cases": [],
  "resume": {
    "last_stage": "",
    "last_case_id": "",
    "can_resume": true
  }
}
```

`cases[].stages` 记录单题阶段状态。单题失败只能影响该题，不能把整批直接写成失败。

## 资源识别

0.3.1 起，资源目录使用 `resource_classification.json` 记录识别结果：

```json
{
  "schema_version": "cloversec.ctf.resource_classification.v1",
  "version": "0.3.1",
  "root": "",
  "root_classification": {
    "project_type": "container_project|compose_project|source_archive_bundle|attachment_challenge|writeup_only|mixed_resource_bundle",
    "confidence": "high|medium|low",
    "recommended_next_skill": "",
    "evidence": []
  },
  "resources": [
    {
      "relative_path": "",
      "resource_type": "dockerfile|compose_file|source_archive|attachment_archive|writeup|screenshot|pcap|binary|database_dump|docker_image_tar|unknown",
      "confidence": "high|medium|low",
      "sha256": "",
      "recommended_next_skill": "",
      "evidence": []
    }
  ],
  "summary": {},
  "recommendations": [],
  "warnings": []
}
```

资源识别结果是分流建议。进入 Dockerizer、附件题检查、Hub 或最终归档前仍要保留人工确认点。

## 脚本入口

统一数据模型脚本：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py init --event "IrisCTF" --year 2025 --category web --limit 20
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py batch --workdir runs/20260614-2025-IrisCTF-web --stage research --mode dry-run --output reports/research_dry_run.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_resource.py classify challenge-dir --output classification/resource_classification.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py validate-json ctf_case.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py export-xlsx ctf_cases.jsonl archive.xlsx
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py import-xlsx archive.xlsx
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py summary ctf_cases.jsonl
```

脚本只使用 Python 标准库，方便随 plugin 分发。

收集与资料整理脚本：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py migrate-xlsx 竞赛题目收集.xlsx ctf_cases.jsonl
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py asset-inventory challenge-dir asset_inventory.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py research-report ctf_cases.jsonl research_report.md
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py validate-collection ctf_cases.jsonl
```

## 证据字段

`evidence[]` 用于记录公开来源、用户提供来源和本地材料证据：

- `source_url`：公开网页、仓库、公告、WP 链接。没有 URL 时可留空，但必须提供 `local_path`。
- `local_path`：本地材料路径。
- `source_type`：`public_web`、`user_provided`、`local_file`、`github`、`ctftime`、`writeup`、`unknown`。
- `title`：来源标题。
- `accessed_at`：访问日期，建议 `YYYY-MM-DD`。
- `summary`：证据摘要。
- `confidence`：`high`、`medium`、`low`。
- `status`：`found`、`missing`、`inaccessible`、`unverified`。

收集阶段不强制要求完整 `Flag`，但进入最终 xlsx 前必须存在完整 `Flag`。

旧表迁移会读取多个业务工作表，并跳过名称包含“标准”或“说明”的工作表。

公网搜索与下载脚本：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py discover --query "LA CTF 2024 web challenge writeup" --year 2024 --output search_results.json --cases-jsonl ctf_cases.jsonl
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py fetch-url <URL> --output fetched_url.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-url <URL> --output-dir downloads --output downloaded_asset.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-from-manifest --manifest search_results.json --output-dir downloads --output asset_downloads.json
```

`search_results.json` 字段：

- `query`
- `years`
- `sources`
- `results[]`
- `errors[]`
- `summary`

`results[]` 字段：

- `provider`：`github`、`github-code`、`ctftime`、`duckduckgo`、`seed`、`ctf-platforms`、`csdn`、`cnblogs`、`yuque`、`agent-web-search`、`browser-google`、`browser-baidu`
- `kind`：`event`、`writeup`、`repository`、`code`、`web`、`challenge_archive`
- `title`
- `url`
- `summary`
- `source_type`
- `confidence`
- `metadata`

`asset_downloads.json` 必须记录 `local_path`、`size`、`sha256`、`content_type`、`source_url` 或 `url`。

容器和附件阶段脚本：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_build.py plan --project-dir challenge-dir --image-name cloversec/example:local --tar-path archive/example.tar --port 18080:80 --output docker_plan.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_package.py inspect challenge.zip --output attachment_manifest.json
```

`docker_artifacts.platform` 必须为 `linux/amd64`。附件 manifest 必须记录 `sha256`、目录项和风险状态。

手册和 Hub 提交阶段脚本：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_writeup.py render ctf_case.json --output-dir writeup_out
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py package --case-json ctf_case.json --hub-fields writeup_out/hub_fields.json --manual writeup_out/manual_filled_draft.md --output-dir hub_submission_package
```

`hub_fields.json` 字段：

- `题目标题`
- `题目内容`
- `Flag类型`
- `题目Flag`
- `题目来源`
- `题目分类`
- `题目分值`
- `题目等级`
- `题目难度`
- `题目难度等级`
- `题目类型`
- `资源等级`
- `题目备注`
- `添加关键字`

`题目Flag` 保存完整 Flag。导出的 `xlsx_fields.json` 也保存完整 `Flag`。

Hub 提交材料目录：

```text
hub_submission_package/
├── fields/
│   ├── hub_fields.json
│   └── hub_fields_preview.json
├── manual/
│   └── manual_filled_draft.md
├── attachments/
├── images/
├── screenshots/
├── manifests/
│   └── upload_manifest.json
└── hub_submission_checklist.md
```

默认截图命名：

- `01-challenge-page.png`
- `02-container-running.png`
- `03-solve-proof.png`

归档、质检、Hub 编号回填和最终输出脚本：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_archive.py package --case-json ctf_case.json --output-root archive --output-case ctf_case.archived.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_archive.py batch --cases ctf_cases.jsonl --output-root archive --output-cases ctf_cases.archived.jsonl --final-output-dir final_out
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_review.py review --case-json ctf_case.json --output-dir quality_review --archive-dir archive/case-001-title --output-case ctf_case.reviewed.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_review.py review --case-json ctf_case.json --output-dir quality_review --archive-dir archive/case-001-title --execute-docker --output-case ctf_case.reviewed.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_retag.py plan --case-json ctf_case.json --hub-id CTF-2026060001 --output-dir archive/retagged-images --output retag_plan.json --output-case ctf_case.retagged.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_retag.py plan --case-json ctf_case.json --hub-id CTF-2026060001 --output-dir archive/retagged-images --output retag_plan.json --execute --output-case ctf_case.retagged.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_final.py generate --cases ctf_cases.jsonl --output-dir final_out
```

阶段 6 写回字段：

- `cloversec_ctf_archive.py`：`是否归档`、`归档目录`、`环境包/附件包路径`
- `cloversec_ctf_review.py`：`验证状态`、`是否通过`、`问题`、`手册状态`
- `cloversec_ctf_retag.py`：`HUB编号`、`环境包/附件包路径`
- `cloversec_ctf_final.py`：生成最终 `archive.xlsx`，其中 `Flag` 必须完整保留

`quality_review.json` 使用 `pass`、`fail`、`skip` 三种状态。没有真实 Docker run 或按手册解题记录时，对应检查必须是 `skip`。
受控 Docker 执行只在显式传入 `--execute-docker` 或 `--execute` 时运行，并把命令、退出码、平台、日志路径、端口探测、tar SHA256 写入结构化证据。

## 状态值

- `材料状态`：`未开始`、`收集中`、`已收集`、`缺材料`、`无法确认`
- `构建状态`：`不适用`、`未开始`、`已构建`、`验证失败`
- `手册状态`：`未开始`、`草稿`、`待人工完善`、`已校验`
- `验证状态`：`未验证`、`部分通过`、`通过`、`失败`
- `是否归档`：`是`、`否`
- `是否通过`：`是`、`否`
