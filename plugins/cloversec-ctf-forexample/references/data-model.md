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
  "workflow_version": "0.5.0",
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

0.3.2 起，资源目录使用 `resource_classification.json` 记录识别结果：

```json
{
  "schema_version": "cloversec.ctf.resource_classification.v1",
  "version": "0.3.2",
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

## 容器推断

0.3.2 起，容器题使用 `container_inference.json` 记录静态推断结果：

```json
{
  "schema_version": "cloversec.ctf.container_inference.v1",
  "version": "0.3.2",
  "project_dir": "",
  "summary": {
    "project_type": "container_project|compose_project|docker_image_delivery|container_instructions|remote_service_challenge|non_container_or_unknown",
    "confidence": "high|medium|low",
    "ports": ["18080:80"],
    "recommended_validation_level": "static_only|inspect_only|build_only|run_probe|solve_verify",
    "requires_manual_review": false
  },
  "runtime": {
    "image_name": "",
    "build_context": "",
    "dockerfile": "",
    "ports": [],
    "probe_urls": []
  },
  "warnings": [],
  "next_actions": []
}
```

`container_inference.json` 是静态建议，不代表 Docker 已构建或启动成功。真实 Docker 证据必须来自 `docker_evidence.json`。

## Proof 证据包

0.3.2 起，审核证据包使用 `proof/proof_manifest.json`：

```json
{
  "schema_version": "cloversec.ctf.proof_pack.v1",
  "version": "0.3.2",
  "case_id": "",
  "copied_evidence": [],
  "skipped_evidence": [],
  "summary": {
    "resource_project_type": "",
    "container_project_type": "",
    "docker_status": "",
    "docker_validation_level": "",
    "docker_run_verified": false,
    "quality_status": "",
    "flag_present": true,
    "ready_for_review": false,
    "issues": []
  },
  "hashes": []
}
```

`proof/` 默认只复制小型 JSON/Markdown 证据和 hash，不执行未知 solver，不点击 Hub 最终提交。

## 0.5.0 Dockerizer 改造确认

容器题、compose 项目和源码型在线题如果没有完成平台契约改造，批量报告和失败案例库必须阻断归档：

```json
{
  "dockerizer": {
    "status": "accepted|rendered|validated|completed",
    "user_confirmed": true
  },
  "docker_artifacts": {
    "platform_contract_verified": true,
    "contract": "cloversec_verified"
  },
  "platform_delivery": {
    "must_use_dockerizer": true,
    "confirmation_action": "dockerizer",
    "blocking_until_confirmed": true,
    "dockerizer_conversion_accepted": true
  }
}
```

任一满足条件可以证明已经完成平台改造确认：`dockerizer.status` 为 `accepted/rendered/validated/passed/complete/completed`，或 `dockerizer.user_confirmed=true`，或 `docker_artifacts.platform_contract_verified=true`。否则相关题目必须写入 `Dockerizer 改造待确认` 和 `platform_conversion_required`。

## 0.5.0 手册质量

手册和 Hub 字段检查使用 `manual_quality.json`：

```json
{
  "schema_version": "cloversec.ctf.manual_quality.v1",
  "version": "0.5.0",
  "case_id": "",
  "summary": {
    "status": "pass|needs_review|fail",
    "pass": 0,
    "warn": 0,
    "fail": 0
  },
  "checks": [],
  "xlsx_fields_patch": {
    "Flag": "flag{完整值}"
  }
}
```

输出文件：

- `manual_quality.json`
- `manual_quality_report.md`
- `xlsx_fields_patch.json`

`xlsx_fields_patch.json` 必须保留完整 `Flag`。Markdown 报告只展示状态、问题和 Flag hash。

## 0.5.0 Hub 草稿与审核状态

Hub 草稿输出：

```json
{
  "schema_version": "cloversec.ctf.hub_draft.v1",
  "version": "0.5.0",
  "case_id": "",
  "summary": {
    "status": "ready|needs_review|blocked",
    "can_fill_browser": true,
    "can_submit": false
  },
  "hub_fields": {},
  "upload_manifest": {},
  "manual_path": "",
  "notes": []
}
```

常见文件：

- `hub_draft.json`
- `hub_upload_manifest.json`
- `hub_browser_plan.json`
- `hub_chrome_plan.json`
- `hub_screenshot_checklist.md`
- `hub_diff_report.md`

Hub 审核状态输出：

```json
{
  "schema_version": "cloversec.ctf.hub_review_state.v1",
  "version": "0.5.0",
  "case_id": "",
  "review_status": "draft|submitted|reviewing|approved|rejected|needs_changes|unknown",
  "hub_id": "",
  "can_retag": false,
  "next_actions": []
}
```

插件不会编造 Hub 编号。`hub_id` 只能来自用户输入、Hub 页面可见内容或已存在的结构化文件。

## 0.5.0 镜像命名计划

审核通过后使用 `image_naming_plan.json` 记录镜像命名、tar 文件名和 xlsx 回填字段：

```json
{
  "schema_version": "cloversec.ctf.image_naming_plan.v1",
  "version": "0.5.0",
  "status": "ready|needs_hub_id",
  "hub_id": "CTF-2026060001",
  "image": {
    "image_name": "",
    "image_tag": "",
    "tar_name": "",
    "platform": "linux/amd64"
  },
  "xlsx_fields": {}
}
```

没有 Hub 编号时状态必须是 `needs_hub_id`，只生成待处理项。

## 0.5.0 归档预览与锁定

归档写入前使用 `archive_preview.json`：

```json
{
  "schema_version": "cloversec.ctf.archive_preview.v1",
  "version": "0.5.0",
  "archive_dir": "",
  "would_create": [],
  "missing_items": [],
  "duplicate_targets": [],
  "oversized_files": [],
  "invalid_names": [],
  "summary": {
    "ready_to_write": false
  }
}
```

归档确认后使用 `manifest.lock.json` 固定交付物：

```json
{
  "schema_version": "cloversec.ctf.manifest_lock.v1",
  "version": "0.5.0",
  "case_id": "",
  "files": [],
  "summary": {
    "flag_present": true,
    "hub_id": "",
    "archive_dir": ""
  },
  "flag": {
    "value": "flag{完整值}",
    "sha256": "",
    "sensitive": true
  },
  "xlsx_fields": {}
}
```

`manifest.lock.json` 保存完整 Flag 和 hash，用于内部归档复核；不要发布到公开渠道。

## 0.5.0 批量报告、失败案例和阶段通知

批量状态：

```json
{
  "schema_version": "cloversec.ctf.batch_status_report.v1",
  "version": "0.5.0",
  "summary": {
    "total": 0,
    "ready_to_archive": 0,
    "archived": 0,
    "needs_user_confirmation": 0
  },
  "rows": []
}
```

失败案例库每行是一个 JSON 对象：

```json
{
  "schema_version": "cloversec.ctf.failure_case.v1",
  "version": "0.5.0",
  "failure_type": "search|download|docker|hub|manual|archive|unknown",
  "case_id": "",
  "evidence": {},
  "suggested_next_actions": []
}
```

阶段通知：

```json
{
  "schema_version": "cloversec.ctf.stage_notification.v1",
  "version": "0.5.0",
  "stage": "",
  "completed": [],
  "failed": [],
  "needs_user": [],
  "next_inputs": []
}
```

## 0.5.0 浏览器可见内容证据

对 403、登录页、验证码页或站点限制导致的抓取失败，允许用户把确认后的页面可见结果导入：

```json
{
  "schema_version": "cloversec.ctf.workflow.visible_content_evidence.v1",
  "version": "0.5.0",
  "query": "",
  "provider": "user-visible-content",
  "results": [
    {
      "title": "",
      "url": "",
      "snippet": "",
      "confidence": "medium",
      "requires_user_confirmation": true
    }
  ]
}
```

只记录页面可见标题、URL、摘要、正文片段或链接，不读取 Cookie、token、localStorage、sessionStorage。

## 脚本入口

统一数据模型脚本：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py init --event "IrisCTF" --year 2025 --category web --limit 20
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py batch --workdir runs/20260614-2025-IrisCTF-web --stage research --mode dry-run --output reports/research_dry_run.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_resource.py classify challenge-dir --output classification/resource_classification.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_container.py infer challenge-dir --resource-classification classification/resource_classification.json --output classification/container_inference.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_proof.py --output-dir proof --case-json ctf_case.json --container-inference classification/container_inference.json --quality-review quality_review.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_manual_quality.py --case-json ctf_case.json --manual manual_filled_draft.md --hub-fields hub_fields.json --output-dir manual_quality
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py draft --case-json ctf_case.json --hub-fields hub_fields.json --manual manual_filled_draft.md --output-dir hub_draft
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py archive-preview --case-json ctf_case.json --output-dir archive_preview
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py lock --case-json ctf_case.json --output-dir manifest_lock
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py batch-report --cases ctf_cases.jsonl --output-dir batch_report
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py visible-content-evidence --input visible_results.json --evidence-dir evidence --output visible_content_evidence.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py validate-json ctf_case.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py export-xlsx ctf_cases.jsonl 最终归档表.xlsx
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py import-xlsx 最终归档表.xlsx
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
- `cloversec_ctf_final.py`：生成 `最终归档表.xlsx`、`语雀粘贴表.md`、`最终报告.md`，其中 `Flag` 必须完整保留；同时保留 `archive.xlsx`、`yuque_table.md`、`final_report.md` 兼容副本

`quality_review.json` 使用 `pass`、`fail`、`skip` 三种状态。没有真实 Docker run 或按手册解题记录时，对应检查必须是 `skip`。
受控 Docker 执行只在显式传入 `--execute-docker` 或 `--execute` 时运行，并把命令、退出码、平台、日志路径、端口探测、tar SHA256 写入结构化证据。

## 状态值

- `材料状态`：`未开始`、`收集中`、`已收集`、`缺材料`、`无法确认`
- `构建状态`：`不适用`、`未开始`、`已构建`、`验证失败`
- `手册状态`：`未开始`、`草稿`、`待人工完善`、`已校验`
- `验证状态`：`未验证`、`部分通过`、`通过`、`失败`
- `是否归档`：`是`、`否`
- `是否通过`：`是`、`否`
