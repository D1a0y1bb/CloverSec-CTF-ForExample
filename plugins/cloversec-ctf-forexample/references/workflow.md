# CloverSec CTF Workflow

## 阶段

1. `cloversec-ctf-workflow-orchestrator`：从年份、赛事、方向和数量创建批量采集任务。
2. `cloversec-ctf-research-intake`：收集赛事和赛题信息。
3. `cloversec-ctf-asset-collector`：收集题目源码、附件、WP、复现资料。
4. `cloversec-ctf-resource-classifier`：识别资源类型并推荐下一步 skill。
5. `cloversec-ctf-build-dockerizer`：容器题目构建转换。
6. `cloversec-ctf-attachment-packager`：附件题目检查和打包。
7. `cloversec-ctf-writeup-scaffold`：手册和 Hub 字段草稿。
8. `cloversec-ctf-manual-quality`：手册、截图、附件、Flag 和 Hub 字段一致性检查。
9. `cloversec-ctf-archive-packager`：归档目录、镜像 tar、hash 清单、预览和锁定文件。
10. `cloversec-ctf-quality-review`：题目、手册、附件、镜像一致性检查。
11. `cloversec-ctf-hub-submission`：Hub 提交草稿、上传清单、截图清单和浏览器计划。
12. `cloversec-ctf-hub-retag`：审核通过后按 HUB 编号生成镜像命名和 retag 计划。
13. `cloversec-ctf-batch-reporter`：批量状态报告、失败案例库、确认请求和阶段通知。
14. `cloversec-ctf-final-report`：最终位置、xlsx 和后续动作报告。

## 全局原则

- 每个阶段产生结构化结果，写入 `ctf_case.json` 或批量 `ctf_cases.jsonl`。
- 不确定字段保留为空，并记录需要用户确认的原因。
- 公网收集优先使用免费源：GitHub、CTFTime、DuckDuckGo、公开归档 seeds、CTF 平台 seeds、CSDN、博客园、语雀。
- 当前 Agent 有联网搜索工具时，优先使用 Agent 搜索 Google/Baidu/全网结果，再导入插件数据模型。
- GitHub code search 优先使用本机 `gh auth login` 或 `GITHUB_TOKEN` / `GH_TOKEN`；默认不要求付费搜索 API key。
- 搜索、抓取、下载必须写入来源 URL、访问时间、hash、HTTP 状态和失败原因。
- 批量任务必须维护 `workflow_state.json`，支持 `dry-run`、`apply` 和 `resume`。
- 外部附件必须先进入 `downloads_sandbox/` 做安全预览，确认后再进入题目目录。
- 下载后或用户提供目录后，先运行资源识别，输出 `resource_classification.json`，再决定进入 Dockerizer、附件题检查或手册流程。
- Hub 自动化第一版不提交，只生成材料。
- 涉及镜像导出时必须检查 `linux/amd64`。
- 内部 xlsx、语雀归档表和相关字段草稿必须保留完整 `Flag`，不能替换成摘要或脱敏值。
- 阶段结束前更新 `TODO.md`。

## 搜索与采集能力

脚本入口：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py init --event "IrisCTF" --year 2025 --category web --limit 20
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py github-doctor --sample-query "IrisCTF 2025 writeup" --output github_sources_status.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py strategy --event "IrisCTF" --year 2025 --category web --output search_strategy.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py discover --query "<赛事/题目/年份/分类>" --year 2025 --output search_results.json --cases-jsonl ctf_cases.jsonl
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py source-evidence --manifest search_results.json --evidence-dir evidence --snapshots-dir snapshots
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py download-sandbox --manifest search_results.json --output-dir .
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_resource.py classify challenge-dir --output classification/resource_classification.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py dedupe --cases ctf_cases.jsonl --output dedupe_candidates.json
```

MCP 入口：

- `cloversec_ctf_workflow_init`
- `cloversec_ctf_workflow_batch`
- `cloversec_ctf_search_strategy`
- `cloversec_ctf_github_doctor`
- `cloversec_ctf_source_evidence`
- `cloversec_ctf_dedupe_candidates`
- `cloversec_ctf_dedupe_apply`
- `cloversec_ctf_download_sandbox`
- `cloversec_ctf_resource_classify`
- `cloversec_ctf_search_plus`
- `cloversec_ctf_results_to_cases`
- `cloversec_ctf_discover`
- `cloversec_ctf_ctftime_events`
- `cloversec_ctf_fetch_url`
- `cloversec_ctf_github_release_assets`
- `cloversec_ctf_import_agent_web_results`
- `cloversec_ctf_browser_search_plan`
- `cloversec_ctf_browser_search_import_visible`
- `cloversec_ctf_browser_search_dom_to_visible`
- `cloversec_ctf_hub_chrome_plan`
- `cloversec_ctf_hub_validate_manifest`
- `cloversec_ctf_manual_quality`
- `cloversec_ctf_archive_preview`
- `cloversec_ctf_manifest_lock`
- `cloversec_ctf_hub_draft`
- `cloversec_ctf_hub_review_state`
- `cloversec_ctf_image_naming_plan`
- `cloversec_ctf_batch_status_report`
- `cloversec_ctf_failure_cases`
- `cloversec_ctf_visible_content_evidence`
- `cloversec_ctf_confirmation_request`
- `cloversec_ctf_stage_notification`
- `cloversec_ctf_codex_warning_report`

没有付费 API key 时，仍可用 GitHub repository search、CTFTime、DuckDuckGo HTML、公开 archive seeds、CTF 平台入口、CSDN、博客园和语雀。平台入口标记为 `platform_lead` / `lead_only`，不能直接当成确认题目。

## 阶段 6 命令顺序

1. 归档资源：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_archive.py package --case-json ctf_case.json --output-root archive --output-case ctf_case.archived.json
```

2. 做质量检查：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_review.py review --case-json ctf_case.archived.json --output-dir quality_review --archive-dir archive/<case_id>-<title> --output-case ctf_case.reviewed.json
```

3. 审核通过并拿到 HUB 编号后生成 retag 计划：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_retag.py plan --case-json ctf_case.reviewed.json --hub-id <HUB编号> --output-dir archive/retagged-images --output retag_plan.json --report retag_report.md --output-case ctf_case.retagged.json
```

4. 汇总最终表：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_final.py generate --cases ctf_cases.jsonl --output-dir final_out
```

默认命令只生成计划和读取已有证据。需要真实执行时必须显式传入：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_review.py review --case-json ctf_case.archived.json --output-dir quality_review --archive-dir archive/<case_id>-<title> --execute-docker --output-case ctf_case.reviewed.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_retag.py plan --case-json ctf_case.reviewed.json --hub-id <HUB编号> --output-dir archive/retagged-images --output retag_plan.json --execute --output-case ctf_case.retagged.json
```

受控 Docker 执行会写入 JSON 证据，包含命令、退出码、平台、日志路径、端口探测和 tar SHA256。

## 0.3.0 工作流状态

标准工作目录：

```text
workflow_state.json
task_plan.json
ctf_cases.jsonl
next_steps.md
logs/
evidence/
snapshots/
downloads_sandbox/
downloads_accepted/
classification/
reports/
```

`workflow_state.json` 必须记录：

- `run_id`
- 当前阶段状态
- 每个 `case_id` 的阶段状态
- 错误和失败原因
- `resume.last_stage`
- `resume.last_case_id`

阶段状态只接受清楚的事实：`pending`、`planned`、`completed`、`failed`。dry-run 只生成预览和计划；apply 才写完成状态。

## 0.3.0 下载沙箱

默认规则：

- 单文件上限 300MB。
- 禁止 `file://`、`ftp://`、localhost、127.0.0.1、内网 IP。
- 文件名强制清洗。
- zip/tar 预览路径穿越、文件数量和解压体积。
- 输出 `download_preview.json` 和 `download_safety_report.md`。
- `accept=true` 且安全状态为 `safe` 时才复制到 `downloads_accepted/`。

## 0.3.1 资源识别

资源识别默认不执行未知代码，不启动 Docker，不把压缩包解压到正式题目目录。

输出文件：

```text
classification/resource_classification.json
```

识别类型包括：

- Dockerfile / compose 项目
- 源码文件和源码压缩包
- 附件压缩包
- writeup 和截图
- pcap / binary / database dump / VM image
- Docker image tar

每条记录都包含 `resource_type`、`confidence`、`evidence`、`sha256` 和 `recommended_next_skill`。低置信度或未知资源必须进入人工确认项。

## 0.3.2 容器推断、验证分级和 proof

容器推断默认只读取本地文件，不执行未知脚本，不启动 Docker。

输出文件：

```text
classification/container_inference.json
docker_validation_plan.json
proof/proof_manifest.json
proof/proof_report.md
proof/hashes.json
```

推荐顺序：

1. 先运行 `cloversec_ctf_resource_classify`，得到 `resource_classification.json`。
2. 再运行 `cloversec_ctf_container_infer`，得到 `container_inference.json`。
3. 根据 `summary.recommended_validation_level` 生成 Docker 验证计划。
4. 只有用户明确授权时，才执行 `cloversec_ctf_docker_execute`。
5. 质量检查完成后，运行 `cloversec_ctf_proof_pack` 生成 `proof/`。

验证等级：

- `static_only`：只读取文件和 JSON。
- `inspect_only`：只 load/inspect 已有镜像或镜像 tar。
- `build_only`：build amd64 镜像并 inspect。
- `run_probe`：build/inspect/run/logs/stop，并探测端口或 URL。
- `solve_verify`：需要人工确认后按手册验证解题，不自动执行未知 solver。

`proof/` 用于审核复核，不替代最终人工判断。

## 0.3.3 手册、Hub、归档和批量交接

### 手册质量

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_manual_quality.py \
  --case-json ctf_case.json \
  --manual writeup_out/manual_filled_draft.md \
  --hub-fields writeup_out/hub_fields.json \
  --output-dir manual_quality
```

输出：

```text
manual_quality/manual_quality.json
manual_quality/manual_quality_report.md
manual_quality/xlsx_fields_patch.json
```

`xlsx_fields_patch.json` 保留完整 `Flag`。`manual_quality_report.md` 只展示检查结果和 hash。

### Hub 草稿

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py draft \
  --case-json ctf_case.json \
  --hub-fields writeup_out/hub_fields.json \
  --manual writeup_out/manual_filled_draft.md \
  --output-dir hub_draft
```

输出：

```text
hub_draft/hub_draft.json
hub_draft/hub_upload_manifest.json
hub_draft/hub_browser_plan.json
hub_draft/hub_chrome_plan.json
hub_draft/hub_screenshot_checklist.md
hub_draft/hub_diff_report.md
```

Hub 草稿只到提交前。分类不确定、上传结果未知、最终提交都由人确认。

### Hub 审核状态和镜像命名

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py review-state \
  --case-json ctf_case.json \
  --submission-status submitted \
  --review-status reviewing \
  --output-dir hub_review

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_retag.py image-naming \
  --case-json ctf_case.json \
  --hub-id CTF-2026060001 \
  --output-dir hub_review
```

没有 Hub 编号时，`image_naming_plan.json` 状态为 `needs_hub_id`。插件不会推测 Hub 编号来源。

### 归档预览和锁定

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py archive-preview \
  --case-json ctf_case.json \
  --output-dir archive_preview \
  --archive-root archive

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py lock \
  --case-json ctf_case.json \
  --output-dir manifest_lock
```

输出：

```text
archive_preview/archive_preview.json
archive_preview/archive_preview.md
manifest_lock/manifest.lock.json
manifest_lock/manifest.lock.md
```

`manifest.lock.json` 固定文件 hash、完整 Flag、Hub 编号和最终 xlsx 字段，供内部复核。

### 批量状态、失败案例和阶段通知

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py batch-report \
  --cases ctf_cases.jsonl \
  --output-dir batch_report

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py failure-library \
  --cases ctf_cases.jsonl \
  --output batch_report/failure_cases.jsonl

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py notify \
  --stage hub \
  --output-dir batch_report \
  --completed "manual_quality" \
  --pending-user "Hub 最终提交前确认"
```

对应 MCP：

- `cloversec_ctf_batch_status_report`
- `cloversec_ctf_failure_cases`
- `cloversec_ctf_stage_notification`
- `cloversec_ctf_confirmation_request`

### 403 或浏览器可见内容导入

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py visible-content-evidence \
  --input visible_results.json \
  --evidence-dir evidence \
  --output visible_content_evidence.json
```

只导入用户确认后的页面可见内容。对登录页、搜索页或不相关页面，结果必须带 `requires_user_confirmation=true` 或降为低置信度。

### 多 Agent 分工模板

`references/agent-roles.json` 记录 Research、Asset、Docker、Writeup、Review、Hub、Archive 七类角色的输入、输出、skill ID 和 MCP tool ID。批量任务中 Agent 必须使用精确 ID，例如 `cloversec-ctf-manual-quality`、`cloversec_ctf_manual_quality`，不能输出泛称。
