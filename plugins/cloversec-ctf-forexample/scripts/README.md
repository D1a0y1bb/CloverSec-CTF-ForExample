# Scripts

## `cloversec_ctf_data.py`

统一数据模型工具，使用 Python 标准库实现。容器改造相关脚本需要 PyYAML，安装命令见 Dockerizer 的 `scripts/requirements.txt`。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py validate-json ctf_case.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py export-xlsx ctf_cases.jsonl 最终归档表.xlsx
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py import-xlsx 最终归档表.xlsx
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py summary ctf_cases.jsonl
```

`export-xlsx` 会把完整 `Flag` 写入 xlsx 的 `Flag` 列。日志和错误信息不输出完整 Flag。
安装 `openpyxl` 后会导出带固定字体、边框、居中和列宽的 xlsx；未安装时自动使用内置基础 writer。需要强制基础 writer 时设置 `CLOVERSEC_XLSX_WRITER=stdlib`。

## `cloversec_ctf_workflow.py`

工作流入口工具。`init` 创建任务，`run` 按工作目录执行安全阶段并支持继续处理。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py init \
  --event "IrisCTF" \
  --year 2025 \
  --category web \
  --limit 20

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py run \
  --workdir runs/20260614-2025-IrisCTF-web \
  --stage research \
  --stage collect \
  --stage dedupe \
  --stage download_preview \
  --stage archive \
  --stage quality \
  --stage final_report
```

`run` 会写 `workflow_engine_run.json`、`logs/workflow_engine.jsonl` 和 `当前状态.md`。真实 Docker、下载接受、Hub 最终提交、retag 执行仍需要用户确认。

## `doctor.py`

环境和安装包自检工具。仓库根目录和安装后的插件目录都可以运行。

```bash
python3 scripts/doctor.py
python3 scripts/doctor.py --json --installed
```

`--installed` 会额外检查插件包内的 `plugin.json`、`.mcp.json`、图标、搜索召回基准、进度脚本和交接表脚本是否存在，并检查核心模块能否导入。它适合升级插件后确认本机 Codex 缓存里拿到的是完整版本。

## `cloversec_ctf_handoff.py`

把搜索、题目清单和资源识别结果导出成中文 xlsx、JSONL 和 schema。xlsx 给人看，JSONL 给后续 Agent 继续处理。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_handoff.py search \
  --manifest search_results.json \
  --output-dir handoff

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_handoff.py collection \
  --cases ctf_cases.jsonl \
  --output-dir handoff

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_handoff.py resource \
  --classification resource_classification.json \
  --output-dir handoff
```

常见输出：

- `赛事题目信息收集表.xlsx` / `.jsonl` / `.schema.json`
- `资源整理与处理建议表.xlsx` / `.jsonl` / `.schema.json`
- `Dockerizer交接表.xlsx` / `.jsonl` / `.schema.json`

源码题、Dockerfile、compose、镜像 tar 和 Web/Pwn 服务题会进入 `Dockerizer交接表`，其中 `确认动作` 固定写 `confirmation_action=dockerizer`。

## `cloversec_ctf_collect.py`

收集与资料整理工具。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py migrate-xlsx 竞赛题目收集.xlsx ctf_cases.jsonl
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py asset-inventory challenge-dir asset_inventory.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py research-report ctf_cases.jsonl research_report.md
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py validate-collection ctf_cases.jsonl
```

`migrate-xlsx` 用于迁移旧表到中间 JSONL，会读取多个业务工作表，并跳过名称包含“标准”或“说明”的工作表。真实内部 xlsx 不应提交进公开仓库。

## `cloversec_ctf_search.py`

公网搜索、抓取和下载工具。免费源默认包括 GitHub repository search、GitHub code search（有 `gh auth login` 或 token 时）、CTFTime events/writeups、DuckDuckGo HTML、内置公开 CTF 归档 seeds、CTF 平台 seeds、CSDN/博客园/语雀 `site:` 定向搜索。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py discover \
  --query "LA CTF 2024 web challenge writeup" \
  --year 2024 \
  --limit 20 \
  --output search_results.json \
  --cases-jsonl ctf_cases.jsonl

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py import-agent-search --input agent_web_results.json --query "IrisCTF 2025 web writeup" --provider agent-web-search --output search_results.agent.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py fetch-url https://example.com/writeup --output fetched_url.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-url https://example.com/challenge.zip --output-dir downloads --output downloaded_asset.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-from-manifest --manifest search_results.json --output-dir downloads --output asset_downloads.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py github-release-assets --repo owner/repo --output github_release_assets.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-github-release-assets --repo owner/repo --output-dir downloads --output release_downloads.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-github-raw https://github.com/owner/repo/blob/main/path/file.zip --output-dir downloads --output raw_download.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-github-tree --repo owner/repo --ref main --path-prefix challenges --output-dir downloads --output tree_downloads.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py preview-archive downloads/challenge.zip --output archive_preview.json
```

可选环境变量：

- `GITHUB_TOKEN` 或 `GH_TOKEN`
- 本机已执行 `gh auth login` 时，脚本默认尝试读取 `gh auth token`
- `CLOVERSEC_DISABLE_GH_AUTH_TOKEN=1`，禁止读取本机 `gh auth token`

没有 GitHub token 时，GitHub code search 会在 `errors` 中标记 skipped，其他免费源继续执行。
`--source github` 会先做无需 key 的 GitHub repository search；没有 `GITHUB_TOKEN` 时，只会把增强项 `github-code` 记录为 skipped。
也可以单独传 `--source github-code`，用于只跑 GitHub code search。
抓取和下载只支持 `http://`、`https://` URL；HTTP 4xx/5xx 响应不会作为成功附件写入下载目录。
GitHub 专用入口支持 Release asset、blob/raw 文件、目录树下载。目录树下载默认保留相对路径；`--asset-only` 只下载常见附件、文档和图片后缀。
`preview-archive` 只预览 zip/tar，记录文件清单和路径穿越风险，不解压文件。

搜索结果会写入：

- `source_url`
- `title`
- `snippet`
- `provider`
- `confidence`
- `evidence`
- `layer`
- `score`
- `lead_only`
- `quality_issues`

`layer` 可取值：

- `confirmed_challenge`
- `writeup_candidate`
- `attachment_candidate`
- `platform_lead`
- `noise`

查询 `IrisCTF` 时，`NepCTF`、`Compfest CTF` 等其他赛事会降为 `noise`。CTFTime、NSSCTF、CTFHub、BUUOJ 等平台首页会标为 `platform_lead` 和 `lead_only=true`。

搜索召回不足时，`discover` 会输出 `recall_recovery` 并运行放宽年份的公开网页/site 搜索。恢复结果会带 `year_relaxed=true` 和 `metadata.recovery_reason=weak_recall`，只能作为线索；确认具体年份、题目、附件或 writeup 仍需要证据。

## `cloversec_ctf_search_plus.py`

统一搜索入口，适合 Agent/MCP 调用。它合并默认免费源、Agent 联网搜索结果、Chrome/浏览器可见结果、直接附件 URL 和显式 GitHub 仓库，默认返回短 JSON，完整结果写文件。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search_plus.py \
  --query "IrisCTF 2025 web writeup" \
  --year 2025 \
  --agent-results agent_web_results.json \
  --browser-visible-results visible_results.json \
  --direct-url https://example.com/challenge.zip \
  --github-repo owner/repo \
  --output search_plus.full.json \
  --compact-output search_plus.compact.json
```

直接 URL 只做安全预览，记录状态码、content-type、hash、截断状态和附件线索，不默认下载为归档资源。遇到冷门比赛、附件下架、网盘失效或搜索召回不足时，结果会把 Agent 联网搜索、Chrome 浏览器辅助搜索或人工入口列为下一步。

## `search_recall_benchmark.py`

真实搜索召回验收工具。它读取 `references/search-recall-benchmark.json`，对人工核对过存在的公开资源做 GitHub repo / URL 归一化命中检查，不用关键词命中代替。

```bash
python3 scripts/search_recall_benchmark.py \
  --run-search \
  --benchmark plugins/cloversec-ctf-forexample/references/search-recall-benchmark.json \
  --input-dir docs/validation/search-recall-v0.7.0 \
  --output docs/validation/search-recall-benchmark-v0.7.0.md \
  --json-output docs/validation/search-recall-benchmark-v0.7.0.json
```

输出里的 `resource_recall` 是已验证资源的真实召回率。搜索策略改动前后都应保留本地报告，方便确认修复的是实际漏召回，不是只改了提示词。

## `cloversec_ctf_browser_search.py`

浏览器辅助搜索工具，用于 Google、Baidu、CSDN、博客园、语雀这类直连不稳定或需要用户浏览器状态的搜索。工具只生成搜索页、导入页面可见结果，不读取 Cookie、token、localStorage、sessionStorage、密码或验证码。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_browser_search.py plan --query "IrisCTF 2025 web writeup" --engine google --output browser_search_plan.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_browser_search.py dom-to-visible --input chrome_visible_dom.json --query "IrisCTF 2025 web writeup" --engine google --output visible_results.json --normalized-output browser_search_results.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_browser_search.py import-visible --input visible_results.json --query "IrisCTF 2025 web writeup" --engine google --output browser_search_results.json
```

`visible_results.json` 格式：

```json
{
  "results": [
    {
      "rank": 1,
      "title": "IrisCTF 2025 web writeup",
      "url": "https://example.com/writeup",
      "snippet": "visible summary"
    }
  ],
  "blocked_by_captcha": false,
  "blocked_reason": ""
}
```

`dom-to-visible` 接收用户确认后的 Chrome/Codex 可见 DOM、HTML、visible text 或 links，不读取浏览器凭证。输出 `visible_results.json` 后再进入评分。

## MCP server

插件带有 `cloversec-ctf-search`、`cloversec-ctf-search-plus`、`cloversec-ctf-browser-search`、`cloversec-ctf-docker`、`cloversec-ctf-archive`、`cloversec-ctf-quality-runner`、`cloversec-ctf-hub-assistant` 和 `cloversec-ctf-workflow` MCP server，配置文件为 `.mcp.json`。工具：

- `cloversec_ctf_search_plus`
- `cloversec_ctf_workflow_run`
- `cloversec_ctf_discover`
- `cloversec_ctf_ctftime_events`
- `cloversec_ctf_fetch_url`
- `cloversec_ctf_github_release_assets`
- `cloversec_ctf_import_agent_web_results`
- `cloversec_ctf_browser_search_plan`
- `cloversec_ctf_browser_search_import_visible`
- `cloversec_ctf_browser_search_dom_to_visible`
- `cloversec_ctf_docker_plan`
- `cloversec_ctf_docker_validation_plan`
- `cloversec_ctf_docker_execute`
- `cloversec_ctf_archive_batch`
- `cloversec_ctf_archive_preview`
- `cloversec_ctf_manifest_lock`
- `cloversec_ctf_quality_run`
- `cloversec_ctf_manual_quality`
- `cloversec_ctf_batch_status_report`
- `cloversec_ctf_failure_cases`
- `cloversec_ctf_proof_pack`
- `cloversec_ctf_hub_browser_plan`
- `cloversec_ctf_hub_chrome_plan`
- `cloversec_ctf_hub_draft`
- `cloversec_ctf_hub_review_state`
- `cloversec_ctf_image_naming_plan`
- `cloversec_ctf_hub_validate_manifest`
- `cloversec_ctf_hub_apply_upload_results`
- `cloversec_ctf_resource_classify`
- `cloversec_ctf_handoff_tables`
- `cloversec_ctf_container_infer`
- `cloversec_ctf_results_to_cases`
- `cloversec_ctf_visible_content_evidence`
- `cloversec_ctf_confirmation_request`
- `cloversec_ctf_stage_notification`
- `cloversec_ctf_codex_warning_report`

MCP 工具调用会记录到本机运行目录，默认 `~/.codex/cloversec-ctf-forexample/mcp-runtime/`。这些日志用于排查批量任务失败，只保存调用摘要和错误，不保存浏览器凭证或完整敏感参数。

## `cloversec_ctf_container.py`

容器题识别工具。它只做静态读取，从 Dockerfile、compose、README、challenge manifest 和 `resource_classification.json` 中提取端口、服务、镜像名建议、启动线索和 Docker 验证等级。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_container.py infer \
  challenge-dir \
  --resource-classification resource_classification.json \
  --output container_inference.json \
  --compact-output container_inference.compact.json
```

验证等级：

- `static_only`：只读取文件和 JSON，不执行 Docker。
- `inspect_only`：load/inspect 已有镜像或镜像 tar。
- `build_only`：build amd64 镜像并 inspect。
- `run_probe`：build/inspect/run/logs/stop，并探测端口或 URL。
- `solve_verify`：表示需要人工确认后按手册验证解题，不自动执行未知 solver。

## `cloversec_ctf_docker.py`

受控 Docker 执行工具。按显式 operations 或 `--validation-level` 执行 `build/load/inspect/run/logs/stop/save`，记录 amd64 平台、端口探测、启动日志、tar SHA256 和失败证据。要求 build 时显式传 `--project-dir` 或通过 `container_inference.json` 提供 build context。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_docker.py execute \
  --case-json ctf_case.json \
  --image-name cloversec/example:local \
  --tar-path archive/example.tar \
  --operation inspect \
  --operation run \
  --operation logs \
  --operation stop \
  --operation save \
  --port 18080:80 \
  --output-dir docker_evidence
```

按验证等级生成计划：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_docker.py plan \
  --container-inference container_inference.json \
  --validation-level run_probe \
  --image-name cloversec/example:local \
  --output docker_validation_plan.json
```

输出文件：

- `docker_evidence/docker_evidence.json`
- `docker_evidence/docker_evidence.md`
- `docker_evidence/docker_logs.txt`（执行 logs 时生成）

## `cloversec_ctf_proof.py`

审核证据包工具。把资源识别、容器推断、Docker evidence、质量检查报告和其他小文件复制到 `proof/evidence/`，写出 manifest、hashes 和人工复核报告。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_proof.py \
  --output-dir proof \
  --case-json ctf_case.json \
  --resource-classification resource_classification.json \
  --container-inference container_inference.json \
  --docker-evidence docker_evidence/docker_evidence.json \
  --quality-review quality_review.json
```

关键输出：

- `proof/proof_manifest.json`
- `proof/proof_report.md`
- `proof/hashes.json`
- `proof/evidence/`

## `cloversec_ctf_archive_runner.py`

批量归档工作流。读取 `ctf_cases.jsonl`，生成归档目录、资源索引、manifest、最终 xlsx、语雀表和缺失项报告。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_archive_runner.py \
  --cases ctf_cases.jsonl \
  --output-root archive_out \
  --compact-output archive_out/_batch/archive_compact.json
```

关键输出：

- `archive_out/_batch/resource_index.json`
- `archive_out/_batch/missing_report.md`
- `archive_out/_batch/ctf_cases.archived.jsonl`
- `archive_out/_final/最终归档表.xlsx`
- `archive_out/_final/语雀粘贴表.md`
- 兼容副本：`archive_out/_final/archive.xlsx`、`archive_out/_final/yuque_table.md`

## `cloversec_ctf_quality_runner.py`

批量质量检查工具。把题目资源、Docker 验证、手册解题步骤、Flag 字段和归档状态汇总成可复核证据。默认不执行 Docker；需要 Docker 验证时显式加 `--execute-docker`。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_quality_runner.py \
  --cases ctf_cases.jsonl \
  --output-dir quality_out \
  --compact-output quality_out/quality_compact.json
```

关键输出：

- `quality_out/quality_summary.json`
- `quality_out/quality_summary.md`
- `quality_out/ctf_cases.reviewed.jsonl`
- `quality_out/<case_id>/quality_review.json`

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

## `cloversec_ctf_writeup.py`

手册草稿、Hub 字段和 xlsx 行草稿生成工具。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_writeup.py render \
  ctf_case.json \
  --output-dir writeup_out
```

输出文件：

- `writeup_out/hub_fields.json`
- `writeup_out/xlsx_fields.json`
- `writeup_out/manual_template.md`
- `writeup_out/manual_filled_draft.md`

`hub_fields.json` 中的 `题目Flag` 和 `xlsx_fields.json` 中的 `Flag` 都保留完整 Flag。10 级难度会转换为 Hub 可填写的 `题目等级`、`题目难度`、`题目难度等级`。

## `cloversec_ctf_hub.py`

Hub 提交材料整理工具。生成材料包、Hub 草稿、浏览器计划、Chrome 计划、提交前检查、上传结果回写和审核状态；不读取凭证，不点击最终提交。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py package \
  --case-json ctf_case.json \
  --hub-fields writeup_out/hub_fields.json \
  --manual writeup_out/manual_filled_draft.md \
  --output-dir hub_submission_package

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py browser-plan \
  --manifest hub_submission_package/manifests/upload_manifest.json \
  --output hub_submission_package/browser_assist_plan.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py chrome-plan \
  --manifest hub_submission_package/manifests/upload_manifest.json \
  --output hub_submission_package/chrome_assist_plan.json \
  --report hub_submission_package/chrome_assist_plan.md

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py validate-manifest \
  --manifest hub_submission_package/manifests/upload_manifest.json \
  --classify-options hub_classify_options.json \
  --output hub_submission_package/manifests/pre_submit_validation.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py apply-upload-results \
  --manifest hub_submission_package/manifests/upload_manifest.json \
  --upload-results hub_upload_results.json \
  --output hub_submission_package/manifests/upload_manifest.with_uploads.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py draft \
  --case-json ctf_case.json \
  --hub-fields writeup_out/hub_fields.json \
  --manual writeup_out/manual_filled_draft.md \
  --output-dir hub_draft

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py review-state \
  --case-json ctf_case.json \
  --submission-status submitted \
  --review-status reviewing \
  --output-dir hub_review
```

输出目录：

- `hub_submission_package/fields/`
- `hub_submission_package/manual/`
- `hub_submission_package/attachments/`
- `hub_submission_package/images/`
- `hub_submission_package/screenshots/`
- `hub_submission_package/manifests/upload_manifest.json`
- `hub_submission_package/hub_submission_checklist.md`
- `hub_draft/hub_draft.json`
- `hub_draft/hub_upload_manifest.json`
- `hub_draft/hub_browser_plan.json`
- `hub_draft/hub_chrome_plan.json`
- `hub_draft/hub_screenshot_checklist.md`
- `hub_draft/hub_diff_report.md`
- `hub_review/hub_review_state.json`
- `hub_review/hub_review_state.md`

默认截图槽位固定为 `题目页面.png`、`容器运行.png`、`解题证明.png`。
`validate-manifest` 会检查分类 ID、题目内容、题目解答、关键字、上传结果和截图槽位；`apply-upload-results` 只合并显式提供的上传返回 JSON，不读取浏览器 Cookie、token 或 session。`chrome-plan` 约束 Agent 只能使用用户当前浏览器可见状态，最终提交前停止。Chrome 填写必须先确认用户已登录 Hub；未登录状态下即使提交页表单可见也不能填写，因为提交会跳转登录并丢失内容。Chrome 文件上传依赖 Codex 扩展的文件访问权限；如果 `setFiles` 返回 `Not allowed`，需要在 `chrome://extensions` 中给 Codex 扩展开启 `Allow access to file URLs`。

## `cloversec_ctf_archive.py`

归档目录生成工具。复制源码、附件、手册和截图，镜像 tar 默认只记录原路径和 hash，写入每题 manifest 与 xlsx 路径字段。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_archive.py package \
  --case-json ctf_case.json \
  --output-root archive \
  --output-case ctf_case.archived.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_archive.py batch \
  --cases ctf_cases.jsonl \
  --output-root archive \
  --output-cases ctf_cases.archived.jsonl \
  --final-output-dir final_out
```

输出目录：

- `archive/<case_id>-<title>/源码/`
- `archive/<case_id>-<title>/附件/`
- `archive/<case_id>-<title>/镜像/`
- `archive/<case_id>-<title>/手册/`
- `archive/<case_id>-<title>/截图/`
- `archive/<case_id>-<title>/清单/archive_manifest.json`

## `cloversec_ctf_manual_quality.py`

手册质量检查工具。检查题目字段、手册段落、解题步骤、截图引用、附件引用、完整 Flag 和 Hub 字段一致性。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_manual_quality.py \
  --case-json ctf_case.json \
  --manual writeup_out/manual_filled_draft.md \
  --hub-fields writeup_out/hub_fields.json \
  --output-dir manual_quality
```

输出文件：

- `manual_quality/manual_quality.json`
- `manual_quality/manual_quality_report.md`
- `manual_quality/xlsx_fields_patch.json`

`xlsx_fields_patch.json` 保留完整 `Flag`，用于内部归档字段修正。

## `cloversec_ctf_audit.py`

归档预览、锁定文件、人工确认、批量报告、失败案例库、阶段通知和 Codex warning 分类工具。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py archive-preview \
  --case-json ctf_case.json \
  --output-dir archive_preview \
  --archive-root archive

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py lock \
  --case-json ctf_case.json \
  --output-dir manifest_lock

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py confirmation \
  --action hub \
  --case-json ctf_case.json \
  --output-dir confirmation

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py batch-report \
  --cases ctf_cases.jsonl \
  --output-dir batch_report

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py failure-library \
  --cases ctf_cases.jsonl \
  --output batch_report/failure_cases.jsonl

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py warning-report \
  --log codex_exec.log \
  --output warnings/codex_warning_report.json
```

输出文件：

- `archive_preview.json` / `archive_preview.md`
- `manifest.lock.json` / `manifest.lock.md`
- `confirmation_request.json` / `confirmation_request.md`
- `batch_status_report.json` / `batch_status_report.md` / `batch_status_report.xlsx`
- `failure_cases.jsonl`
- `stage_notification.json` / `stage_notification.md`
- `codex_warning_report.json` / `codex_warning_report.md`

## `cloversec_ctf_review.py`

质量检查报告工具。读取 `ctf_case.json`、归档目录和已有验证记录，输出 `quality_review.json` 和 `quality_review_report.md`。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_review.py review \
  --case-json ctf_case.json \
  --output-dir quality_review \
  --archive-dir archive/case-001-title \
  --output-case ctf_case.reviewed.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_review.py review \
  --case-json ctf_case.json \
  --output-dir quality_review \
  --archive-dir archive/case-001-title \
  --execute-docker \
  --probe-url http://127.0.0.1:18080/ \
  --output-case ctf_case.reviewed.json
```

脚本默认不会执行 Docker。只有显式传入 `--execute-docker` 时，才会执行受控的 load、inspect、run、端口探测、logs、stop、rm，并写入 `docker_execution.json`。
没有 `docker_artifacts.run_verified=true`、`--execute-docker` 证据或 `writeup.solve_verified=true` 时，相关检查写为 `skip`。

## `cloversec_ctf_retag.py`

Hub 审核通过后的编号和镜像 tag 计划工具。它只生成命令计划，不自动运行 Docker。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_retag.py plan \
  --case-json ctf_case.json \
  --hub-id CTF-2026060001 \
  --output-dir archive/retagged-images \
  --registry-prefix registry.example.com/cloversec \
  --tag-template "{hub_id}" \
  --output retag_plan.json \
  --report retag_report.md \
  --output-case ctf_case.retagged.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_retag.py plan \
  --case-json ctf_case.json \
  --hub-id CTF-2026060001 \
  --output-dir archive/retagged-images \
  --output retag_plan.json \
  --execute \
  --output-case ctf_case.retagged.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_retag.py image-naming \
  --case-json ctf_case.json \
  --hub-id CTF-2026060001 \
  --output-dir hub_review
```

默认只生成命令计划。只有显式传入 `--execute` 时，才会执行 Docker tag、save、load、inspect，并记录 tar SHA256 与平台。

`image-naming` 只生成 `image_naming_plan.json`、`retag_inputs.json` 和 `image_naming_plan.md`。没有 Hub 编号时状态为 `needs_hub_id`，不会自造编号。

## `cloversec_ctf_final.py`

最终归档输出工具。生成 xlsx、语雀粘贴表、Markdown 报告和 JSON 报告。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_final.py generate \
  --cases ctf_cases.jsonl \
  --output-dir final_out \
  --base-dir .
```

输出文件：

- `final_out/最终归档表.xlsx`
- `final_out/语雀粘贴表.md`
- `final_out/最终报告.md`
- `final_out/最终报告.json`

兼容副本：

- `final_out/archive.xlsx`
- `final_out/yuque_table.md`
- `final_out/final_report.md`
- `final_out/final_report.json`

`最终归档表.xlsx` 和 `语雀粘贴表.md` 均按内部归档字段写入完整 `Flag`，不要放到公开渠道。

如果 cases 里保存的是 `work/...` 这类相对路径，`--base-dir` 填线程或项目根目录。否则最终报告可能在不同执行目录下误判归档目录或附件不存在。
