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

## `cloversec_ctf_search.py`

公网搜索、抓取和下载工具。免费源默认包括 GitHub repository search、GitHub code search（有 `gh auth login` 或 token 时）、CTFTime events/writeups、DuckDuckGo HTML、内置公开 CTF 归档 seeds、CTF 平台 seeds、CSDN/博客园/语雀 `site:` 定向搜索；可选 key 会增强搜索面。

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
- `BRAVE_SEARCH_API_KEY` 或 `CLOVERSEC_BRAVE_API_KEY`
- `BING_SEARCH_API_KEY` 或 `CLOVERSEC_BING_API_KEY`

没有 GitHub token 时，GitHub code search 会在 `errors` 中标记 skipped，其他免费源继续执行。Brave、Bing 只在显式传 `--source brave` / `--source bing` 时使用。
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

## `cloversec_ctf_browser_search.py`

浏览器辅助搜索工具，用于 Google、Baidu、CSDN、博客园、语雀这类直连不稳定或需要用户浏览器状态的搜索。工具只生成搜索页、导入页面可见结果，不读取 Cookie、token、localStorage、sessionStorage、密码或验证码。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_browser_search.py plan --query "IrisCTF 2025 web writeup" --engine google --output browser_search_plan.json
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

## MCP server

插件带有 `cloversec-ctf-search` 和 `cloversec-ctf-browser-search` MCP server，配置文件为 `.mcp.json`。工具：

- `cloversec_ctf_discover`
- `cloversec_ctf_ctftime_events`
- `cloversec_ctf_fetch_url`
- `cloversec_ctf_github_release_assets`
- `cloversec_ctf_import_agent_web_results`
- `cloversec_ctf_browser_search_plan`
- `cloversec_ctf_browser_search_import_visible`

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

Hub 提交材料整理工具。第一版只生成材料包，不登录 Hub、不读取凭证、不自动提交。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py package \
  --case-json ctf_case.json \
  --hub-fields writeup_out/hub_fields.json \
  --manual writeup_out/manual_filled_draft.md \
  --output-dir hub_submission_package

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py browser-plan \
  --manifest hub_submission_package/manifests/upload_manifest.json \
  --output hub_submission_package/browser_assist_plan.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py validate-manifest \
  --manifest hub_submission_package/manifests/upload_manifest.json \
  --classify-options hub_classify_options.json \
  --output hub_submission_package/manifests/pre_submit_validation.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py apply-upload-results \
  --manifest hub_submission_package/manifests/upload_manifest.json \
  --upload-results hub_upload_results.json \
  --output hub_submission_package/manifests/upload_manifest.with_uploads.json
```

输出目录：

- `hub_submission_package/fields/`
- `hub_submission_package/manual/`
- `hub_submission_package/attachments/`
- `hub_submission_package/images/`
- `hub_submission_package/screenshots/`
- `hub_submission_package/manifests/upload_manifest.json`
- `hub_submission_package/hub_submission_checklist.md`

默认截图槽位固定为 `01-challenge-page.png`、`02-container-running.png`、`03-solve-proof.png`。
`validate-manifest` 会检查分类 ID、题目内容、题目解答、关键字、上传结果和截图槽位；`apply-upload-results` 只合并显式提供的上传返回 JSON，不读取浏览器 Cookie、token 或 session。

## `cloversec_ctf_archive.py`

归档目录生成工具。复制源码、附件、镜像 tar、手册和截图，写入每题 manifest 与 xlsx 路径字段。

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

- `archive/<case_id>-<title>/source/`
- `archive/<case_id>-<title>/attachments/`
- `archive/<case_id>-<title>/image/`
- `archive/<case_id>-<title>/writeup/`
- `archive/<case_id>-<title>/screenshots/`
- `archive/<case_id>-<title>/manifests/archive_manifest.json`

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
```

默认只生成命令计划。只有显式传入 `--execute` 时，才会执行 Docker tag、save、load、inspect，并记录 tar SHA256 与平台。

## `cloversec_ctf_final.py`

最终归档输出工具。生成 xlsx、语雀粘贴表、Markdown 报告和 JSON 报告。

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_final.py generate \
  --cases ctf_cases.jsonl \
  --output-dir final_out
```

输出文件：

- `final_out/archive.xlsx`
- `final_out/yuque_table.md`
- `final_out/final_report.md`
- `final_out/final_report.json`

`archive.xlsx` 和 `yuque_table.md` 均按内部归档字段写入完整 `Flag`，不要放到公开渠道。
