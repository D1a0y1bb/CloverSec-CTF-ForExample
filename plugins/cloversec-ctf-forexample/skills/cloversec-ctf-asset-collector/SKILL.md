---
name: cloversec-ctf-asset-collector
description: CloverSec CTF 题目附件、源码、WP、复现资料收集 skill。基于赛题清单和搜索结果整理、下载、预览和记录源码、附件、WP、截图、hash、来源证据和缺失项。
---

# CloverSec CTF Asset Collector

## Use This When

- 已有 `research_table.xlsx`、`ctf_cases.jsonl`、`ctf_case.json` 或搜索结果。
- 需要收集源码、附件、GitHub Release、raw/blob 文件、WP、截图和来源证据。
- 需要生成 `asset_inventory.json`、`asset_downloads.json`、`asset_collection_report.md` 或 `downloads/`。
- 需要判断已下载资源应该交给 Dockerizer、附件题检查、手册还是人工确认。

## Default Behavior

用户只说“完整收集一道 CTF 题目”“帮我完整收集一道题”时，本 skill 只能做材料收集阶段，不能把 `downloads/`、`archive/`、`reports/`、`manifests/` 或 `_cache/` 当最终交付。拿到真实材料后必须交给 `cloversec-ctf-workflow-orchestrator` 继续做资源识别、Dockerizer/附件分流、手册、质量检查和中文最终交付目录。

如果用户没有明确说“原创题”“新建题目”“出题”，不要生成原创题；默认找公开真实 CTF 比赛题目和官方材料。

1. 按题目建立材料目录，区分 repo、Release asset、raw/blob、writeup、公开归档和直接附件 URL。
2. 只自动下载直接文件 URL；登录页、网盘、动态页面只记录来源。
3. 下载和本地文件都记录 SHA256、size、content-type、source URL 和失败原因。
4. zip/tar 附件先运行预览，检查路径穿越和文件清单。
5. 下载或用户提供目录后，运行资源识别并输出 `resource_classification.json`。
6. 不把 HTTP 错误页、搜索页或登录页写成成功附件。

## Commands

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-from-manifest \
  --manifest search_results.json \
  --output-dir downloads \
  --max-files 10 \
  --output asset_downloads.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py preview-archive \
  downloads/challenge.zip \
  --output archive_preview.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_resource.py classify \
  downloads \
  --output resource_classification.json
```

GitHub asset collection:

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py github-release-assets --repo owner/repo --output github_release_assets.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-github-tree --repo owner/repo --path-prefix challenges --asset-only --output-dir downloads --output tree_downloads.json
```

## Read When Needed

- Full command catalog, field list, validation, and stop conditions: `../../references/asset-collector.md`.

## Stop Conditions

需要账号、验证码、网盘提取码、版权授权或大批量下载许可时，停止并让用户确认。
