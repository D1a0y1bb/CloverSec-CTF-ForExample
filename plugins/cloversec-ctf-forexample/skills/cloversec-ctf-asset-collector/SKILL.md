---
name: cloversec-ctf-asset-collector
description: CloverSec CTF 题目附件、源码、WP、复现资料收集 skill。用于基于赛题清单和搜索结果，从 GitHub、CTFTime、公开归档、直接 URL、可选搜索 API 与本地材料整理和下载源码、附件、WP、截图、hash、来源证据、缺失项和可复现材料。
---

# CloverSec CTF Asset Collector

## 任务定位

围绕已确定的赛题清单收集题目源码、附件、WP、复现说明、官方公告、仓库链接、网盘或压缩包信息。该 skill 负责找材料、下载允许下载的直接文件、记录证据和失败原因；不负责构建镜像，也不负责写手册。

## 输入

- `research_table.xlsx`、`ctf_cases.jsonl` 或单题 `ctf_case.json`。
- 题目链接、仓库链接、附件链接、WP 链接。
- 用户提供的本地附件目录。

## 输出

- `asset_inventory.json`：材料清单。
- `asset_downloads.json`：直接 URL 下载结果。
- `asset_collection_report.md`：收集状态和缺失项。
- `downloads/`：用户许可后保存的附件或源码。

清单字段：`asset_type`、`name`、`source_url`、`local_path`、`sha256`、`size`、`license_or_notice`、`status`、`evidence`。

## 工作流程

1. 读取赛题清单或 `search_results.json`，按题目建立材料目录。
2. 把 GitHub repo、GitHub Release asset、GitHub raw/blob、CTFTime writeup、公开归档、直接附件 URL 分开记录。
3. 只自动下载直接文件 URL，例如 `.zip`、`.tar.gz`、`.pdf`、`.md`、图片；网盘、登录页、未知动态页面只记录来源。
4. 对下载文件计算 SHA256，记录大小、content-type 和来源 URL。
5. 对 HTTP 4xx/5xx、失败下载、失效链接、疑似错题材料标记问题，不把错误页写成成功附件。
6. 对 zip/tar 附件先用 `preview-archive` 生成目录预览，检查路径穿越和文件清单。
7. 输出材料清单给下游 skill 使用。

## 脚本入口

公网搜索后下载直接附件 URL：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py discover \
  --query "Google CTF 2023 web challenge attachment" \
  --source github \
  --source ctftime \
  --source seeds \
  --limit 20 \
  --output search_results.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-from-manifest \
  --manifest search_results.json \
  --output-dir downloads \
  --max-files 10 \
  --output asset_downloads.json
```

GitHub Release 附件：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py github-release-assets \
  --repo owner/repo \
  --output github_release_assets.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-github-release-assets \
  --repo owner/repo \
  --output-dir downloads \
  --max-files 10 \
  --output release_downloads.json
```

GitHub raw/blob 文件和目录树：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-github-raw \
  https://github.com/owner/repo/blob/main/path/challenge.zip \
  --output-dir downloads \
  --output raw_download.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-github-tree \
  --repo owner/repo \
  --ref main \
  --path-prefix challenges \
  --output-dir downloads \
  --asset-only \
  --output tree_downloads.json
```

压缩包预览：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py preview-archive \
  downloads/challenge.zip \
  --output archive_preview.json
```

抓取单个 URL：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py fetch-url <URL> --output fetched_url.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-url <URL> --output-dir downloads --output downloaded_asset.json
```

本地材料目录扫描：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py asset-inventory <题目材料目录> asset_inventory.json
```

生成结果包含文件名、相对路径、材料类型、大小、SHA256 和状态。

## 验证

- 本地存在的附件必须能读取并计算 hash。
- 远程材料未下载时，不能写成已收集；必须保留 `source_url` 和失败原因。
- 题目名称、赛事来源和附件名称不一致时，写入风险项。
- 下载文件超过上限、HTTP 失败、content-type 可疑时，写入 `issues`。
- GitHub 目录树下载保留相对路径，遇到异常路径或下载失败写入 `issues`。
- zip/tar 预览发现路径穿越时，禁止直接进入归档交付流程。

## 停止条件

需要账号、验证码、网盘提取码、版权授权或大批量下载许可时，停止并给用户选择。
