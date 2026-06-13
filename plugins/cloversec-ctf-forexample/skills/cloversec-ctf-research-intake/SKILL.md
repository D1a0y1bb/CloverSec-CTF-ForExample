---
name: cloversec-ctf-research-intake
description: CloverSec CTF 竞赛信息和赛题信息收集 skill。用于按年份、赛事、类别、关键词或来源从 CTFTime、GitHub、公开 CTF 归档、可选搜索 API 与用户材料整理竞赛列表、赛题列表、来源证据、字段缺失项，并生成可进入复现和归档流程的结构化表格。
---

# CloverSec CTF Research Intake

## 任务定位

收集竞赛信息和赛题信息，输出可追溯的结构化结果。适用输入包括年份范围、赛事名称、题目分类、关键词、用户给出的链接、已有 xlsx 或零散题目清单。

## 输入

- 年份范围，例如 `2024`、`2025-2026`。
- 赛事名称、赛题名称、分类、来源链接。
- 已有收集表或用户提供的材料目录。
- 可选：`ctf_case.json` 或批量 `ctf_cases.jsonl`。

## 输出

- `research_report.md`：收集说明、来源、缺失项。
- `ctf_cases.jsonl`：每道题一行结构化记录。
- `search_results.json`：公网搜索和公开归档来源结果。
- `research_table.xlsx` 或 xlsx 行草稿。

字段至少包含：`赛事来源`、`题目来源`、`名称`、`分类`、`题目类型`、`来源链接`、`证据摘要`、`收集状态`、`备注`。

## 工作流程

1. 明确目标范围：年份、赛事、分类、关键词、数量要求。
2. 如果当前 Codex Agent 有联网搜索工具，优先查 Google、Baidu 和全网结果；把可用结果导入插件数据模型，`provider` 固定为 `agent-web-search`。
3. 再跑默认免费源：GitHub repository/code search、CTFTime events/writeups、公开归档 seeds、CTF 平台 seeds、DuckDuckGo HTML、CSDN/博客园/语雀 `site:` 定向搜索。
4. GitHub code search 默认读取 `GITHUB_TOKEN` / `GH_TOKEN`，没有环境变量时尝试读取本机 `gh auth token`；不要求用户申请付费 key。
5. Google/Baidu 直连不作为稳定来源。需要这类结果时使用 `cloversec-ctf-browser-search`，只读取页面可见标题、URL、摘要、排名和搜索词。
6. 每条记录保留 `source_url`、`title`、`snippet`、`provider`、`confidence`、`evidence`。
7. 对缺少来源、题名、分类、附件线索的记录标记 `无法确认`。
8. 输出结构化结果，不把推断内容写成事实。

## 结果分层

搜索结果必须带 `layer` 和 `score`：

- `confirmed_challenge`：题名、赛事、年份、分类有明确证据。
- `writeup_candidate`：有题解、WP、源码说明或文章线索，但附件未确认。
- `attachment_candidate`：疑似源码、附件、GitHub Release、raw 文件或直接下载链接。
- `platform_lead`：CTFTime、NSSCTF、CTFHub、BUUOJ 等平台入口；同时带 `lead_only=true`，不能直接当题目。
- `noise`：无关赛事、泛教程、搜索首页、登录页、验证码页、明显不相关内容。

过滤规则：

- 赛事名强匹配。例：查询 `IrisCTF` 时，`NepCTF`、`Compfest CTF` 不能升为候选题目。
- 年份强匹配。缺年份会降分，年份冲突要降级。
- 标题 token、分类词、附件词、WP 词分别计分。
- 搜索引擎首页、登录页、验证码页直接标记 `noise`。
- CSDN/博客园文章标题出现其他赛事名时降级。
- 附件、源码、WP、题目页分开评分，不能混成同一可信等级。

## 脚本入口

公网搜索：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py discover \
  --query "LA CTF 2024 web challenge writeup" \
  --year 2024 \
  --limit 20 \
  --output search_results.json \
  --cases-jsonl ctf_cases.jsonl
```

导入 Agent 联网搜索结果：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py import-agent-search \
  --input agent_web_results.json \
  --query "IrisCTF 2025 web writeup" \
  --provider agent-web-search \
  --output search_results.agent.json
```

浏览器辅助搜索计划：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_browser_search.py plan \
  --query "IrisCTF 2025 web writeup" \
  --engine google \
  --output browser_search_plan.json
```

只查 CTFTime 赛事：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py ctftime-events --year 2025 --output ctftime_events_2025.json
```

旧表和报告：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py migrate-xlsx <旧表.xlsx> ctf_cases.jsonl
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py research-report ctf_cases.jsonl research_report.md
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py validate-collection ctf_cases.jsonl
```

## MCP 工具

插件提供 `cloversec-ctf-search` MCP server：

- `cloversec_ctf_discover`：执行 CTF 公网搜索。
- `cloversec_ctf_ctftime_events`：按年份查询 CTFTime events。
- `cloversec_ctf_fetch_url`：抓取 URL 元数据、标题、hash 和文本。
- `cloversec_ctf_github_release_assets`：列出 GitHub Release 可下载附件。
- `cloversec_ctf_import_agent_web_results`：导入当前 Agent 已查到的联网搜索结果并评分。

插件提供 `cloversec-ctf-browser-search` MCP server：

- `cloversec_ctf_browser_search_plan`：生成 Google/Baidu/CSDN/博客园/语雀浏览器辅助搜索计划，可选择打开搜索页。
- `cloversec_ctf_browser_search_import_visible`：导入页面可见搜索结果并评分。

Codex 当前会话没有这些 MCP 工具时，使用脚本入口。

## 可选 key

- `GITHUB_TOKEN` 或 `GH_TOKEN`：启用 GitHub code search，提高仓库内 WP/README 命中率。
- 本机已执行 `gh auth login` 时，脚本默认尝试读取 `gh auth token`。
- `CLOVERSEC_DISABLE_GH_AUTH_TOKEN=1`：禁止脚本读取 `gh auth token`。
- `BRAVE_SEARCH_API_KEY` 或 `CLOVERSEC_BRAVE_API_KEY`：可选 Brave Search，不作为默认要求。
- `BING_SEARCH_API_KEY` 或 `CLOVERSEC_BING_API_KEY`：可选 Bing Search，不作为默认要求。

没有付费 key 时仍使用 GitHub repository/code search、CTFTime、DuckDuckGo HTML、内置公开归档 seeds、CTF 平台 seeds，以及 CSDN/博客园/语雀 `site:` 定向搜索。没有 GitHub token 时，GitHub code search 会记录为 skipped，其他来源继续执行。
`--source github` 不等于需要 key；它会先跑 GitHub repository search。没有 `GITHUB_TOKEN` 时，只把 `github-code` 增强项记录为 skipped。
抓取工具只接受 `http://` 和 `https://` URL。

可用来源：

- `github`：GitHub repository search，未提供 token 时跳过 code search。
- `github-code`：GitHub code search，需要 `GITHUB_TOKEN` 或 `GH_TOKEN`。
- `ctftime`：CTFTime events/writeups。
- `duckduckgo`：DuckDuckGo HTML 搜索。
- `brave`：Brave Search，需要 key。
- `bing`：Bing Search，需要 key。
- `seeds`：公开归档仓库 seeds。
- `ctf-platforms`：CTFTime、NSSCTF、CTFHub、攻防世界、BUUOJ、picoCTF、pwn.college、Root-Me 等平台 seeds；结果只作为 `platform_lead`。
- `csdn`：通过 DuckDuckGo 的 `site:blog.csdn.net` / `site:csdn.net` 定向搜索。
- `cnblogs`：通过 DuckDuckGo 的 `site:cnblogs.com` 定向搜索。
- `yuque`：通过 DuckDuckGo 的 `site:yuque.com` 定向搜索。

真实内部 xlsx 不应提交到公开仓库。

## 验证

- 每条记录必须有来源或明确标记为用户提供。
- 同名题目需要记录赛事来源，不能直接合并。
- 无法确认的字段留空，并写入缺失项列表。
- `search_results.json` 的 `errors` 中如果出现 provider 失败或跳过，报告里必须写明。

## 停止条件

遇到付费墙、登录限制、版权风险、来源真实性无法判断、用户要求的渠道不明确、大批量抓取可能影响站点时，停止并给用户选择。
