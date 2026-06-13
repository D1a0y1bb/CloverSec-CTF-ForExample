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
2. 先跑免费源：CTFTime events/writeups、GitHub repository search、公开归档 seeds、DuckDuckGo HTML。
3. 如果用户提供 key，再启用 GitHub code search、Brave Search、Bing Search。
3. 每条记录保留来源链接、访问日期、证据摘要。
4. 对缺少来源、题名、分类、附件线索的记录标记 `无法确认`。
5. 输出结构化结果，不把推断内容写成事实。

## 脚本入口

公网搜索：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py discover \
  --query "LA CTF 2024 web challenge writeup" \
  --year 2024 \
  --source github \
  --source ctftime \
  --source duckduckgo \
  --source seeds \
  --limit 20 \
  --output search_results.json \
  --cases-jsonl ctf_cases.jsonl
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

Codex 当前会话没有这些 MCP 工具时，使用脚本入口。

## 可选 key

- `GITHUB_TOKEN` 或 `GH_TOKEN`：启用 GitHub code search，提高仓库内 WP/README 命中率。
- `BRAVE_SEARCH_API_KEY` 或 `CLOVERSEC_BRAVE_API_KEY`：启用 Brave Search。
- `BING_SEARCH_API_KEY` 或 `CLOVERSEC_BING_API_KEY`：启用 Bing Search。

没有 key 时仍使用 GitHub repository search、CTFTime、DuckDuckGo HTML 和内置公开归档 seeds。

真实内部 xlsx 不应提交到公开仓库。

## 验证

- 每条记录必须有来源或明确标记为用户提供。
- 同名题目需要记录赛事来源，不能直接合并。
- 无法确认的字段留空，并写入缺失项列表。
- `search_results.json` 的 `errors` 中如果出现 provider 失败或跳过，报告里必须写明。

## 停止条件

遇到付费墙、登录限制、版权风险、来源真实性无法判断、用户要求的渠道不明确、大批量抓取可能影响站点时，停止并给用户选择。
