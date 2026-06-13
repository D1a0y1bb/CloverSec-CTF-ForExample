---
name: cloversec-ctf-research-intake
description: CloverSec CTF 竞赛信息和赛题信息收集 skill。按年份、赛事、类别、关键词或来源收集竞赛、题目、writeup、附件线索和证据，输出可进入复现和归档流程的结构化结果。
---

# CloverSec CTF Research Intake

## Use This When

- 用户要收集某年或某赛事的 CTF 竞赛、赛题、writeup、附件线索。
- 输入是年份、赛事名、题目名、分类、URL、旧 xlsx 或零散清单。
- 输出需要 `search_results.json`、`ctf_cases.jsonl`、`research_report.md` 或 xlsx 行草稿。

## Default Behavior

1. 如果当前 Agent 有联网搜索工具，先用它查 Google/Baidu/全网结果，再导入为 `provider=agent-web-search`。
2. 再跑默认免费源：GitHub、CTFTime、DuckDuckGo、公开归档 seeds、CTF 平台 seeds、CSDN、博客园、语雀。
3. GitHub code search 优先使用 `GITHUB_TOKEN` / `GH_TOKEN`，没有环境变量时尝试本机 `gh auth token`。
4. 默认搜索能力不要求任何付费搜索 API key。
5. 每条结果必须保留 `source_url`、`title`、`snippet`、`provider`、`confidence`、`evidence`、`layer`、`score`。
6. 不把推断内容写成事实；无法确认的字段留空并记录缺失原因。

## Result Layers

- `confirmed_challenge`: 明确到具体题目，且有赛事、年份和题名证据。
- `writeup_candidate`: 有 writeup/WP/源码说明/文章线索，但附件未确认。
- `attachment_candidate`: 疑似源码、附件、Release、raw 文件或直接下载链接。
- `platform_lead`: 平台入口，必须带 `lead_only=true`，不能直接当题目。
- `noise`: 无关赛事、教程、搜索页、登录页、验证码页。

## Commands

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py discover \
  --query "LA CTF 2024 web challenge writeup" \
  --year 2024 \
  --limit 20 \
  --output search_results.json \
  --cases-jsonl ctf_cases.jsonl
```

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py import-agent-search \
  --input agent_web_results.json \
  --query "IrisCTF 2025 web writeup" \
  --provider agent-web-search \
  --output search_results.agent.json
```

## MCP Tools

- `cloversec_ctf_discover`
- `cloversec_ctf_ctftime_events`
- `cloversec_ctf_fetch_url`
- `cloversec_ctf_github_release_assets`
- `cloversec_ctf_import_agent_web_results`
- `cloversec_ctf_browser_search_plan`
- `cloversec_ctf_browser_search_import_visible`

## Read When Needed

- Detailed scoring, source list, commands, and stop conditions: `references/research-intake.md`.

## Stop Conditions

遇到付费墙、登录限制、版权风险、来源真实性无法判断、用户要求渠道不明确或大批量抓取风险时，停止并让用户确认。
