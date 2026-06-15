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

1. 如果用户给的是年份、赛事、方向、数量，先使用 `cloversec_ctf_workflow_init` 创建工作目录、`task_plan.json`、`workflow_state.json`、`ctf_cases.jsonl`、日志目录和证据目录。
2. 随后使用 `cloversec_ctf_collect_execute` 执行 `task_plan.search_tasks`，写入 `search_results.json`、`ctf_cases.jsonl` 和来源证据。不要只给搜索计划。
3. 使用 `cloversec_ctf_collect_materials` 把直接附件 URL、GitHub Release、raw/tree 文件和仓库预览整理成本地材料候选。
4. 使用 `cloversec_ctf_search_strategy` 为 Web/Pwn/Reverse/Crypto/Misc/Forensics/AI 生成专用 query。
5. 单题或补充查询时使用 `cloversec_ctf_search_plus`。它会统一默认免费源、Agent 联网搜索结果、Chrome/浏览器可见结果、直接附件 URL、GitHub Release/tree 线索和短 JSON 输出。
6. 如果当前 Agent 有联网搜索工具，先用它查 Google/Baidu/全网结果，再把结果传给 `cloversec_ctf_search_plus.agent_results` 或写成文件交给 `cloversec_ctf_collect_execute`。
7. 再跑默认免费源：GitHub、CTFTime、DuckDuckGo、公开归档 seeds、CTF 平台 seeds、CSDN、博客园、语雀。
8. GitHub code search 优先使用 `GITHUB_TOKEN` / `GH_TOKEN`，没有环境变量时尝试本机 `gh auth token`；需要诊断时使用 `cloversec_ctf_github_doctor`。
9. 每条结果必须保留 `source_url`、`title`、`snippet`、`provider`、`confidence`、`evidence`、`layer`、`score`。
10. 直接附件 URL 进入下载沙箱，不要直接写入正式题目目录。
11. 不把推断内容写成事实；无法确认的字段留空并记录缺失原因。
12. `ctf_cases.jsonl` 必须区分线索和可处理题目。只有题名、平台页、WP、solver repo 的记录写 `writeup_only`、`solver_or_writeup_only`、`lead_only` 或 `needs_material_check`，不能写成可交付。
13. 每道题至少写清题名、赛事、年份、分类、来源 URL、来源等级、材料状态、WP 状态和下载候选。缺源码、缺附件、缺官方题包时直接写在 `missing_reason` 和 `metadata.问题`。
14. 冷门比赛、中文站点收录差、附件下架或网盘失效时，用 Agent 联网搜索、Chrome 浏览器辅助搜索或用户提供的入口继续补证据。
15. 大结果不要让 LLM 一次性输出长 JSON；优先让工具写文件，聊天里只返回短 JSON 摘要、top results 和待人工处理项。

## Result Layers

- `confirmed_challenge`: 明确到具体题目，且有赛事、年份和题名证据。
- `writeup_candidate`: 有 writeup/WP/源码说明/文章线索，但附件未确认。
- `attachment_candidate`: 疑似源码、附件、Release、raw 文件或直接下载链接。
- `platform_lead`: 平台入口，必须带 `lead_only=true`，不能直接当题目。
- `noise`: 无关赛事、教程、搜索页、登录页、验证码页。

## Commands

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py init \
  --event "IrisCTF" \
  --year 2025 \
  --category web \
  --limit 20
```

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py github-doctor \
  --sample-query "IrisCTF 2025 writeup" \
  --output github_sources_status.json
```

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py discover \
  --query "LA CTF 2024 web challenge writeup" \
  --year 2024 \
  --limit 20 \
  --output search_results.json \
  --cases-jsonl ctf_cases.jsonl
```

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py execute-search \
  --workdir runs/20260614-2025-IrisCTF-web \
  --limit 20 \
  --download-preview
```

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py collect-materials \
  --manifest runs/20260614-2025-IrisCTF-web/search_results.json \
  --output-dir runs/20260614-2025-IrisCTF-web
```

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py import-agent-search \
  --input agent_web_results.json \
  --query "IrisCTF 2025 web writeup" \
  --provider agent-web-search \
  --output search_results.agent.json
```

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search_plus.py \
  --query "IrisCTF 2025 web writeup" \
  --year 2025 \
  --agent-results agent_web_results.json \
  --browser-visible-results visible_results.json \
  --direct-url https://example.com/challenge.zip \
  --output search_plus.full.json \
  --compact-output search_plus.compact.json
```

## MCP Tools

- `cloversec_ctf_search_plus`
- `cloversec_ctf_discover`
- `cloversec_ctf_ctftime_events`
- `cloversec_ctf_fetch_url`
- `cloversec_ctf_github_release_assets`
- `cloversec_ctf_import_agent_web_results`
- `cloversec_ctf_browser_search_plan`
- `cloversec_ctf_browser_search_import_visible`
- `cloversec_ctf_browser_search_dom_to_visible`
- `cloversec_ctf_workflow_init`
- `cloversec_ctf_collect_execute`
- `cloversec_ctf_collect_materials`
- `cloversec_ctf_search_strategy`
- `cloversec_ctf_github_doctor`
- `cloversec_ctf_source_evidence`
- `cloversec_ctf_dedupe_candidates`
- `cloversec_ctf_download_sandbox`

## Read When Needed

- Detailed scoring, source list, commands, and stop conditions: `references/research-intake.md`.

## Stop Conditions

遇到付费墙、登录限制、版权风险、来源真实性无法判断、用户要求渠道不明确或大批量抓取风险时，停止并让用户确认。
