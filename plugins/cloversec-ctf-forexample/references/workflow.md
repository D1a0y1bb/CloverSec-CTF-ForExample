# CloverSec CTF Workflow

## 阶段

1. `cloversec-ctf-research-intake`：收集赛事和赛题信息。
2. `cloversec-ctf-asset-collector`：收集题目源码、附件、WP、复现资料。
3. `cloversec-ctf-build-dockerizer`：容器题目构建转换。
4. `cloversec-ctf-attachment-packager`：附件题目检查和打包。
5. `cloversec-ctf-writeup-scaffold`：手册和 Hub 字段草稿。
6. `cloversec-ctf-archive-packager`：归档目录、镜像 tar、hash 清单。
7. `cloversec-ctf-quality-review`：题目、手册、附件、镜像一致性检查。
8. `cloversec-ctf-hub-submission`：Hub 提交材料生成。
9. `cloversec-ctf-hub-retag`：审核通过后按 HUB 编号重打镜像 tag。
10. `cloversec-ctf-final-report`：最终位置、xlsx 和后续动作报告。

## 全局原则

- 每个阶段产生结构化结果，写入 `ctf_case.json` 或批量 `ctf_cases.jsonl`。
- 不确定字段保留为空，并记录需要用户确认的原因。
- 公网收集优先使用免费源：GitHub、CTFTime、DuckDuckGo、公开归档 seeds、CTF 平台 seeds、CSDN、博客园、语雀。
- 当前 Agent 有联网搜索工具时，优先使用 Agent 搜索 Google/Baidu/全网结果，再导入插件数据模型。
- GitHub 增强优先使用本机 `gh auth login` 或 `GITHUB_TOKEN` / `GH_TOKEN`；Brave/Bing 只作为可选 provider。
- 搜索、抓取、下载必须写入来源 URL、访问时间、hash、HTTP 状态和失败原因。
- Hub 自动化第一版不提交，只生成材料。
- 涉及镜像导出时必须检查 `linux/amd64`。
- 内部 xlsx、语雀归档表和相关字段草稿必须保留完整 `Flag`，不能替换成摘要或脱敏值。
- 阶段结束前更新 `TODO.md`。

## 搜索与采集能力

脚本入口：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py discover --query "<赛事/题目/年份/分类>" --year 2025 --output search_results.json --cases-jsonl ctf_cases.jsonl
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-from-manifest --manifest search_results.json --output-dir downloads --output asset_downloads.json
```

MCP 入口：

- `cloversec_ctf_discover`
- `cloversec_ctf_ctftime_events`
- `cloversec_ctf_fetch_url`
- `cloversec_ctf_github_release_assets`
- `cloversec_ctf_import_agent_web_results`
- `cloversec_ctf_browser_search_plan`
- `cloversec_ctf_browser_search_import_visible`

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
