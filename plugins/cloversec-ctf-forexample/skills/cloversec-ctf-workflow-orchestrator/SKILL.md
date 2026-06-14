---
name: cloversec-ctf-workflow-orchestrator
description: CloverSec CTF 批量工作流编排 skill。用于从年份、赛事、方向和数量创建采集任务，维护 workflow_state.json，执行 dry-run/apply/resume，检查 GitHub 搜索能力，生成搜索策略、来源证据、资源识别、去重候选和下载沙箱预览。
---

# CloverSec CTF Workflow Orchestrator

## 何时使用

- 用户只给年份、赛事、方向、数量，需要先创建标准工作目录。
- 批量处理多题时，需要 dry-run、apply、断点继续和单题失败记录。
- 需要检查本机 `gh auth login`、`GITHUB_TOKEN` / `GH_TOKEN` 和 GitHub 搜索能力。
- 需要按 Web/Pwn/Reverse/Crypto/Misc/Forensics/AI 分类生成搜索 query。
- 需要对搜索结果生成来源证据、HTML 快照、下载 URL、hash、抓取时间和缺失原因。
- 需要对下载或用户提供的资源目录生成 `resource_classification.json`。
- 需要对重复题目生成候选合并计划，等待人工确认后再合并。
- 需要把外部附件先放进下载沙箱，预览大小、hash、压缩包路径和风险。

## 默认工作目录

未指定输出目录时，使用：

```text
runs/<日期>-<年份>-<赛事>-<方向>
```

目录结构：

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

## 完整流程执行规则

用户要求“完整处理”“全流程”“一路做完”时，按下列阶段推进，并在需要确认的地方停止等待：

```text
任务创建 -> 搜索候选 -> 来源证据 -> 去重筛选 -> 下载沙箱 -> 资源识别 -> 容器推断 -> 容器改造或附件检查 -> 手册字段 -> 归档预览 -> 质量检查 -> Hub 草稿 -> Hub 审核状态/retag -> 最终报告
```

默认先执行不改文件、不运行未知代码的阶段。下列动作必须等用户确认：

- 把下载沙箱内容移入正式题目目录。
- 生成或覆盖 `Dockerfile`、`start.sh`、`changeflag.sh`、`flag`、`check/check.sh`。
- 执行 Docker build/run/save/load，尤其是 `--privileged`、capability、宿主目录挂载、内网访问。
- Hub 页面上传附件、填写真实提交内容、最终提交。
- 审核后根据 Hub 编号 retag、导出镜像 tar、回写最终归档。

中断后优先读取 `workflow_state.json`，从未完成阶段继续，不把未验证阶段写成通过。

## 资源分流规则

下载后或用户提供目录后，必须先输出 `resource_classification.json`，再决定下一步：

| 资源状态 | 下一步 | 质量结论 |
|---|---|---|
| 没有源码、没有附件，只有题名/WP 线索 | 写缺失项和人工入口，不进入构建 | `missing_source` / `needs_user_material` |
| 只有附件 zip/tar | `cloversec-ctf-attachment-packager` | 附件题检查，不强行容器化 |
| 有源码，没有 Dockerfile | `cloversec-ctf-build-dockerizer` 先出方案 | 可转容器候选，需后续验证 |
| 有源码和上游 Dockerfile/compose | 仍进入 `cloversec-ctf-build-dockerizer` | 上游 Dockerfile/compose 只作为迁移输入 |
| 只有镜像 tar | 授权后 inspect/hash，缺平台契约时写迁移计划 | 不能直接算平台交付 |
| Pwn jail/kernel/eBPF/QEMU/privileged 题 | 静态推断和普通权限计划；高权限单独确认 | 记录运行条件和平台差异 |

看到 Dockerfile、compose 或官方启动脚本时，不能直接把它们当作 CloverSec 平台最终交付。容器题最终必须经 `cloversec-ctf-build-dockerizer` 生成或校验 `/start.sh`、`/changeflag.sh`、`/flag`、端口、amd64、镜像 tar 和 xlsx 字段。

## 常用命令

创建任务：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py init \
  --event "IrisCTF" \
  --year 2025 \
  --category web \
  --limit 20
```

生成搜索策略：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py strategy \
  --event "IrisCTF" \
  --year 2025 \
  --category web \
  --output search_strategy.json
```

批处理状态：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py batch \
  --workdir runs/20260614-2025-IrisCTF-web \
  --stage research \
  --mode dry-run \
  --output reports/research_dry_run.json
```

GitHub 配置检查：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py github-doctor \
  --sample-query "IrisCTF 2025 writeup" \
  --output github_sources_status.json
```

来源证据与快照：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py source-evidence \
  --manifest search_results.json \
  --evidence-dir evidence \
  --snapshots-dir snapshots
```

去重候选：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py dedupe \
  --cases ctf_cases.jsonl \
  --output dedupe_candidates.json
```

下载沙箱：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py download-sandbox \
  --manifest search_results.json \
  --max-redirects 5 \
  --output-dir .
```

资源识别：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_resource.py classify \
  path/to/challenge \
  --output classification/resource_classification.json
```

## 输出约束

批量任务不要一次输出很长的 JSON。给用户看的状态优先用短 JSON 或表格，详细记录写入文件。

短 JSON 字段类型固定：

```json
{
  "wf": true,
  "gh": true,
  "strategy": true,
  "evidence": true,
  "sandbox": true,
  "dedupe_human": true,
  "hub_submit": false,
  "flag_xlsx": true,
  "json_mitigation": "short_json"
}
```

- `json_mitigation` 必须是字符串，只能取 `short_json`、`chunking`、`larger_output_tokens`。
- `hub_submit` 必须是布尔值 `false`，最终提交交给人确认。
- `flag_xlsx` 必须是布尔值 `true`，内部 xlsx 保留完整 Flag。
- 长报告、完整证据、下载预览和去重候选写到文件路径里，不塞进一次模型回复。

## MCP Tools

- `cloversec_ctf_workflow_init`
- `cloversec_ctf_workflow_batch`
- `cloversec_ctf_search_strategy`
- `cloversec_ctf_github_doctor`
- `cloversec_ctf_source_evidence`
- `cloversec_ctf_dedupe_candidates`
- `cloversec_ctf_dedupe_apply`
- `cloversec_ctf_download_sandbox`
- `cloversec_ctf_resource_classify`
- `cloversec_ctf_visible_content_evidence`
- `cloversec_ctf_confirmation_request`
- `cloversec_ctf_stage_notification`
- `cloversec_ctf_codex_warning_report`

## 多 Agent 分工

大批量任务需要拆给多个 Codex 会话时，读取 `references/agent-roles.json`。角色固定为 Research、Asset、Docker、Writeup、Review、Hub、Archive，每个角色都有明确输入、输出、skill 和 MCP tool ID。输出 ID 时只能使用文件中的精确 ID。

## 规则

- dry-run 可以生成计划和预览，不把未执行阶段写成完成。
- apply 写入 `workflow_state.json`。
- resume 跳过已完成的单题阶段。
- 下载后或用户提供目录后，先输出 `resource_classification.json`，再决定进入 Dockerizer、附件题检查、手册或人工确认。
- 现成 Dockerfile、compose 或官方启动脚本只能作为证据和迁移输入；不能跳过 `cloversec-ctf-build-dockerizer`。
- 直接 Docker build/run 只能作为验证证据，不能替代 CloverSec 平台交付改造。
- 去重只生成候选，默认不合并；只有人工把 `approved` 改成 `true` 才合并。
- 外部附件先进入 `downloads_sandbox/`，安全预览通过后才能进入 `downloads_accepted/`。
- 下载沙箱默认单文件上限 300MB、最多 5 次重定向，禁止 `file://`、`ftp://`、localhost、内网 IP 和路径穿越压缩包。
- 不确定来源、分类、附件和题目对应关系时，把问题写入报告或 TODO，不写成已确认。
