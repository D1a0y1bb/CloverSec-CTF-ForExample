<p align="center">
  <img src="plugins/cloversec-ctf-forexample/assets/app-icon.png" width="120" alt="CloverSec CTF For Example icon" />
</p>

<h1 align="center">CloverSec CTF For Example</h1>

<p align="center">
  <strong>CloverSec CTF 周期性工作 Codex Plugin：收集题目、整理资源、容器改造、写手册、归档、检查和 Hub 提交准备。</strong>
</p>

<p align="center">
  <a href="https://github.com/D1a0y1bb/CloverSec-CTF-ForExample/releases"><img alt="Version" src="https://img.shields.io/badge/version-v1.0.7-2563eb"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-green"></a>
  <img alt="Codex Plugin" src="https://img.shields.io/badge/Codex-Plugin-111827">
  <img alt="Skills" src="https://img.shields.io/badge/skills-15-f59e0b">
  <img alt="MCP" src="https://img.shields.io/badge/MCP-8-8b5cf6">
</p>

## Overview

`CloverSec CTF For Example` 是给 Codex 使用的 CTF 工作插件。它不是一个单独命令，而是一组 skill、脚本和 MCP server。你把目标说清楚，例如“收集 2025 IrisCTF 的 Web 题、WP 和附件线索”，Codex 会按场景调用搜索、下载预览、资源识别、Dockerizer 交接、手册、归档、质量检查和 Hub 提交准备能力。

它适合处理竞赛岗位里重复、耗时、容易漏文件的工作：找资料、整理附件、识别源码、生成 Dockerizer 输入、写中文手册、检查 Flag 和截图、做中文交付包、准备 Hub 填表材料。人的判断仍然保留在关键位置，比如未知 Docker 执行、Hub 最终提交、分类不确定、材料缺失和平台不兼容题。

我们准备了一个演示视频，用来展示一批 CTF 题目怎样从公开线索整理到内部交付包：题目信息收集、附件和源码整理、平台镜像改造、手册撰写、检查、Hub 浏览器辅助填表和最终 xlsx/语雀表。

## 1.0.7 交付样式

`1.0.7` 按内部已经认可的真实题目归档样例调整输出，不再把英文过程文件当成最终交付入口。

批次根目录主要放这些文件：

```text
交付说明.md
最终归档表.xlsx
语雀粘贴表.md
分类-题目名/
```

容器题目录按三件套整理：

```text
分类-题目名/
├── 题目源码/
├── 题目镜像/
└── 题目手册/
    └── 题目解题手册.md
```

附件题目录按两件套整理，不生成 `题目镜像/`：

```text
分类-题目名/
├── 题目附件/
└── 题目手册/
    └── 题目解题手册.md
```

正式手册按真实样例的结构输出：先写题目说明、环境和附件，再写解题过程、关键命令、截图说明、Flag 和复现说明。`manual_template.md`、`manual_filled_draft.md`、中间 JSON、过程日志不作为人接手的主入口。

收集表也按人工整理过的 `最新赛事收集.xlsx` 风格生成：中文字段、固定列宽、统一行高、细边框、等线 12 号字体。表格给人看，JSONL 给 Agent 继续处理，两边通过同一条记录对应。

## Quick Start

在 Codex 插件页选择“添加插件市场”：

```text
来源：D1a0y1bb/CloverSec-CTF-ForExample
Git 引用：v1.0.7
稀疏路径：留空
```

也可以用命令行：

```bash
codex plugin marketplace add D1a0y1bb/CloverSec-CTF-ForExample --ref v1.0.7
codex plugin add cloversec-ctf-forexample@cloversec-ctf
```

安装或更新后新开 Codex 会话，然后直接描述目标：

```text
使用 CloverSec CTF For Example，帮我收集 2025 IrisCTF 的 Web 题、writeup 和附件线索。
```

```text
根据这个 ctf_cases.jsonl，整理附件、源码、WP，识别哪些题需要进入 Dockerizer，最后输出中文交付包。
```

## Recommended Setup

| 项目 | 是否必须 | 用途 |
| --- | --- | --- |
| `gh auth login` | 推荐 | GitHub 搜索、仓库预览、Release 资源更稳定 |
| Docker Desktop | 容器题需要 | build/run/inspect/save/load、amd64 检查 |
| PyYAML | 容器改造需要 | Dockerizer 解析 `challenge.yaml`、`stacks.yaml` 和模板数据 |
| openpyxl | 推荐 | 生成更整齐的 xlsx；未安装时仍可导出基础 xlsx |
| Chrome 已登录 Hub | Hub 辅助填写需要 | 使用当前浏览器页面准备提交，不保存 Cookie、token 或密码 |
| 题目目录或清单 | 推荐 | 可以是 `ctf_case.json`、`ctf_cases.jsonl`、xlsx、zip、URL |

安装 Dockerizer 依赖：

```bash
pip install -r plugins/cloversec-ctf-forexample/skills/cloversec-ctf-build-dockerizer/scripts/requirements.txt
```

检查本机能力：

```bash
python3 scripts/doctor.py
```

## Common Requests

| 你可以这样说 | 插件通常会做什么 | 主要产物 |
| --- | --- | --- |
| `帮我收集 2024 LA CTF 的 Web 题、WP 和附件线索` | 搜索公开来源，生成题目清单、中文收集表和证据 | `search_results.json`、`ctf_cases.jsonl`、`赛事题目信息收集表.xlsx` |
| `根据这个 ctf_cases.jsonl 收集附件和 writeup` | 下载预览、GitHub Release/tree 预览、记录 hash 和失败原因 | `downloads_sandbox/`、`material_candidates.json` |
| `识别这个题目目录下一步怎么处理` | 判断 Docker/compose/source/attachment/writeup 等资源类型，并生成中文处理建议 | `resource_classification.json`、`资源整理与处理建议表.xlsx`、`Dockerizer交接表.xlsx` |
| `这个源码题整理成平台容器交付` | 交给 `cloversec-ctf-build-dockerizer` 做平台化改造 | `Dockerfile`、`start.sh`、`changeflag.sh`、`flag` |
| `这个附件题检查后归档` | 检查压缩包、hash、解压、路径风险 | `attachment_manifest.json` |
| `根据题目目录生成手册和 Hub 字段` | 生成中文正式手册、Hub 字段、xlsx 字段 | `题目解题手册.md`、`hub_fields.json`、`xlsx_fields.json` |
| `生成 Hub 提交材料` | 生成字段、上传清单、Chrome 填写计划，最终提交前停止 | `hub_upload_manifest.json`、`hub_session_state.json` |
| `生成最终交付包` | 整理中文目录、最终表格、语雀表、质量报告 | `交付说明.md`、`最终归档表.xlsx`、`语雀粘贴表.md` |

## Full Workflow

完整处理一批题目时，可以这样给 Codex 下任务：

```text
使用 CloverSec CTF For Example，帮我完整处理 2026 年公开 CTF 题目 10 道。
要求：
1. 先创建工作目录和任务计划。
2. 收集候选题、来源证据、WP、附件和源码线索。
3. 只把来源明确、年份和分类能确认的题目写入 ctf_cases.jsonl。
4. 下载材料先进 downloads_sandbox，做 hash、大小、压缩包预览和风险检查。
5. 对每道题生成 resource_classification.json。
6. 源码题、Dockerfile、compose、镜像 tar、Web/Pwn 服务题必须进入 cloversec-ctf-build-dockerizer。
7. 附件题走附件检查和归档。
8. 生成中文正式手册、Hub 字段、xlsx 字段、归档目录、质量检查和最终交付包。
9. Docker 执行、Hub 最终提交、镜像 retag 前都要等我确认。
```

中断后继续：

```text
继续这个 runs/xxxxxxxxx 工作目录，从 workflow_state.json 里未完成的阶段继续处理。
```

查看状态：

```bash
python3 scripts/show_progress.py runs/xxxxxxxxx/workflow_state.json
python3 scripts/show_progress.py runs/xxxxxxxxx/workflow_state.json --watch
python3 scripts/show_progress.py runs/xxxxxxxxx/workflow_state.json --table
```

默认输出是中文工作汇报，适合人直接看；`--json` 给脚本和 Agent 读取；`--table` 保留旧的紧凑表格，方便调试阶段状态。
如果只拿到安装后的插件目录，也可以在插件目录里运行 `python3 scripts/show_progress.py workflow_state.json`。

需要让脚本按已有材料继续执行安全阶段时，可以直接跑工作流执行器：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py run \
  --workdir runs/xxxxxxxxx \
  --stage research \
  --stage collect \
  --stage dedupe \
  --stage download_preview \
  --stage archive \
  --stage quality \
  --stage final_report
```

批量处理 Docker 构建前，可以对明确范围做一次授权。授权文件会写进工作目录，Docker 执行器会读取它；没有授权时不会直接执行真实 Docker 操作。

```bash
python3 scripts/authorize_batch.py --workdir runs/xxxxxxxxx --action docker_build --case-id case-001 --case-id case-002
```

搜索质量验证可以生成本地报告，报告留在 `docs/validation/`，不进入发布包：

```bash
python3 scripts/search_recall_benchmark.py \
  --run-search \
  --benchmark plugins/cloversec-ctf-forexample/references/search-recall-benchmark.json \
  --input-dir docs/validation/search-recall-v1.0.7 \
  --output docs/validation/search-recall-benchmark-v1.0.7.md \
  --json-output docs/validation/search-recall-benchmark-v1.0.7.json
```

这个基准不是看关键词有没有出现，而是看已人工核对过存在的公开资源是否被搜到。当前基准覆盖西电 XDSEC miniLCTF、中科大 Hackergame、HGame、IrisCTF、LA CTF 和 Google CTF，按 GitHub repo / URL 归一化命中统计召回。

## Capability Table

| 能力 | 说明 |
| --- | --- |
| Workflow intake | 从年份、赛事、方向、数量创建任务目录、搜索计划和状态文件 |
| Research intake | 多来源搜索、Agent 联网搜索结果导入、浏览器可见结果导入 |
| Handoff tables | 生成中文 xlsx、JSONL 和 schema，让人能看、Agent 能继续处理 |
| Asset collection | 下载预览、GitHub Release/tree 预览、hash、失败原因 |
| Resource classifier | 识别源码、Dockerfile、compose、附件、writeup、截图、二进制、pcap |
| Container validator | 提取端口、启动命令、Flag 路径和 Dockerizer 交接信息 |
| Dockerizer | 用户已验证的 CloverSec 平台容器题改造 skill |
| Writeup scaffold | 用户已验证的中文手册和字段生成 skill |
| Archive packager | 生成中文归档目录、manifest、资源索引 |
| Quality review | 检查资源、手册、Flag、归档、Docker evidence 状态 |
| Hub submission | 生成 Hub 草稿、上传清单、浏览器辅助计划，最终提交前停止 |
| Hub retag | 审核通过后按正式 `HUB编号` 生成镜像 tag 和导出计划 |
| Final report | 生成最终 xlsx、语雀表、报告和待处理事项 |

## Development Notes

- 关键用户可见提示集中在 `plugins/cloversec-ctf-forexample/references/i18n.zh-CN.json`，后续要做英文版时优先替换这份 catalog。
- 公开搜索、下载预览、端口探测等 HTTP 请求统一走 `cloversec_ctf_http.py`，避免各脚本各自处理超时、重试和重定向。
- MCP 工具调用会记录到本机运行日志，默认在 `~/.codex/cloversec-ctf-forexample/mcp-runtime/`，用于排查批量任务里哪个工具失败。
- `cloversec_ctf_workflow.py run` 会写 `workflow_engine_run.json`、`logs/workflow_engine.jsonl` 和 `当前状态.md`，中断后可以继续同一工作目录。
- Hub 最终提交不能批量预授权，仍然需要人工确认。

## Resource Rules

| 材料情况 | 处理方式 |
| --- | --- |
| 只有题名、平台页或 WP | 只算线索，记录缺材料，不写成可交付 |
| 只有附件 zip/tar | 走附件检查、手册、归档和质量检查 |
| 有源码但没有 Dockerfile | 必须进入 Dockerizer，生成平台交付方案 |
| 有源码和上游 Dockerfile/compose | 上游文件只当迁移输入，仍必须进入 Dockerizer |
| 只有镜像 tar | 可 inspect/hash，但不能直接算平台交付件 |
| Pwn jail、kernel、eBPF、QEMU、高权限题 | 记录平台差异和运行条件，不默认写成通过 |

容器题最终要满足 `/start.sh`、`/changeflag.sh`、`/flag`、端口、linux/amd64、镜像 tar 和内部 xlsx 字段要求。直接 `docker build/run` 只能作为验证证据，不能替代 Dockerizer 平台改造。

## Handoff Files

0.8.0 开始，插件会把“给人看的表”和“给 Agent 继续处理的数据”一起生成，不再只给一堆 JSON。

| 阶段 | 给人看的文件 | 给 Agent 的文件 | 作用 |
| --- | --- | --- | --- |
| 题目信息收集 | `赛事题目信息收集表.xlsx` | `赛事题目信息收集表.jsonl`、`ctf_cases.jsonl` | 看清每道题是不是可处理、缺什么材料、下一步做什么 |
| 资源识别 | `资源整理与处理建议表.xlsx` | `资源整理与处理建议表.jsonl` | 看清每个文件是源码、附件、WP、截图还是未知资源 |
| Dockerizer 交接 | `Dockerizer交接表.xlsx` | `Dockerizer交接表.jsonl` | 源码题、Dockerfile、compose、镜像 tar 和 Web/Pwn 服务题进入 Dockerizer |

表格字段是中文，方便人工接手；JSONL 的行内容和表格一致，方便后续 Agent 继续处理。已有 Dockerfile 或 compose 只能当迁移输入，不能直接算 CloverSec 平台交付件。

## References

- [工作流说明](plugins/cloversec-ctf-forexample/references/workflow.md)
- [数据模型](plugins/cloversec-ctf-forexample/references/data-model.md)
- [调研与搜索](plugins/cloversec-ctf-forexample/references/research-intake.md)
- [资源收集](plugins/cloversec-ctf-forexample/references/asset-collector.md)
- [Hub 提交](plugins/cloversec-ctf-forexample/references/hub-submission.md)
- [脚本说明](plugins/cloversec-ctf-forexample/scripts/README.md)

## Development

常用验证：

```bash
python3 /Users/d1a0y1bb/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py plugins/cloversec-ctf-forexample
python3 scripts/validate_release.py
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/package_plugin_release.py
```

发布前用 `scripts/bump_version.py` 更新版本号。Release 标题使用 tag，例如 `v1.0.7`；正文第一行使用 `# CloverSec CTF For Example 1.0.7`。

## License

MIT License. Copyright (c) D1a0y1bb.
