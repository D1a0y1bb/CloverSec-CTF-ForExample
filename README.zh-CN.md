<p align="center">
  <img src="plugins/cloversec-ctf-forexample/assets/app-icon.png" width="112" alt="CloverSec CTF For Example" />
</p>

<h1 align="center">CloverSec CTF For Example</h1>

<p align="center">
  四叶草安全竞赛工作 Codex 插件,为解决竞赛岗位相关周期性、重复性工作而生——<br/>
  赛题收集、差距整理、题目规范容器化、手册撰写、归档,内部 Hub 平台提交。
</p>

<p align="center">
  <a href="https://github.com/D1a0y1bb/CloverSec-CTF-ForExample/releases"><img alt="Version" src="https://img.shields.io/badge/version-v1.1.0-2563eb"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-22c55e"></a>
  <img alt="Codex Plugin" src="https://img.shields.io/badge/Codex-Plugin-111827">
  <img alt="Skills" src="https://img.shields.io/badge/skills-15-f59e0b">
  <img alt="MCP" src="https://img.shields.io/badge/MCP%20servers-8-8b5cf6">
</p>

<p align="center">
  <a href="README.md">English</a>&nbsp;&nbsp;·&nbsp;&nbsp;<b>简体中文</b>
</p>

---

## 概览

**CloverSec CTF For Example** 是四叶草安全-AI 实验室专为竞赛工作所设计的 Codex 插件,专门解决CTF 出题（通用竞赛工作）准备里最慢、最重复的那部分:找源码和 WP、整理附件、把源码改造成平台容器、写中文题解手册、归档、质检,再把材料一路准备到 Hub 提交前的最后一步。

它不是一条命令,而是一组 skill、脚本和 MCP server,Codex 按需要去调。你把目标说清楚——比如「收集 2025 IrisCTF 的 Web 题、WP 和附件线索」——Codex 自己走完搜索、下载预览、资源识别、Dockerizer 交接、写手册、归档、质检、Hub 准备这一整串。

该你拍板的地方它不替你做:跑未知 Docker 镜像、Hub 最终提交、分类拿不准、材料缺失、平台不兼容的题——这些都会停下来等你,而不是替你猜。

## 快速开始

在 Codex 插件页选「添加插件市场」:

```text
来源:      D1a0y1bb/CloverSec-CTF-ForExample
Git 引用:  v1.1.0
稀疏路径:  留空
```

或者用命令行:

```bash
codex plugin marketplace add D1a0y1bb/CloverSec-CTF-ForExample --ref v1.1.0
codex plugin add cloversec-ctf-forexample@cloversec-ctf
```

装好(或更新)后新开一个 Codex 会话,直接说目标:

```text
使用 CloverSec CTF For Example,帮我收集 2025 IrisCTF 的 Web 题、writeup 和附件线索。
```

```text
根据这个 ctf_cases.jsonl,整理附件、源码、WP,识别哪些题要进 Dockerizer,最后输出中文交付包。
```

## 环境准备

| 项目 | 是否必须 | 用途 |
| --- | --- | --- |
| `gh auth login` | 推荐 | GitHub 搜索、仓库预览、Release 资源更稳 |
| Docker Desktop | 容器题需要 | build/run/inspect/save/load、amd64 检查 |
| PyYAML | 容器改造需要 | Dockerizer 解析 `challenge.yaml`、`stacks.yaml` 和模板数据 |
| openpyxl | 推荐 | xlsx 更整齐;没装也能导出基础 xlsx |
| Chrome 已登录 Hub | Hub 辅助填写需要 | 用当前页面准备提交,不存 Cookie、token、密码 |
| 题目目录或清单 | 推荐 | `ctf_case.json`、`ctf_cases.jsonl`、xlsx、zip 或 URL |

安装 Dockerizer 依赖:

```bash
pip install -r plugins/cloversec-ctf-forexample/skills/cloversec-ctf-build-dockerizer/scripts/requirements.txt
```

检查本机能力:

```bash
python3 scripts/doctor.py
```

## 你可以这样说

| 你可以这样说 | 插件通常会做什么 | 主要产物 |
| --- | --- | --- |
| `帮我收集 2024 LA CTF 的 Web 题、WP 和附件线索` | 搜公开来源,生成题目清单、中文收集表和证据 | `search_results.json`、`ctf_cases.jsonl`、`赛事题目信息收集表.xlsx` |
| `根据这个 ctf_cases.jsonl 收集附件和 writeup` | 下载预览、GitHub Release/tree 预览,记 hash 和失败原因 | `downloads_sandbox/`、`material_candidates.json` |
| `这个题目目录下一步怎么处理` | 判断 Docker/compose/source/attachment/writeup,给中文处理建议 | `resource_classification.json`、`资源整理与处理建议表.xlsx`、`Dockerizer交接表.xlsx` |
| `这个源码题整理成平台容器交付` | 交给 `cloversec-ctf-build-dockerizer` 做平台化改造 | `Dockerfile`、`start.sh`、`changeflag.sh`、`flag` |
| `这个附件题检查后归档` | 检查压缩包、hash、解压、路径风险 | `attachment_manifest.json` |
| `根据题目目录生成手册和 Hub 字段` | 生成中文正式手册、Hub 字段、xlsx 字段 | `题目解题手册.md`、`hub_fields.json`、`xlsx_fields.json` |
| `生成 Hub 提交材料` | 生成字段、上传清单、Chrome 填写计划,最终提交前停下 | `hub_upload_manifest.json`、`hub_session_state.json` |
| `生成最终交付包` | 整理中文目录、最终表格、语雀表、质量报告 | `交付说明.md`、`最终归档表.xlsx`、`语雀粘贴表.md` |

## 跑完整一批

要把一整批题从头走到尾,可以这样给 Codex 下任务:

```text
使用 CloverSec CTF For Example,帮我完整处理 2026 年公开 CTF 题目 10 道。
要求:
1. 先创建工作目录和任务计划。
2. 收集候选题、来源证据、WP、附件和源码线索。
3. 只把来源明确、年份和分类能确认的题目写入 ctf_cases.jsonl。
4. 下载材料先进 downloads_sandbox,做 hash、大小、压缩包预览和风险检查。
5. 对每道题生成 resource_classification.json。
6. 源码题、Dockerfile、compose、镜像 tar、Web/Pwn 服务题必须进入 cloversec-ctf-build-dockerizer。
7. 附件题走附件检查和归档。
8. 生成中文正式手册、Hub 字段、xlsx 字段、归档目录、质量检查和最终交付包。
9. Docker 执行、Hub 最终提交、镜像 retag 前都要等我确认。
```

中断后继续:

```text
继续这个 runs/xxxxxxxxx 工作目录,从 workflow_state.json 里未完成的阶段接着处理。
```

查看进度:

```bash
python3 scripts/show_progress.py runs/xxxxxxxxx/workflow_state.json
python3 scripts/show_progress.py runs/xxxxxxxxx/workflow_state.json --watch
python3 scripts/show_progress.py runs/xxxxxxxxx/workflow_state.json --table
```

默认输出是给人看的中文工作汇报;`--json` 给脚本和 Agent 读,`--table` 保留旧的紧凑表格方便调试阶段状态。如果手里只有装好的插件目录,在目录里直接跑 `python3 scripts/show_progress.py workflow_state.json` 即可。

<details>
<summary><b>进阶 — 直接驱动各阶段</b></summary>

让脚本按已有材料继续跑安全阶段:

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

对明确范围做一次 Docker 批量授权。授权文件写进工作目录,Docker 执行器读它;没有授权就不会跑真实 Docker 操作:

```bash
python3 scripts/authorize_batch.py --workdir runs/xxxxxxxxx --action docker_build --case-id case-001 --case-id case-002
```

验证搜索质量,报告留在 `docs/validation/`,不进发布包:

```bash
python3 scripts/search_recall_benchmark.py \
  --run-search \
  --benchmark plugins/cloversec-ctf-forexample/references/search-recall-benchmark.json \
  --input-dir docs/validation/search-recall-v1.1.0 \
  --output docs/validation/search-recall-benchmark-v1.1.0.md \
  --json-output docs/validation/search-recall-benchmark-v1.1.0.json
```

这个基准不看关键词有没有出现,而是看人工核对过、确实存在的公开资源有没有被搜到。当前覆盖西电 XDSEC miniLCTF、中科大 Hackergame、HGAME、IrisCTF、LA CTF 和 Google CTF,按 GitHub repo / URL 归一化统计召回。

</details>

## 能力一览

| 能力 | 说明 |
| --- | --- |
| Workflow intake | 从年份、赛事、方向、数量创建任务目录、搜索计划和状态文件 |
| Research intake | 多来源搜索、Agent 联网搜索结果导入、浏览器可见结果导入 |
| Handoff tables | 生成中文 xlsx + JSONL + schema,人能看、Agent 能续 |
| Asset collection | 下载预览、GitHub Release/tree 预览、hash、失败原因 |
| Resource classifier | 识别源码、Dockerfile、compose、附件、writeup、截图、二进制、pcap |
| Container validator | 提取端口、启动命令、Flag 路径和 Dockerizer 交接信息 |
| Dockerizer | 用户已验证的 CloverSec 平台容器题改造 skill |
| Writeup scaffold | 用户已验证的中文手册和字段生成 skill |
| Archive packager | 生成中文归档目录、manifest、资源索引 |
| Quality review | 检查资源、手册、Flag、归档、Docker evidence 状态 |
| Hub submission | 生成 Hub 草稿、上传清单、浏览器辅助计划,最终提交前停下 |
| Hub retag | 审核通过后按正式 `HUB编号` 生成镜像 tag 和导出计划 |
| Final report | 生成最终 xlsx、语雀表、报告和待处理事项 |

## 表给人看,数据给 Agent

每个交接阶段都同时产出「人能看的表」和「Agent 接着处理的数据」——同一条记录,两种视图。

| 阶段 | 给人看 | 给 Agent | 重点 |
| --- | --- | --- | --- |
| 题目信息收集 | `赛事题目信息收集表.xlsx` | `赛事题目信息收集表.jsonl`、`ctf_cases.jsonl` | 哪些可处理、缺什么、下一步做什么 |
| 资源识别 | `资源整理与处理建议表.xlsx` | `资源整理与处理建议表.jsonl` | 每个文件是源码、附件、WP、截图还是未知 |
| Dockerizer 交接 | `Dockerizer交接表.xlsx` | `Dockerizer交接表.jsonl` | 哪些题进 Dockerizer |

已有的 Dockerfile 或 compose 只是迁移输入,本身永远不算 CloverSec 平台交付件。

## 材料处理规则

| 材料情况 | 处理方式 |
| --- | --- |
| 只有题名、平台页或 WP | 只算线索,记缺材料,不写成可交付 |
| 只有附件 zip/tar | 走附件检查、手册、归档、质检 |
| 有源码但没 Dockerfile | 必须进 Dockerizer,生成平台交付方案 |
| 有源码 + 上游 Dockerfile/compose | 上游件只当迁移输入,仍必须进 Dockerizer |
| 只有镜像 tar | 可 inspect/hash,但不算平台交付件 |
| Pwn jail、kernel、eBPF、QEMU、高权限题 | 记录平台差异和运行条件,不默认写成通过 |

容器题最终要满足 `/start.sh`、`/changeflag.sh`、`/flag`、端口、linux/amd64、镜像 tar 和内部 xlsx 字段。直接 `docker build/run` 只能算验证证据,替代不了 Dockerizer 平台改造。

## 一些内部约定

- 用户可见文案集中在 `plugins/cloversec-ctf-forexample/references/i18n.zh-CN.json`,以后要出英文版优先换这份 catalog。
- 搜索、下载预览、端口探测等 HTTP 请求统一走 `cloversec_ctf_http.py`,超时、重试、重定向只在一处处理,不各脚本各写一套。
- MCP 工具调用记到本机运行日志,默认在 `~/.codex/cloversec-ctf-forexample/mcp-runtime/`,用来排查批量任务里哪个工具失败。
- `cloversec_ctf_workflow.py run` 会写 `workflow_engine_run.json`、`logs/workflow_engine.jsonl` 和 `当前状态.md`,中断后可在同一目录继续。
- Hub 最终提交不能批量预授权,永远需要人确认。

## 参考文档

- [工作流说明](plugins/cloversec-ctf-forexample/references/workflow.md)
- [数据模型](plugins/cloversec-ctf-forexample/references/data-model.md)
- [调研与搜索](plugins/cloversec-ctf-forexample/references/research-intake.md)
- [资源收集](plugins/cloversec-ctf-forexample/references/asset-collector.md)
- [Hub 提交](plugins/cloversec-ctf-forexample/references/hub-submission.md)
- [脚本说明](plugins/cloversec-ctf-forexample/scripts/README.md)

## 许可证

MIT © D1a0y1bb - 四叶草安全
