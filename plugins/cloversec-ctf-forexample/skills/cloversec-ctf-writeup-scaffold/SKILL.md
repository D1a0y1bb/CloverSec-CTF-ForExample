---
name: cloversec-ctf-writeup-scaffold
description: 四叶草安全-创研中心竞赛专用题目手册构建 Skills，面向题目源码、WP、构建产物与零散人工草稿的标准化整理：自动提取考点、部署信息、Flag线索、HUB录题字段与题解模板，并生成符合内部规范的 manual_template.md / manual_filled_draft.md 草稿。
---

# CloverSec-CTF-Writeup-Scaffold

四叶草安全-创研中心竞赛专用题目手册构建 Skills，面向题目源码、WP、构建产物与零散人工草稿的标准化整理：自动提取考点、部署信息、Flag线索、HUB录题字段与题解模板，并生成符合内部规范的 `manual_template.md` / `manual_filled_draft.md` 草稿。

v0.4.0 的重点不是继续堆门面，而是把本技能升级成**可回归、可审计、可规模化维护**的题目文档生产引擎。默认推荐“**先提案、后生成**”：先输出高影响字段的提案摘要，再决定是否生成模板版和草稿版。

## 一句话定位

当出题人已经有题目源码、WP、构建信息或零散说明，希望快速生成符合内部规范、可直接审阅和录入的平台文档时，使用本技能。

## 能力边界

- 做的事：文档标准化、录题字段整理、证据化上下文抽取、模板版 / 草稿版生成、格式校验。
- 不做的事：自动出题、环境构建、实际部署运维、无证据的完整题解编造。
- 协同方式：可与 `CloverSec-CTF-Build-Dockerizer` 串联，但仍保持独立运行。

## 适用场景

- 只有 WP、Markdown 或零散人工草稿，希望快速得到标准手册骨架。
- 有源码但文档不完整，希望先抽取考点、启动方式、Flag 路径与录题字段候选。
- 有 `challenge.yaml`、`Dockerfile`、`start.sh`、`changeflag.sh`、`check/`，希望吸收到部署说明与平台备注。
- 做外部题转内部题，希望把材料统一到内部标准格式并保留人工审阅空间。

## 输入契约

优先读取以下输入：

1. `challenge.yaml` / `challenge.yml`
2. `Dockerfile`
3. `start.sh`
4. `changeflag.sh`
5. `check/` 或 `check.sh`
6. `writeup.md` / `wp.md` / `README.md`
7. 其他与题目直接相关的源码、配置和人工草稿

额外说明：

- 默认允许读取**当前工作目录 + 用户显式指定路径**中的必要文件。
- 不做无边界扩散扫描。
- 对目录深度、文件大小和扩展名做保守约束。
- 如缺少关键材料，不得凭空补写题名、Flag、来源、分值、备注、非预期测试点。

## 输出契约

固定输出：

- `manual_template.md`
- `manual_filled_draft.md`

中间产物 / 推荐辅助输出：

- `writeup_context.json`
- `writeup_proposal.md`
- `hub_fields.json`
- `xlsx_fields.json`

结构硬约束：

- 固定章节为 `1.1`~`1.8` 与 `2.1`~`2.14`
- `2.1`~`2.11` 必须使用 `plain` 代码块
- `2.11` 与 `2.12` 间必须插入 `---`
- 附件清单与上传清单统一使用 `● / ○` 两级结构
- 难度只能是“简单 / 中等 / 困难”
- Hub 与 xlsx 字段保留 10 级难度编号、星级和完整 Flag
- 分类只能落在 `Web / Pwn / Crypto / Misc / Reverse / Mobile / IoT`

## AI Orchestrated Mode（强制协议）

### Step 0：Collect

- 只收集当前目录与显式路径中的必要材料。
- 优先结构化证据，其次 WP 和人工草稿。
- 不得为了“多看一点”而扩散扫描仓库外目录。

### Step 1：Infer

- 运行上下文抽取，生成字段级 `value / status / confidence / evidence`。
- 提取题目名称候选、分类候选、题目类型、Flag 类型、端口、入口、附件结构、考点、工具和关键词。
- 允许保守推断工程事实，不允许虚构敏感结论。

### Step 2：Proposal（推荐）

先提案、后生成。默认只确认 4 类高影响项：

1. 题目名称
2. 分类 / 题目类型
3. 是否按动态 Flag 处理
4. 是否把“解题步骤”保留为完全人工补写

提案摘要至少应能说明：

- 题目名称候选
- 分类候选
- 题目类型判断
- 构建产物吸收结果
- 仍需人工补写字段

### Step 3：Draft

- 输出 `manual_template.md`：保留人工补写空间，尤其是解题步骤。
- 输出 `manual_filled_draft.md`：仅补齐可确认或可保守推断的非敏感段落。
- 题型模板可差异化引导解题步骤，但不得把未知利用链写成既成事实。

### Step 4：Validate

生成后必须执行格式校验，检查：

- 固定章节完整性
- `plain` 代码块
- 枚举值合法性
- `---` 分隔符
- `● / ○` 层级
- `2.13` / `2.14` 是否存在且非空

## 数据层与回归层

v0.4.0 开始，本技能不再只靠脚本硬编码规则，而是引入：

- `data/categories.yaml`
- `data/difficulty_rules.yaml`
- `data/source_patterns.yaml`
- `data/template_defaults.yaml`

同时引入：

- `examples/`：四类最小样例
- golden outputs：`manual_template.expected.md` 与 `manual_filled_draft.expected.md`
- `python3 scripts/validate_examples.py`：统一回归入口

## 反编造规则（硬约束）

- 不得凭空补写题目名称、题目 Flag、题目来源、分值、备注、非预期测试点。
- 无法确认的字段只能留空或使用占位符。
- 推断出的内容必须偏工程事实，不得写成营销化、故事化或过度 AI 总结腔。
- 不得把本技能当自动出题器使用。

## 与 CloverSec-CTF-Build-Dockerizer 的协同方式

推荐链路：

1. 先用 `CloverSec-CTF-Build-Dockerizer` 生成交付件与校验结果。
2. 把 `challenge.yaml`、`Dockerfile`、`start.sh`、`changeflag.sh`、`check/` 留在当前目录。
3. 再用本技能生成手册模板、录题字段和题解草稿。

但没有上游产物时，本技能也必须能从源码 / WP / 人工材料独立工作。

## 手动模式（备用）

```bash
python3 src/CloverSec-CTF-Writeup-Scaffold/scripts/extract_context.py --project-dir . --pretty --output writeup_context.json --proposal-out writeup_proposal.md
python3 src/CloverSec-CTF-Writeup-Scaffold/scripts/render_manual.py --project-dir . --output-dir .
python3 src/CloverSec-CTF-Writeup-Scaffold/scripts/validate_manual.py manual_template.md manual_filled_draft.md
```

`render_manual.py` 会同时生成 `hub_fields.json` 与 `xlsx_fields.json`。`hub_fields.json` 的 `题目Flag` 和 `xlsx_fields.json` 的 `Flag` 必须保存完整 Flag。

## 命令速查

### 核心命令

```bash
python3 src/CloverSec-CTF-Writeup-Scaffold/scripts/extract_context.py --project-dir . --pretty --output writeup_context.json --proposal-out writeup_proposal.md
python3 src/CloverSec-CTF-Writeup-Scaffold/scripts/render_manual.py --project-dir . --output-dir .
python3 src/CloverSec-CTF-Writeup-Scaffold/scripts/validate_manual.py manual_template.md manual_filled_draft.md
```

### 提案与差异预览

```bash
python3 scripts/render_summary.py --project-dir . --compare-render
```

### 回归与发布

```bash
python3 scripts/validate_examples.py
bash scripts/sync.sh --codex-dir
bash scripts/release_build.sh
bash scripts/publish_release.sh --dry-run
```

## 自检清单

- 是否先输出了提案摘要
- 是否保留了解题步骤等人工补写空间
- 是否正确吸收了构建产物中的部署信息
- 是否为核心字段保留了 evidence / confidence
- 是否通过了 examples 回归和格式校验

## 故障排查剧本

- 草稿信息太少：先看 `writeup_proposal.md` 的缺失字段列表。
- 题目被判成附件型：通常是缺少 `challenge.yaml`、`Dockerfile`、`start.sh` 或端口线索。
- 校验失败：优先检查 `2.1`~`2.11`、`2.13`、`2.14` 与 `● / ○` 层级。
- 规则升级后质量漂移：先跑 `python3 scripts/validate_examples.py`，确认是否属于预期变更。

## 变更边界

- 不要在本技能中引入容器构建职责。
- 不要把文档规范与平台部署契约混成一个技能。
- 不要为了“写满内容”而牺牲反编造边界。

## 相关文件索引

- 规则层：`data/`
- 样例与 golden outputs：`examples/`
- 规范文档：`references/spec.md`
- 推断边界：`references/inference-guide.md`
- 构建 skill 联动：`references/integration.md`
- 标准文档归档：`docs/竞赛题目手册标准文档.md`
