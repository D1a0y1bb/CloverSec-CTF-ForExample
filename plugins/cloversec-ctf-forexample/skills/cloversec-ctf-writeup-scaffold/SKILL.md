---
name: cloversec-ctf-writeup-scaffold
description: 四叶草安全-创研中心竞赛专用题目手册构建 Skills，面向题目源码、WP、构建产物与零散人工草稿的标准化整理：自动提取考点、部署信息、完整 Flag、HUB录题字段与题解模板，并生成符合内部规范的 manual_template.md / manual_filled_draft.md 草稿；hub_fields.json 和 xlsx_fields.json 必须保留完整 Flag。
---

# CloverSec-CTF-Writeup-Scaffold

## 任务定位

把题目源码、WP、构建产物和人工草稿整理成内部题目手册与录题字段。默认产物：

- `manual_template.md`
- `manual_filled_draft.md`
- `writeup_context.json`
- `writeup_proposal.md`
- `hub_fields.json`
- `xlsx_fields.json`

本 Skill 只处理文档、字段和格式校验；不负责容器构建、部署运维、漏洞利用链验证，也不把未知解法写成事实。

## 首选入口

本文中的 `scripts/`、`references/`、`docs/`、`data/`、`assets/` 均相对于本 `SKILL.md` 所在目录。使用已安装 Skill 时，不要给这些路径加源码仓库前缀；先解析 Skill 根目录真实位置，再读取或执行对应文件。

输入提示：可直接给题目目录，也可用 `--project-dir <path/to/challenge>` 指向题目目录。

优先执行上下文抽取，先给用户字段提案：

```bash
python3 scripts/extract_context.py \
  --project-dir <题目目录> \
  --pretty \
  --output writeup_context.json \
  --proposal-out writeup_proposal.md
```

用户确认提案或给出修正后，再生成手册和录题字段：

```bash
python3 scripts/render_manual.py --project-dir <题目目录> --output-dir <输出目录>
python3 scripts/validate_manual.py <输出目录>/manual_template.md <输出目录>/manual_filled_draft.md
```

如果用户明确要求直接生成，可以执行 `render_manual.py`，但结果中仍要保留缺失字段和人工确认项。

## 输入路由

| 输入状态 | 推荐处理 | 按需读取 |
|---|---|---|
| 有 `challenge.yaml`、`Dockerfile`、`start.sh`、`changeflag.sh` | 抽取部署方式、端口、动态 Flag、附件结构和平台备注 | `references/integration.md` |
| 有 `writeup.md`、`wp.md`、`README.md` 或人工草稿 | 抽取题名、分类、考点、工具、步骤线索和 Flag | `references/inference-guide.md` |
| 只有源码或附件目录 | 只写可确认的工程事实，解题步骤保留人工填写 | `references/spec.md` |
| 需要对齐内部标准 | 按固定章节、代码块、附件层级和难度规则生成 | `docs/竞赛题目手册标准文档.md` |
| 格式或字段异常 | 先看常见失败，再重新生成或手工修正 | `docs/common-failures.md` |

默认只读取当前目录和用户显式指定路径中的必要文件。不要扫描无关仓库、下载外部资料或读取大文件，除非用户明确要求。

## 输出规则

- `manual_template.md` 保留人工填写空间，尤其是解题步骤。
- `manual_filled_draft.md` 只填写可确认或可保守推断的内容。
- `hub_fields.json` 用于 Hub 录题字段。
- `xlsx_fields.json` 用于内部 xlsx 归档字段。
- `hub_fields.json` 的 `题目Flag` 和 `xlsx_fields.json` 的 `Flag` 必须保留完整 Flag。
- 难度文档展示仍使用“简单 / 中等 / 困难”；Hub 与 xlsx 字段保留 10 级难度编号和星级。
- 分类只能使用 `Web / Pwn / Crypto / Misc / Reverse / Mobile / IoT`。

## 格式要求

- 固定章节为 `1.1` 到 `1.8` 与 `2.1` 到 `2.14`。
- `2.1` 到 `2.11` 必须使用 `plain` 代码块。
- `2.11` 与 `2.12` 之间必须插入 `---`。
- 附件清单与上传清单统一使用 `● / ○` 两级结构。
- `2.13` 和 `2.14` 必须存在且非空。
- 缺少证据的题名、Flag、来源、分值、备注、非预期测试点只能留空或使用占位符。

## 工作流程

1. 收集：读取结构化配置、WP、README、脚本和必要源码片段。
2. 提案：生成字段级 `value / status / confidence / evidence`，列出需要人工确认的字段。
3. 生成：输出模板版、草稿版、Hub 字段和 xlsx 字段。
4. 校验：执行 `validate_manual.py`，根据报错修正文档格式。

默认确认项：

- 题目名称
- 分类 / 题目类型
- Flag 类型和完整 Flag
- 是否把解题步骤保留为人工填写

## 与 Build-Dockerizer 协同

如果题目已经经过 `CloverSec-CTF-Build-Dockerizer` 处理，优先读取当前目录中的：

- `challenge.yaml`
- `Dockerfile`
- `start.sh`
- `changeflag.sh`
- `check/`
- `docker_artifacts.json`
- `docker_artifacts.executed.json`
- `xlsx_fields.json`

上游产物只作为证据来源。写手册时仍要区分“平台交付契约已验证”和“题目已经可解”。

## 按需读取索引

| 需要的信息 | 文件 |
|---|---|
| 手册章节、代码块、附件清单规则 | `references/spec.md` |
| 字段推断边界和证据等级 | `references/inference-guide.md` |
| Build-Dockerizer 产物如何进入手册 | `references/integration.md` |
| 常见校验失败与处理方式 | `docs/common-failures.md` |
| 工作流示例 | `docs/workflow-examples.md` |
| 内部标准原文归档 | `docs/竞赛题目手册标准文档.md` |
| 分类、难度、来源优先级、默认模板值 | `data/categories.yaml`、`data/difficulty_rules.yaml`、`data/source_patterns.yaml`、`data/template_defaults.yaml` |

读取原则：只读当前任务需要的文件，不要一次性加载全部参考资料。

## 停止条件

遇到以下情况时，先输出缺失项和建议的下一步，不要继续编写确定性内容：

- 无法确认完整 Flag，但用户要求归档字段必须填入真实 Flag。
- WP 或源码证据不足，不能确认解题步骤。
- 分类、题型或题名存在冲突证据。
- 用户要求填写 Hub/xlsx 字段，但必要字段来源不明。

## 输出汇报要求

完成任务时必须说明：

- 生成了哪些文件。
- 哪些字段来自证据，哪些字段仍需人工确认。
- 是否保留了完整 Flag。
- 执行了哪些校验命令。
- 哪些检查没执行，以及原因。
