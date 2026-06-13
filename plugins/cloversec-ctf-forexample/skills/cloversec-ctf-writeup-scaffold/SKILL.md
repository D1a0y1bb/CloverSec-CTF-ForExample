---
name: cloversec-ctf-writeup-scaffold
description: CloverSec CTF 手册撰写和 HUB 字段草稿 skill。用于根据题目材料、解题步骤、构建结果和内部模板生成标准手册、HUB 表单字段、10 级难度和星级、xlsx 行草稿，并检查解题步骤完整度。
---

# CloverSec CTF Writeup Scaffold

## 任务定位

生成题目解题手册和 Hub 填报字段。当前插件版本保留对既有 `CloverSec-CTF-Writeup-Scaffold` 正式仓库的集成位置；本 skill 强调 Hub 字段和归档表字段。

## 输入

- `ctf_case.json`。
- `metadata.json`、`solve_verification.json`、`docker_artifacts.json`、`attachment_manifest.json`。
- 用户提供的手册草稿、WP、截图。

## 输出

- `manual_template.md`。
- `manual_filled_draft.md`。
- `hub_fields.json`。
- `xlsx_fields.json`。

## 脚本入口

使用插件脚本生成手册草稿和字段草稿：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_writeup.py render ctf_case.json --output-dir writeup_out
```

输出目录包含：

- `writeup_out/hub_fields.json`
- `writeup_out/xlsx_fields.json`
- `writeup_out/manual_template.md`
- `writeup_out/manual_filled_draft.md`

`hub_fields.json` 的 `题目Flag` 和 `xlsx_fields.json` 的 `Flag` 必须保存完整 Flag。

## 必填内容

- 题目名称。
- 题目难度，保留 10 级难度编号和星级。
- 题目分值。
- 前置知识。
- 考察知识点。
- 解题工具。
- 解题步骤。
- Flag。
- 附件清单。
- Hub 表单字段。

## 验证

- 手册章节符合内部模板。
- 解题步骤包含题目信息、工具、关键命令或代码、截图需求、Flag 证明。
- HUB 字段和 xlsx 字段一致。
- 不确定的利用链、题名、来源、分值不得编造。
- 10 级难度必须转换为 `题目等级`、`题目难度`、`题目难度等级`。

## 停止条件

缺少 WP、无法复现 flag、题目难度无法判断、Hub 字段含义不明确时，停止并给用户选择。
