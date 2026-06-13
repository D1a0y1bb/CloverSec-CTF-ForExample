---
name: cloversec-ctf-quality-review
description: CloverSec CTF 题目、手册、附件、镜像质量检查 skill。用于检查题目是否对得上、镜像是否能启动、附件是否存在、手册能否支撑解出 Flag、归档字段是否完整。
---

# CloverSec CTF Quality Review

## 任务定位

在提交或归档前做质量检查。该 skill 只报告事实和风险，不把未执行的验证写成通过。

## 输入

- 题目归档目录。
- `ctf_case.json`。
- 手册、附件、镜像 tar、构建材料。

## 输出

- `quality_review_report.md`。
- `quality_review.json`。
- xlsx 状态字段建议。

## 检查项

- 题目名称、分类、来源、Flag、附件和手册是否一致。
- 容器镜像能否 import、run。
- 端口是否可访问。
- 附件是否能解压。
- 手册步骤是否能获得 Flag。
- `Flag` 是否写入 xlsx 字段。
- 缺失资源是否列明。

## 验证

- 能执行的检查必须执行。
- 不能执行的检查写清原因。
- 失败项不得改写成警告。

## 停止条件

检查会执行潜在危险样本、需要联网访问未知服务、需要用户凭证或会修改外部系统时，停止并给用户选择。

