---
name: cloversec-ctf-hub-retag
description: CloverSec CTF Hub 审核后编号回填与镜像 tag skill。用于用户确认审核通过并提供 HUB 编号后，按确认过的命名规则重打镜像 tag、重新导出 amd64 tar，并更新归档字段。
---

# CloverSec CTF Hub Retag

## 任务定位

处理审核通过后的 HUB 编号、镜像 tag 和 tar 重新导出。没有 HUB 编号或 tag 规则时不得继续。

## 输入

- 审核通过状态。
- HUB 编号。
- 已验证镜像。
- tag 命名规则。
- `ctf_case.json`。

## 输出

- 新镜像 tag。
- 新 amd64 镜像 tar。
- `retag_report.md`。
- 更新后的 `docker_artifacts.json` 和 xlsx 字段。

## 工作流程

1. 要求用户确认 HUB 编号和 tag 规则。
2. 检查原镜像存在并能运行。
3. 执行 docker tag。
4. 导出 tar。
5. import 后再次 run。
6. 更新归档和 xlsx 字段。

## 验证

- HUB 编号来源明确。
- 新 tag 符合用户确认规则。
- 新 tar 为 `linux/amd64`。
- import 后可运行。

## 停止条件

审核状态、HUB 编号、tag 规则、镜像来源或导出方式不确定时，停止并给用户选择。

