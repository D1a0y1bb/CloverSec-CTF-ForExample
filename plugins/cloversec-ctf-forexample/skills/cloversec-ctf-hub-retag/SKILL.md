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
- 新 amd64 镜像 tar 路径计划。
- `retag_report.md`。
- 更新后的 `docker_artifacts.json` 和 xlsx 字段。

## 工作流程

1. 要求用户确认 HUB 编号和 tag 规则。
2. 读取 `docker_artifacts.image_name`、`platform`、`tar_path`。
3. 生成 docker tag、save、load、inspect 命令计划。
4. 写入 `retag_plan.json` 和 `retag_report.md`。
5. 用户执行或明确授权后，再把真实执行结果写回。

## 脚本入口

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_retag.py plan \
  --case-json ctf_case.json \
  --hub-id CTF-2026060001 \
  --output-dir archive/retagged-images \
  --registry-prefix registry.example.com/cloversec \
  --tag-template "{hub_id}" \
  --output retag_plan.json \
  --report retag_report.md \
  --output-case ctf_case.retagged.json
```

脚本只生成命令计划，不自动运行 Docker。

## 验证

- HUB 编号来源明确。
- 新 tag 符合用户确认规则。
- 原始 `docker_artifacts.platform` 必须为 `linux/amd64`。
- Docker 命令执行、导出 tar、import 后运行属于真实执行检查；没有执行记录时不得写成通过。

## 停止条件

审核状态、HUB 编号、tag 规则、镜像来源或导出方式不确定时，停止并给用户选择。
