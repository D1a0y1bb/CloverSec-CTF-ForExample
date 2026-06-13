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

## 脚本入口

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_review.py review \
  --case-json ctf_case.json \
  --output-dir quality_review \
  --archive-dir archive/case-001-title \
  --output-case ctf_case.reviewed.json
```

脚本读取已有验证记录和本地文件状态。没有真实 Docker run、import、按手册解题记录时，状态写为 `skip`，不会写成通过。

## 检查项

- 题目名称、分类、来源、Flag、附件和手册是否一致。
- 容器镜像 tar 是否存在、平台是否为 `linux/amd64`。
- Docker run 是否已有真实验证记录。
- 附件是否能解压。
- 手册步骤是否已有解出 Flag 的验证记录。
- `Flag` 是否写入 xlsx 字段。
- 缺失资源是否列明。

## 验证

- 能执行的检查必须执行。
- 当前脚本不会执行未知 Docker 命令，只读取 `docker_artifacts.run_verified` 等明确结果。
- 不能执行的检查写清原因，状态保持 `skip`。
- 失败项不得改写成警告。
- 有失败项时 `验证状态=失败`；只有未执行项时 `验证状态=部分通过`；全部通过时 `验证状态=通过`。

## 停止条件

检查会执行潜在危险样本、需要联网访问未知服务、需要用户凭证或会修改外部系统时，停止并给用户选择。
