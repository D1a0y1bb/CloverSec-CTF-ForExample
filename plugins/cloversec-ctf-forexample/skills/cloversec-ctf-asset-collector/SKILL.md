---
name: cloversec-ctf-asset-collector
description: CloverSec CTF 题目附件、源码、WP、复现资料收集 skill。用于基于赛题清单整理全网资料、下载状态、hash、来源证据、缺失项和可复现材料，为容器构建、附件题打包和手册撰写提供输入。
---

# CloverSec CTF Asset Collector

## 任务定位

围绕已确定的赛题清单收集题目源码、附件、WP、复现说明、官方公告、仓库链接、网盘或压缩包信息。该 skill 不负责构建镜像，也不负责写手册。

## 输入

- `research_table.xlsx`、`ctf_cases.jsonl` 或单题 `ctf_case.json`。
- 题目链接、仓库链接、附件链接、WP 链接。
- 用户提供的本地附件目录。

## 输出

- `asset_inventory.json`：材料清单。
- `asset_collection_report.md`：收集状态和缺失项。
- `downloads/`：用户许可后保存的附件或源码。

清单字段：`asset_type`、`name`、`source_url`、`local_path`、`sha256`、`size`、`license_or_notice`、`status`、`evidence`。

## 工作流程

1. 读取赛题清单，按题目建立材料目录。
2. 记录每个材料来源和下载状态。
3. 对压缩包计算 SHA256，记录大小和文件名。
4. 对失败下载、失效链接、疑似错题材料标记问题。
5. 输出材料清单给下游 skill 使用。

## 脚本入口

本地材料目录扫描：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py asset-inventory <题目材料目录> asset_inventory.json
```

生成结果包含文件名、相对路径、材料类型、大小、SHA256 和状态。

## 验证

- 本地存在的附件必须能读取并计算 hash。
- 远程材料未下载时，不能写成已收集。
- 题目名称、赛事来源和附件名称不一致时，写入风险项。

## 停止条件

需要账号、验证码、网盘提取码、版权授权或大批量下载许可时，停止并给用户选择。
