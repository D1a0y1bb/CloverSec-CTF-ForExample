---
name: cloversec-ctf-attachment-packager
description: CloverSec CTF 非容器附件题处理 skill。用于检查离线附件题的压缩包、题目资源、解压可用性、hash、目录清单和题目匹配关系，生成可归档附件包和 xlsx 字段。
---

# CloverSec CTF Attachment Packager

## 任务定位

处理附件型题目。确认压缩包能解压、资源与题目匹配、文件清单清楚、hash 可复算。该 skill 不处理环境型镜像构建。

## 输入

- 本地附件包或下载目录。
- `asset_inventory.json`。
- `ctf_case.json`。
- 可选 WP 或题面。

## 输出

- `attachment_manifest.json`。
- 标准附件包。
- `xlsx_fields.json`。

## 工作流程

1. 识别附件包格式和文件数量。
2. 解压到临时目录检查结构。
3. 记录文件清单、大小、SHA256。
4. 检查题名、赛事、分类和附件内容是否明显不匹配。
5. 重新打包为标准附件包。

## 验证

- 原始附件可读取。
- 压缩包可解压。
- 重新打包后可再次解压。
- manifest 中的 hash 能复算。

## 停止条件

附件损坏、密码未知、疑似错题、包含恶意样本且缺少隔离要求时，停止并给用户选择。

