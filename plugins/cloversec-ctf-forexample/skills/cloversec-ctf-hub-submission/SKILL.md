---
name: cloversec-ctf-hub-submission
description: CloverSec CTF Hub 提交材料生成 skill。用于根据手册、附件、镜像和 xlsx 字段生成 Hub 表单字段、上传核对清单和提交包。第一版只准备材料，不自动登录、不保存凭证、不自动点击提交。
---

# CloverSec CTF Hub Submission

## 任务定位

生成 Hub 提交所需材料。Hub 地址为用户提供的内部平台；没有官方 API 文档时，不设计无人值守提交。

## 输入

- `ctf_case.json`。
- `manual_filled_draft.md`。
- `hub_fields.json`。
- 附件包、镜像 tar、截图。

## 输出

- `hub_submission_package/`。
- `hub_submission_checklist.md`。
- `hub_fields_preview.json`。

## 脚本入口

使用插件脚本生成 Hub 提交材料包：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py package --case-json ctf_case.json --hub-fields writeup_out/hub_fields.json --manual writeup_out/manual_filled_draft.md --output-dir hub_submission_package
```

目录结构：

```text
hub_submission_package/
├── fields/
│   ├── hub_fields.json
│   └── hub_fields_preview.json
├── manual/
│   └── manual_filled_draft.md
├── attachments/
├── images/
├── screenshots/
├── manifests/
│   └── upload_manifest.json
└── hub_submission_checklist.md
```

默认截图命名：

- `01-challenge-page.png`：题目页面或题目信息截图。
- `02-container-running.png`：容器运行或服务访问截图。
- `03-solve-proof.png`：解题验证截图。

## 工作流程

1. 检查 Hub 必填字段。
2. 生成表单字段预览。
3. 整理上传文件和截图。
4. 生成上传顺序和核对清单。
5. 标记需要用户手动确认的字段。

## 安全边界

- 不读取或保存密码、验证码、Cookie、token、CSRF、localStorage、sessionStorage。
- 不保存浏览器 session 文件。
- 不自动提交表单。
- 浏览器辅助填表属于后续阶段，且需要用户确认。
- `hub_fields.json` 的 `题目Flag` 保留完整 Flag。

## 验证

- 上传清单中的文件必须存在。
- 文件名、大小、hash 必须记录。
- Hub 字段和手册内容一致。

## 停止条件

Hub 字段含义、附件限制、截图要求、账号权限或提交方式不明确时，停止并给用户选择。
