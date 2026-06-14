---
name: cloversec-ctf-hub-submission
description: 生成 CloverSec CTF Hub 提交包、字段 payload、浏览器/Chrome 辅助填表计划、上传结果回写和提交前检查；不保存凭证，不点击最终提交。
---

# CloverSec CTF Hub Submission

## 何时使用

- 已有 `ctf_case.json`、手册草稿、Hub 字段和资源文件，需要生成 Hub 提交材料。
- 需要把题目分类文本匹配成 Hub 分类 ID。
- 需要用浏览器或 Chrome 插件辅助填写 Hub 表单、上传附件和截图。
- 用户已经在 Chrome 登录 Hub，需要记录登录确认、字段填写、上传、提交前截图和人工提交状态。
- 需要在最终提交前检查字段、附件、截图、上传结果和 Flag。

## 必须遵守

- 完整 Flag 必须保留在 `hub_fields.json` 和后续 xlsx 字段中。
- 不读取或保存密码、验证码、Cookie、token、CSRF、localStorage、sessionStorage。
- 不保存浏览器 session 文件。
- 只有确认用户当前 Chrome 已登录 Hub 后，才允许打开新增题目页并填写字段；页面仍显示“登录/注册”、SSO、403 或未登录状态时必须停止，不填写。
- 不自动点击最终提交按钮；Chrome 辅助流程必须停在提交前检查。
- 上传未知文件、分类 ID、字段差异和最终提交都需要用户确认。
- Chrome 文件上传如果返回 `Not allowed`，提示用户在 `chrome://extensions` 给 Codex 扩展开启 `Allow access to file URLs`，不要改用 Cookie/session 方案绕过。

## 常用命令

生成提交材料：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py package --case-json ctf_case.json --hub-fields writeup_out/hub_fields.json --manual writeup_out/manual_filled_draft.md --output-dir hub_submission_package
```

生成 Chrome 辅助计划：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py chrome-plan \
  --manifest hub_submission_package/manifests/upload_manifest.json \
  --output hub_submission_package/chrome_assist_plan.json \
  --report hub_submission_package/chrome_assist_plan.md
```

提交前检查：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py validate-manifest \
  --manifest hub_submission_package/manifests/upload_manifest.json \
  --classify-options hub_classify_options.json \
  --output hub_submission_package/manifests/pre_submit_validation.json
```

页面上传完成后回写结果：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py apply-upload-results \
  --manifest hub_submission_package/manifests/upload_manifest.json \
  --upload-results hub_upload_results.json \
  --output hub_submission_package/manifests/upload_manifest.with_uploads.json
```

记录 Hub 浏览器接管状态：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py session-state \
  --output-dir hub_submission_package \
  --draft hub_submission_package/hub_draft.json \
  --manifest hub_submission_package/hub_upload_manifest.json \
  --login-confirmed \
  --field-fill-status filled \
  --pre-submit-screenshot hub_submission_package/pre_submit.png
```

## MCP

优先使用 `cloversec-ctf-hub-assistant`：

- `cloversec_ctf_hub_chrome_plan`
- `cloversec_ctf_hub_browser_plan`
- `cloversec_ctf_hub_validate_manifest`
- `cloversec_ctf_hub_apply_upload_results`
- `cloversec_ctf_hub_session_state`

## 需要更多细节时再读取

读取 `plugins/cloversec-ctf-forexample/references/hub-submission.md`，里面有页面字段、接口观察、目录结构、Chrome 执行约束和停止条件。
