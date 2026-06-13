# CloverSec CTF Hub Submission Reference

## 任务边界

生成 Hub 提交材料、浏览器辅助填表计划、Chrome 辅助执行约束、上传结果回写和提交前检查。没有官方 API 文档时，不做无人值守提交。

安全要求：

- 不读取或保存密码、验证码、Cookie、token、CSRF、localStorage、sessionStorage。
- 不保存浏览器 session 文件。
- 必须先确认当前 Chrome 已登录 Hub，再打开新增题目页并填写字段。未登录状态下即使新增页表单可见，也不能填写，因为点击提交会跳转登录并丢失已填内容。
- 不自动点击最终提交按钮。
- 上传未知文件、页面分类和最终提交都必须有人确认。
- `hub_fields.json` 的 `题目Flag` 保留完整 Flag。

## 已验证页面信息

- Hub CTF 列表：`https://hub.yunyansec.com/#/resource/ctf`
- 新增题目路由：`https://hub.yunyansec.com/#/activity/submitctf/0/0/0`
- 未登录状态：CTF list API 返回 403 并跳转 SSO。
- 分类接口：`GET /ctf/classify/?type=1`
- 提交接口：`POST /ctf/add/`
- 文件上传：`POST /ctf/upload_file/`
- 图片上传：`POST /ctf/upload_image/`
- 附件限制：ZIP/RAR，500M 以内。

## 输入输出

输入：

- `ctf_case.json`
- `manual_filled_draft.md`
- `hub_fields.json`
- 附件包、镜像 tar、截图
- 可选：Hub 分类接口返回 JSON

输出：

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

默认截图：

- `01-challenge-page.png`：题目页面或题目信息截图。
- `02-container-running.png`：容器运行或服务访问截图。
- `03-solve-proof.png`：解题验证截图。

## 表单字段

- `题目标题` -> `name`
- `题目内容` -> `desc`
- `Flag类型` -> `flag_type`，静态为 `1`，动态为 `2`
- `题目Flag` -> `flag`
- `题目来源` -> `source`
- `题目分类` -> `classify`，需要匹配成分类 ID
- `题目分值` -> `score`
- `题目等级` -> `level`
- `题目类型` -> `test_type`，环境型为 `1`，附件型为 `2`
- `资源等级` -> `resource_level`
- `题目备注` -> `remark`
- `题目解答` -> `answer`
- `添加关键字` -> `keyword`
- `上传附件` -> `attached` / `attached_name`
- `其他附件` -> `other_attached` / `other_attached_name`

## 脚本

生成材料包：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py package --case-json ctf_case.json --hub-fields writeup_out/hub_fields.json --manual writeup_out/manual_filled_draft.md --output-dir hub_submission_package
```

生成普通浏览器辅助计划：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py browser-plan \
  --manifest hub_submission_package/manifests/upload_manifest.json \
  --output hub_submission_package/browser_assist_plan.json
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

上传结果回写：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py apply-upload-results \
  --manifest hub_submission_package/manifests/upload_manifest.json \
  --upload-results hub_upload_results.json \
  --output hub_submission_package/manifests/upload_manifest.with_uploads.json
```

## MCP 工具

`cloversec-ctf-hub-assistant` 暴露：

- `cloversec_ctf_hub_browser_plan`
- `cloversec_ctf_hub_chrome_plan`
- `cloversec_ctf_hub_validate_manifest`
- `cloversec_ctf_hub_apply_upload_results`

Chrome 执行约束：

- 允许打开页面、等待用户登录、填写可见字段、选择可见分类、设置页面文件控件、记录可见上传结果、生成提交前截图。
- 禁止读取 Cookie、token、CSRF、localStorage、sessionStorage、密码或验证码。
- 禁止点击最终提交。
- 登录态门槛：先打开资源列表或用户已有登录页面，确认没有“登录/注册”、SSO 或 403，再进入 `#/activity/submitctf/0/0/0`；未登录时停止等待用户处理。
- Chrome 文件上传依赖 Codex 扩展文件访问权限；如果 `setFiles` 返回 `Not allowed`，需要用户在 `chrome://extensions` 中给 Codex 扩展开启 `Allow access to file URLs`。

## 验证

- 上传清单中的文件必须存在。
- 文件名、大小、hash 必须记录。
- `classify` 需要有页面分类 ID。
- 已上传附件需要记录 URL、文件 ID、状态或错误。
- 必填字段、关键字、题目解答和截图槽位缺失时，validation 必须写入 `needs_input`。
- Hub 字段和手册内容一致。

## 停止条件

- Hub 字段含义、附件限制、截图要求、账号权限或提交方式不明确。
- 页面出现登录、验证码、风控或权限异常。
- 分类 ID 不能从页面可见选项确认。
- 上传结果不可见或文件状态不明确。
- 到达最终提交按钮前。
