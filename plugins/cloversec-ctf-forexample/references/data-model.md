# CloverSec CTF Data Model

## 中间 JSON

每道题使用 `ctf_case.json` 保存完整流程状态。

```json
{
  "case_id": "",
  "source_files": [],
  "research": {},
  "asset_collection": {},
  "metadata": {},
  "flag": {
    "value": "",
    "type": "static|dynamic|unknown",
    "sensitive": true
  },
  "environment": {},
  "docker_artifacts": {},
  "attachments": [],
  "writeup": {},
  "hub_fields": {},
  "review": {},
  "archive": {},
  "evidence": [],
  "confidence": "high|medium|low"
}
```

## xlsx 字段

输出 xlsx 必须保留内部归档需要的人可读字段：

- `HUB编号`
- `赛事来源`
- `题目来源`
- `名称`
- `分类`
- `题目类型`
- `Flag类型`
- `Flag`
- `难度编号`
- `星级`
- `分值`
- `资源等级`
- `提交时间`
- `开放端口`
- `离线/在线解题`
- `解题工具`
- `提交用户名`
- `审核人`
- `是否通过`
- `问题`
- `是否归档`
- `材料状态`
- `构建状态`
- `手册状态`
- `验证状态`
- `归档目录`
- `环境包/附件包路径`
- `备注`

`Flag` 是 xlsx 必填字段。脚本在日志、错误输出、公开报告中避免打印完整 Flag。

## 脚本入口

统一数据模型脚本：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py validate-json ctf_case.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py export-xlsx ctf_cases.jsonl archive.xlsx
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py import-xlsx archive.xlsx
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py summary ctf_cases.jsonl
```

脚本只使用 Python 标准库，方便随 plugin 分发。

收集与资料整理脚本：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py migrate-xlsx 竞赛题目收集.xlsx ctf_cases.jsonl
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py asset-inventory challenge-dir asset_inventory.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py research-report ctf_cases.jsonl research_report.md
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py validate-collection ctf_cases.jsonl
```

## 证据字段

`evidence[]` 用于记录公开来源、用户提供来源和本地材料证据：

- `source_url`：公开网页、仓库、公告、WP 链接。没有 URL 时可留空，但必须提供 `local_path`。
- `local_path`：本地材料路径。
- `source_type`：`public_web`、`user_provided`、`local_file`、`github`、`ctftime`、`writeup`、`unknown`。
- `title`：来源标题。
- `accessed_at`：访问日期，建议 `YYYY-MM-DD`。
- `summary`：证据摘要。
- `confidence`：`high`、`medium`、`low`。
- `status`：`found`、`missing`、`inaccessible`、`unverified`。

收集阶段不强制要求完整 `Flag`，但进入最终 xlsx 前必须存在完整 `Flag`。

旧表迁移会读取多个业务工作表，并跳过名称包含“标准”或“说明”的工作表。

容器和附件阶段脚本：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_build.py plan --project-dir challenge-dir --image-name cloversec/example:local --tar-path archive/example.tar --port 18080:80 --output docker_plan.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_package.py inspect challenge.zip --output attachment_manifest.json
```

`docker_artifacts.platform` 必须为 `linux/amd64`。附件 manifest 必须记录 `sha256`、目录项和风险状态。

手册和 Hub 提交阶段脚本：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_writeup.py render ctf_case.json --output-dir writeup_out
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_hub.py package --case-json ctf_case.json --hub-fields writeup_out/hub_fields.json --manual writeup_out/manual_filled_draft.md --output-dir hub_submission_package
```

`hub_fields.json` 字段：

- `题目标题`
- `题目内容`
- `Flag类型`
- `题目Flag`
- `题目来源`
- `题目分类`
- `题目分值`
- `题目等级`
- `题目难度`
- `题目难度等级`
- `题目类型`
- `资源等级`
- `题目备注`
- `添加关键字`

`题目Flag` 保存完整 Flag。导出的 `xlsx_fields.json` 也保存完整 `Flag`。

Hub 提交材料目录：

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

- `01-challenge-page.png`
- `02-container-running.png`
- `03-solve-proof.png`

## 状态值

- `材料状态`：`未开始`、`收集中`、`已收集`、`缺材料`、`无法确认`
- `构建状态`：`不适用`、`未开始`、`已构建`、`验证失败`
- `手册状态`：`未开始`、`草稿`、`待人工完善`、`已校验`
- `验证状态`：`未验证`、`部分通过`、`通过`、`失败`
- `是否归档`：`是`、`否`
- `是否通过`：`是`、`否`
