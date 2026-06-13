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

## 状态值

- `材料状态`：`未开始`、`收集中`、`已收集`、`缺材料`、`无法确认`
- `构建状态`：`不适用`、`未开始`、`已构建`、`验证失败`
- `手册状态`：`未开始`、`草稿`、`待人工完善`、`已校验`
- `验证状态`：`未验证`、`部分通过`、`通过`、`失败`
- `是否归档`：`是`、`否`
- `是否通过`：`是`、`否`

