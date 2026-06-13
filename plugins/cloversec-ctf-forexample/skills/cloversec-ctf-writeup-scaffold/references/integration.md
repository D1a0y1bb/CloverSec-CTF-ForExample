# 与 CloverSec-CTF-Build-Dockerizer 的联动

`CloverSec-CTF-Writeup-Scaffold` 默认与 `CloverSec-CTF-Build-Dockerizer` 协同，但不对上游构建产物形成硬依赖。

## 推荐联动链路

`收集/构建 -> 推断/规整 -> 草稿生成 -> 格式校验 -> 人工补写 -> 入库`

## 优先吸收的上游产物

- `challenge.yaml`
- `Dockerfile`
- `start.sh`
- `changeflag.sh`
- `check/` 或 `check.sh`

## 优先吸收的信息

- 题目名称候选
- 运行栈与端口
- 启动入口与部署方式
- `/flag` 路径与权限说明
- 动态 flag 入口线索
- 平台备注候选
- 附件结构与上传建议

## 推荐叙事方式

在 README、SKILL 或用户交互中，默认写成：

- 推荐先用 `CloverSec-CTF-Build-Dockerizer` 生成并校验交付件
- 再用 `CloverSec-CTF-Writeup-Scaffold` 把构建信息整理成标准手册
- 如果没有上游构建结果，也可以直接从源码、WP 或零散草稿进入文档流程

## 不要做的事

- 不要把两个 Skill 强行合并
- 不要要求只有 `challenge.yaml` 才能生成文档
- 不要把文档 Skill 写成部署器或渲染器的替代品

## 后续可在构建 Skill 中加入的轻量提示

当构建 Skill 完成 `render + validate` 后，可追加一句建议：

```text
下一步可使用 CloverSec-CTF-Writeup-Scaffold 生成标准题目手册与 HUB 录题草稿。
```

