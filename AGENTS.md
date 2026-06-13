# AGENTS.md

## 硬约束

- 外部 API、CLI、模型名、端点、语法不确定时，先查官方文档或停下确认。
- 测试失败、未验证、无法验证都要明说。
- 发现流程前提不成立时，直接指出。
- 报完成前必须执行能执行的验证。
- 操作文件前确认当前目录，尊重现有结构和 Git 状态。

## 沟通

- 使用中文，表达直接。
- 需要用户决定时给选项。
- 汇报功能层面的变化，不堆实现细节。

## 本仓库约束

- 本仓库用于开发 `CloverSec-CTF-ForExample` Codex plugin。
- 插件源码放在 `plugins/cloversec-ctf-forexample/`。
- repo marketplace 放在 `.agents/plugins/marketplace.json`。
- 每个流程能力必须 skill 化，skill 名使用 `cloversec-ctf-*`。
- Hub 自动化第一版只生成提交材料和核对清单，不做自动提交。
- xlsx 输出必须包含完整 `Flag` 字段，这是内部归档要求。
- 不得自造 Hub API、镜像 tag 规则、审核编号来源。

