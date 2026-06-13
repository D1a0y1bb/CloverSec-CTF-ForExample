# CloverSec-CTF-ForExample

面向 Codex 的 CloverSec CTF 工作流插件。第一阶段目标是建立官方格式的 plugin 与 10 个 skill 骨架，覆盖赛题收集、资料整理、构建转换、手册、归档、检查、Hub 提交材料、审核后镜像 tag 和最终报表。

## 目录

```text
.agents/plugins/marketplace.json
plugins/cloversec-ctf-forexample/
  .codex-plugin/plugin.json
  skills/
  assets/
  scripts/
  references/
```

## 当前边界

- Hub 自动化第一版只生成提交材料、字段清单和上传核对表。
- 不保存用户 Hub 凭证、Cookie、token 或浏览器 session。
- 审核后的 HUB 编号和镜像 tag 规则由用户确认或官方文档提供后再自动处理。
- xlsx 归档表必须包含完整 Flag 字段。

## 本地验证

```bash
python3 /Users/d1a0y1bb/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py plugins/cloversec-ctf-forexample
python3 /Users/d1a0y1bb/.codex/skills/.system/skill-creator/scripts/quick_validate.py plugins/cloversec-ctf-forexample/skills/cloversec-ctf-research-intake
```

