# CloverSec-CTF-ForExample

面向 Codex 的 CloverSec CTF 工作流插件。第一阶段目标是建立官方格式的 plugin 与 10 个 skill 骨架，覆盖赛题收集、资料整理、构建转换、手册、归档、检查、Hub 提交材料、审核后镜像 tag 和最终报表。

## 安装

这个仓库本身就是 Codex repo marketplace。给朋友或内部同事使用时，让对方在 Codex 的“添加插件市场”里填写：

```text
来源：D1a0y1bb/CloverSec-CTF-ForExample
Git 引用：v0.1.1
稀疏路径：留空
```

`Git 引用` 推荐填最新 Release tag，例如 `v0.1.1`。如果要跟随开发版，可以填 `main`。

如果界面支持多个稀疏路径，也可以只拉取插件相关目录：

```text
.agents/plugins
plugins
```

CLI 安装：

```bash
codex plugin marketplace add D1a0y1bb/CloverSec-CTF-ForExample --ref v0.1.1
codex plugin list
codex plugin add cloversec-ctf-forexample@cloversec-ctf
```

使用开发版：

```bash
codex plugin marketplace add D1a0y1bb/CloverSec-CTF-ForExample --ref main
codex plugin add cloversec-ctf-forexample@cloversec-ctf
```

更新已添加的 marketplace：

```bash
codex plugin marketplace upgrade cloversec-ctf
codex plugin add cloversec-ctf-forexample@cloversec-ctf
```

Codex 会把插件安装到本机缓存。安装或更新后，建议新开一个 Codex 会话再测试新 skill 和 MCP 工具。

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
python3 -m unittest tests.test_data_model
python3 scripts/validate_release.py
```

## 数据模型脚本

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py validate-json ctf_case.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py export-xlsx ctf_cases.jsonl archive.xlsx
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py import-xlsx archive.xlsx
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_data.py summary ctf_cases.jsonl
```

脚本只使用 Python 标准库。`export-xlsx` 会把完整 `Flag` 写入 xlsx 的 `Flag` 列。
