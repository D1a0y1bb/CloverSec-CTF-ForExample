# 常见失败场景

## 场景 A：草稿信息太少

通常是输入材料不足，或者没有明确给出题名、题目来源、Flag、分值等关键信息。先看 `writeup_proposal.md` 或 `python3 scripts/render_summary.py --project-dir .` 的缺失字段列表。

## 场景 B：部署方式不准确

通常是因为缺少 `challenge.yaml`、`Dockerfile` 或 `start.sh`，导致系统只能保守输出附件型说明。若存在上游构建产物，请把它们放在当前工作目录或显式传给脚本。

## 场景 C：校验失败

通常与 `plain` 代码块、`---` 分隔符、枚举值或附件层级格式有关。优先复核 `2.1`~`2.11`、`2.13`、`2.14` 及 `● / ○` 层级。

## 场景 D：规则升级后质量漂移

先运行 `python3 scripts/validate_examples.py` 看 golden outputs 是否发生意外漂移，再决定是否更新快照。
