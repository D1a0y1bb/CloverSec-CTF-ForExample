# Workflow 示例

## 示例 1：先提案、后生成

1. 运行 `python3 scripts/render_summary.py --project-dir . --compare-render`。
2. 先确认题目名称、分类、Flag 类型、是否保留“解题步骤”为人工补写。
3. 运行 `python3 src/CloverSec-CTF-Writeup-Scaffold/scripts/render_manual.py --project-dir . --output-dir .`。
4. 再执行 `python3 src/CloverSec-CTF-Writeup-Scaffold/scripts/validate_manual.py manual_template.md manual_filled_draft.md`。

## 示例 2：先构建后写手册

1. 用 `CloverSec-CTF-Build-Dockerizer` 生成题目环境。
2. 把 `challenge.yaml`、`Dockerfile`、`start.sh`、`check/` 留在工作目录。
3. 用本技能生成 `manual_template.md` 与 `manual_filled_draft.md`。
4. 人工补写解题步骤、截图与非预期测试。

## 示例 3：规则迭代后做回归

1. 修改 `data/` 或 `scripts/` 中的规则。
2. 运行 `python3 scripts/validate_examples.py`。
3. 若变更确属预期，再执行 `python3 scripts/validate_examples.py --update` 更新 golden outputs。
