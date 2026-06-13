# CloverSec CTF Workflow

## 阶段

1. `cloversec-ctf-research-intake`：收集赛事和赛题信息。
2. `cloversec-ctf-asset-collector`：收集题目源码、附件、WP、复现资料。
3. `cloversec-ctf-build-dockerizer`：容器题目构建转换。
4. `cloversec-ctf-attachment-packager`：附件题目检查和打包。
5. `cloversec-ctf-writeup-scaffold`：手册和 Hub 字段草稿。
6. `cloversec-ctf-archive-packager`：归档目录、镜像 tar、hash 清单。
7. `cloversec-ctf-quality-review`：题目、手册、附件、镜像一致性检查。
8. `cloversec-ctf-hub-submission`：Hub 提交材料生成。
9. `cloversec-ctf-hub-retag`：审核通过后按 HUB 编号重打镜像 tag。
10. `cloversec-ctf-final-report`：最终位置、xlsx 和后续动作报告。

## 全局原则

- 每个阶段产生结构化结果，写入 `ctf_case.json` 或批量 `ctf_cases.jsonl`。
- 不确定字段保留为空，并记录需要用户确认的原因。
- Hub 自动化第一版不提交，只生成材料。
- 涉及镜像导出时必须检查 `linux/amd64`。
- 阶段结束前更新 `TODO.md`。

