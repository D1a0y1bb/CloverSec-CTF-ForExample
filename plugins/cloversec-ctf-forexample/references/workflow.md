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

## 阶段 6 命令顺序

1. 归档资源：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_archive.py package --case-json ctf_case.json --output-root archive --output-case ctf_case.archived.json
```

2. 做质量检查：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_review.py review --case-json ctf_case.archived.json --output-dir quality_review --archive-dir archive/<case_id>-<title> --output-case ctf_case.reviewed.json
```

3. 审核通过并拿到 HUB 编号后生成 retag 计划：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_retag.py plan --case-json ctf_case.reviewed.json --hub-id <HUB编号> --output-dir archive/retagged-images --output retag_plan.json --report retag_report.md --output-case ctf_case.retagged.json
```

4. 汇总最终表：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_final.py generate --cases ctf_cases.jsonl --output-dir final_out
```

`cloversec_ctf_retag.py` 只生成命令计划。真实 Docker tag/save/load/inspect 执行结果需要用户执行或明确授权后写回。
