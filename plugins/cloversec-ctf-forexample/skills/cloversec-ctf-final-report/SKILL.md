---
name: cloversec-ctf-final-report
description: CloverSec CTF 最终报告和 xlsx 归档输出 skill。用于在全流程结束后汇总题目位置、手册、附件、镜像 tar、HUB 编号、审核状态、完整 Flag、语雀粘贴表和后续处理事项；内部 xlsx 和语雀归档输出必须保留完整 Flag。
---

# CloverSec CTF Final Report

## 任务定位

生成最终交付报告和归档 xlsx。该 skill 是流程末端，必须基于已存在的归档材料和检查结果，不重新收集或重构题目。

## 输入

- `ctf_cases.jsonl`。
- 归档目录。
- 质量检查报告。
- Hub 提交或审核状态。

## 输出

- `final_report.md`。
- `archive.xlsx`。
- `yuque_table.md`。
- `final_report.json`。
- 后续事项列表。

## xlsx 要求

归档 xlsx 必须包含完整 `Flag` 字段。字段缺失时，不能用空泛描述代替，必须在后续事项中列明。

## 脚本入口

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_final.py generate \
  --cases ctf_cases.jsonl \
  --output-dir final_out
```

输出：

- `final_out/archive.xlsx`
- `final_out/yuque_table.md`
- `final_out/final_report.md`
- `final_out/final_report.json`

## 报告内容

- 每道题归档位置。
- 手册路径。
- 附件路径。
- 镜像 tar 路径。
- HUB 编号和审核状态。
- 未完成检查。
- 需要用户处理的上传或审核事项。

## 验证

- xlsx 可以打开。
- 关键字段存在。
- 文件路径真实存在。
- 检查未执行时写明原因。
- `yuque_table.md` 按内部字段输出，含完整 `Flag`，不要贴到公开渠道。

## 停止条件

缺少归档目录、Flag、审核状态、HUB 编号来源或 xlsx 字段规则不明确时，停止并给用户选择。
