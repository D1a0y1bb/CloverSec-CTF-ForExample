---
name: cloversec-ctf-final-report
description: CloverSec CTF 最终报告和 xlsx 归档输出 skill。用于在全流程结束后汇总题目位置、手册、附件、镜像 tar、HUB 编号、审核状态、完整 Flag、语雀粘贴表和后续处理事项；内部 xlsx 和语雀归档输出必须保留完整 Flag。
---

# CloverSec CTF Final Report

## 任务定位

生成最终交付报告、归档 xlsx 和给人接手看的中文交付目录。该 skill 是流程末端，必须基于已存在的归档材料和检查结果，不重新收集或重构题目。

## 输入

- `ctf_cases.jsonl`。
- 归档目录。
- 质量检查报告。
- Hub 提交或审核状态。

## 输出

- `最终归档表.xlsx`。
- `语雀粘贴表.md`。
- `交付说明.md`。
- `待处理问题.md`。
- `质量检查报告.md`。
- 每题 `分类-题目名/` 目录。
- `最终报告.md` 仍可作为脚本输出或内部检查资料，但不进入人看的最终交付根目录。
- `最终报告.json`。
- 后续事项列表。
- 面向人接手查看的中文交付目录。

给人看的最终交付名称只使用中文。英文 JSON、过程数据和脚本内部报告只能放在脚本输出目录或 `_cache/`，不进入人看的交付目录。

Agent 被问到最终交付文件时，必须优先列出这些中文入口：

- `交付说明.md`
- `最终归档表.xlsx`
- `语雀粘贴表.md`
- `待处理问题.md`
- `质量检查报告.md`
- `Web-题目名/题目源码/`
- `Web-题目名/题目镜像/`
- `Web-题目名/题目手册/题目解题手册.md`
- 附件题使用 `Misc-题目名/题目附件/` 和 `Misc-题目名/题目手册/`

## xlsx 要求

归档 xlsx 必须包含完整 `Flag` 字段。字段缺失时，不能用空泛描述代替，必须在后续事项中列明。

如果输出机器可读 JSON，布尔字段只能写 `true` 或 `false`，不要写中文“是/否”。内部 xlsx 的 `Flag` 必须是完整值；如果题目还没有 Flag，状态必须写未通过或待补充，不能因为缺 Flag 把 `full_flag_in_xlsx` 设为 `false` 后继续标 ready。

`赛事来源`、`题目来源`、`开放端口`、`离线/在线解题`、`解题工具`、`Flag`、`归档目录`、`资源路径` 缺失时，不能把 `是否通过` 写成 `是`，也不能把 `是否归档` 写成 `是`。如果旧字段已经写成 `是`，生成最终表时要按真实缺项改回 `否` 或 `部分通过`，并写入 `问题`。

## 脚本入口

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_final.py generate \
  --cases ctf_cases.jsonl \
  --output-dir final_out \
  --base-dir .
```

如果 `ctf_cases.jsonl` 里的归档目录或资源路径是 `work/...` 这类相对路径，`--base-dir` 必须指向线程或项目根目录，避免把真实存在的文件误判成缺失。

输出：

- `final_out/最终归档表.xlsx`
- `final_out/语雀粘贴表.md`
- `final_out/最终报告.md`
- `final_out/最终报告.json`

生成中文交付目录：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_delivery.py \
  --workdir work/ctf-2026-collection \
  --outputs-dir outputs \
  --output-dir outputs
```

最终回复前必须让 `cloversec_ctf_delivery.py` 生成或扫描交付目录。扫描还有问题时，只能报告“交付目录待整理”，不能把 `archive/`、`_cache/`、`reports/`、`manifests/` 或手写目录当最终结果。`容器交付件/`、`镜像包/`、`录题字段/`、`原始资料/`、`验证记录/` 这类目录只能作为整理器输入，不能出现在人看的最终交付根目录。

默认目录：

```text
交付说明.md
最终归档表.xlsx
语雀粘贴表.md
待处理问题.md
质量检查报告.md
Web-EZSmuggler/
  题目源码/
  题目镜像/
  题目手册/
Misc-Example/
  题目附件/
  题目手册/
```

镜像 tar 默认复制到 `题目镜像/`，包括大于通用复制限制的正式镜像包；只有用户明确要求不复制镜像 tar 时，才使用 `--no-copy-image-tars`。

## 报告内容

- 每道题归档位置。
- 手册路径。
- 附件路径。
- 镜像 tar 路径。
- HUB 编号和审核状态。
- 未完成检查。
- 需要用户处理的上传或审核事项。
- 验证状态为 `失败`、`未验证`、`部分通过` 的题目必须进入后续事项。

## 验证

- xlsx 可以打开。
- 关键字段存在。
- 文件路径真实存在。
- 检查未执行时写明原因。
- `语雀粘贴表.md` 按内部字段输出，含完整 `Flag`，不要贴到公开渠道。
- 最终交付给人看的目录只允许中文总表、语雀表、交付说明、待处理问题、质量检查报告和每题目录；英文 `work/` 目录、英文 JSON 和兼容副本只作为脚本输入或过程资料。

## 停止条件

缺少归档目录、Flag、审核状态、HUB 编号来源或 xlsx 字段规则不明确时，停止并给用户选择。
