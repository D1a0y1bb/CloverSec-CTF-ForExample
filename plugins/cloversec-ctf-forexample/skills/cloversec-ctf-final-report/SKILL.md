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

- `最终报告.md`。
- `最终归档表.xlsx`。
- `语雀粘贴表.md`。
- `最终报告.json`。
- 后续事项列表。
- 面向人接手查看的中文交付目录。

脚本会同时保留 `final_report.md`、`archive.xlsx`、`yuque_table.md`、`final_report.json` 作为兼容副本。给人看的最终交付名称只使用中文。
英文 JSON、英文兼容文件和过程数据只能放在 `过程证据/机器数据/` 或脚本输出目录里，不作为人看的主入口。

Agent 被问到最终交付文件时，必须优先列出这些中文入口：

- `交付说明.md`
- `最终表格/最终归档表.xlsx`
- `语雀归档表/语雀粘贴表.md`
- `手册/题目解题手册.md`
- `待处理问题/缺失项报告.md` 或 `待处理问题.md`
- `质量检查报告/最终报告.md`

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

兼容副本：

- `final_out/archive.xlsx`
- `final_out/yuque_table.md`
- `final_out/final_report.md`
- `final_out/final_report.json`

生成中文交付目录：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_delivery.py \
  --workdir work/ctf-2026-collection \
  --outputs-dir outputs \
  --output-dir outputs/交付包-ctf-2026-collection
```

默认目录：

```text
交付说明.md
交付清单.json
最终表格/
语雀归档表/
题目归档包/
镜像包清单/
质量检查报告/
Hub提交材料/
过程证据/
过程证据/机器数据/
待处理问题/
```

镜像 tar 默认只引用原路径并写入 `镜像包清单/镜像包清单.md`。只有用户明确要求复制镜像 tar 时，才使用 `--copy-image-tars`。

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
- 最终交付给人看的目录使用中文分区和中文文件名；英文 `work/` 目录和英文副本只作为过程证据、脚本输入和兼容文件。

## 停止条件

缺少归档目录、Flag、审核状态、HUB 编号来源或 xlsx 字段规则不明确时，停止并给用户选择。
