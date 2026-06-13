# 后续开发计划

## 阶段 1：插件与 skill 骨架

- [x] 初始化 Git 仓库。
- [x] 使用官方 `plugin-creator` 创建 plugin manifest 和 repo marketplace。
- [x] 使用官方 `skill-creator` 创建 10 个 skill 骨架。
- [x] 写入统一数据模型，确认 xlsx 包含完整 `Flag`。
- [x] 让用户确认第一阶段骨架命名和字段。

## 阶段 2：统一数据模型脚本

- [x] 实现 `ctf_case.json` schema 校验脚本。
- [x] 实现 xlsx 导入、导出、字段校验脚本。
- [x] 实现批量状态汇总脚本。
- [x] 增加 `unittest` 覆盖完整 Flag、状态枚举、xlsx round trip 和 summary。

## 阶段 3：收集与资料整理

- [x] 实现赛事/赛题收集报告模板。
- [x] 实现附件、源码、WP、链接的材料清单生成。
- [x] 实现来源证据和缺失项检查。
- [x] 定义公开来源收集记录格式和证据字段。
- [x] 提供旧 xlsx 到 `ctf_cases.jsonl` 的迁移命令。
- [x] 让用户确认旧 xlsx 迁移后的字段映射是否需要继续调整。

## 阶段 4：构建与附件题处理

- [x] 增强 `cloversec-ctf-build-dockerizer`：docker build/run/export/import 与 amd64 检查计划。
- [x] 输出 `environment`、`docker_artifacts`、`xlsx_fields`。
- [x] 实现附件题压缩包检查、hash、目录清单。
- [x] 增加路径穿越风险检查。
- [x] 增加阶段 4 单元测试。

## 阶段 5：手册与 Hub 提交材料

- [x] 增强 `cloversec-ctf-writeup-scaffold`：HUB 字段、10 级难度、星级、xlsx 行草稿。
- [x] 生成 Hub 提交材料目录和上传核对表。
- [x] 明确截图命名和附件清单格式。
- [x] 定义 `hub_fields.json` 和上传目录结构。
- [x] 将已有 `CloverSec-CTF-Build-Dockerizer` 源项目完整同步到 plugin skill。
- [x] 将已有 `CloverSec-CTF-Writeup-Scaffold` 源项目完整同步到 plugin skill。
- [x] 在源项目增强后再迁移，不使用简化替代版 skill。
- [x] 发布 `CloverSec-CTF-Build-Dockerizer` `v2.2.0-r7`，并更新本地安装版 Skill。
- [x] 优化 `CloverSec-CTF-Writeup-Scaffold` 运行入口，改为安装版可直接使用的渐进加载说明。
- [x] 验证两个源 Skill 与 For Example 插件副本一致。

## 阶段 6：归档、审核、最终报告

- [x] 优先扩展 `cloversec-ctf-archive-packager`，生成统一归档目录、manifest、手册、附件包和 amd64 镜像 tar 索引。
- [x] 优先扩展 `cloversec-ctf-quality-review`，检查题目、资源、镜像启动、手册步骤和 Flag 可验证性。
- [x] 优先扩展 `cloversec-ctf-hub-retag`，按审核后的 HUB 编号生成镜像 tag 与导出 tar 命令计划。
- [x] 优先扩展 `cloversec-ctf-final-report`，生成最终归档 xlsx 和语雀粘贴表。
- [x] 实现归档目录生成。
- [x] 实现质量检查报告。
- [x] 实现审核通过后的 HUB 编号回填和镜像 tag 处理计划。
- [x] 实现最终 xlsx 和语雀粘贴表。
- [x] 扩展 `cloversec-ctf-archive-packager`：统一输出手册、附件包、amd64 镜像 tar、manifest 和归档索引。
- [x] 扩展 `cloversec-ctf-quality-review`：检查题目、资源、镜像启动、手册步骤和 Flag 可验证性。
- [x] 扩展 `cloversec-ctf-hub-retag`：按审核后的 HUB 编号生成镜像 tag 与导出 tar 命令计划。
- [x] 扩展 `cloversec-ctf-final-report`：生成最终归档 xlsx 和语雀粘贴表。

## 下一阶段计划

- [x] 为收集阶段实现 C 方案：免费源优先，可选 key 增强，增加搜索脚本和 MCP server。
- [x] 完成真实公网烟测：CTFTime 2025 events、GitHub/公开 seeds 搜索、DuckDuckGo lite writeup 搜索、GitHub 页面抓取。
- [x] 审计搜索与下载边界：限制 fetch/download URL scheme、修正 `--max-bytes` 实际读取上限、HTTP 4xx/5xx 不再写成成功附件、GitHub code search 跳过信息独立为 `github-code`。
- [x] 修正 skill UI 占位介绍，完善 plugin 对外元数据、repo marketplace 名称和 GitHub 安装说明。
- [x] 配置 GitHub Release 工作流，增加发布前校验和插件包生成脚本。
- [ ] 对 `cloversec-ctf-research-intake` 做更多真实公网样例验收：CTFTime、GitHub archive、具体赛事 writeup、直接附件 URL。
- [ ] 用户提供 key 后，验收 GitHub code search、Brave Search、Bing Search 的真实返回质量。
- [ ] 插件重新安装后，在新的 Codex 会话确认 `cloversec-ctf-search` MCP 工具是否直接暴露给 Agent。
- [x] 对 `cloversec-ctf-asset-collector` 增加 GitHub release asset、raw 文件、目录树下载和压缩包内容预览。
- [x] 对 GitHub release asset、raw 文件、目录树下载和 zip 预览做真实公网烟测。
- [ ] 为 `cloversec-ctf-quality-review` 增加受控 Docker 执行模式：load、inspect、run、端口探测、停止容器、记录执行证据。
- [ ] 为 `cloversec-ctf-hub-retag` 增加受控执行模式：tag、save、load、inspect、amd64 校验、hash 记录。
- [ ] 设计 Hub 浏览器辅助填表方案：只使用用户当前登录态，不读取或保存 Cookie、token、localStorage、sessionStorage。
- [ ] 增加批量归档命令，支持 `ctf_cases.jsonl` 一次性生成所有题目的归档目录和最终报告。
- [ ] 增加真实样例 fixture，覆盖容器题、附件题、缺手册、缺截图、Hub 已编号等场景。

## MCP / App 后续规划

- [ ] MCP：`cloversec-ctf-search-plus`，统一 GitHub、Brave、Bing、CTFTime、公开归档站、writeup 站点和直接附件 URL 的搜索、证据记录、下载预览与来源评分。
- [ ] MCP：`cloversec-ctf-docker`，受控执行 `docker build/load/inspect/run/logs/stop/save`，记录 amd64 校验、端口、启动日志、hash 和失败证据。
- [ ] MCP：`cloversec-ctf-archive`，批量读取 `ctf_cases.jsonl`，生成归档目录、资源索引、manifest、最终 xlsx、语雀表和缺失项报告。
- [ ] MCP：`cloversec-ctf-hub-assistant`，使用用户当前浏览器登录态辅助填写 Hub 表单、上传截图和资源清单；禁止读取或保存 Cookie、token、localStorage、sessionStorage。
- [ ] MCP：`cloversec-ctf-quality-runner`，把题目资源、Docker 验证、手册解题步骤、Flag 字段和归档状态汇总成可复核的质量检查证据。
- [ ] App：`CloverSec CTF Workbench`，展示赛事、题目、资源、手册、镜像、Hub 审核和归档进度，支持从表格进入单题工作流。
- [ ] App：`CloverSec CTF Hub Uploader`，浏览器辅助提交界面，所有字段和上传动作都需要人工确认，保留提交前截图和字段差异。
- [ ] App：`CloverSec CTF Review Dashboard`，聚合 Docker 验证、附件检查、手册质量、Flag 验证、Hub 编号和最终归档状态。
- [ ] App：`CloverSec CTF Archive Browser`，查看归档包、manifest、附件预览、hash、镜像 tar 信息、手册路径和最终导出位置。

## 体验与自动化增强池

- [ ] 任务向导：从“年份/赛事/方向/数量”生成采集任务，自动创建工作目录、`ctf_cases.jsonl`、日志目录、证据目录和下一步清单。
- [ ] 批处理编排：支持 dry-run/apply、断点继续、单题失败不影响整批、阶段状态写入 `workflow_state.json`。
- [ ] 来源可信度：对每个题目记录多来源证据、置信度、原始页面快照、下载 URL、hash、抓取时间和缺失原因。
- [ ] 去重合并：按赛事名、题目名、分类、附件 hash、writeup 标题和 URL 聚合重复题目，人工确认后合并字段。
- [ ] 搜索策略库：为 Web/Pwn/Reverse/Crypto/Misc/Forensics/AI 等分类生成专用 query 组合，提高公开资料命中率。
- [ ] Key 配置向导：检测 GitHub、Brave、Bing 等可选 key，执行小样本查询，展示限额、失败原因和当前可用搜索源。
- [ ] 下载沙箱：所有外部附件先进入隔离目录，限制协议、大小、重定向、文件名和解压路径，生成安全预览后再进入题目目录。
- [ ] 附件智能识别：自动判断源码包、附件题、Docker 项目、compose 项目、writeup、截图、pcap、binary、数据库 dump 等资源类型。
- [ ] 容器题识别：从 Dockerfile、compose、README、端口、启动脚本中推断服务类型、端口、环境变量、构建命令和运行命令。
- [ ] Docker 验证分级：轻量 inspect、构建验证、启动验证、端口探测、日志采集、HTTP 探测、手册解题验证分层执行。
- [ ] 手册质量助手：检查字段完整性、题目描述、考点、环境、解题步骤、截图引用、Flag、附件引用和 Hub 表单字段一致性。
- [ ] 解题证据包：把关键命令、输出摘要、截图、flag 验证记录、容器日志和文件 hash 打包成 `proof/`，供审核复核。
- [ ] Hub 提交草稿：从 markdown、xlsx 字段和资源目录生成表单草稿、上传清单、截图清单和提交前差异报告。
- [ ] Hub 审核跟踪：记录已提交题目、审核状态、退回意见、Hub 编号、镜像 tag 计划和重新导出任务。
- [ ] 镜像命名助手：根据 Hub 编号、题目分类、内部规范生成镜像名、tag、tar 文件名、hash 和归档字段。
- [ ] 归档一致性锁定：生成 `manifest.lock.json`，固定手册、附件、镜像 tar、hash、flag、Hub 编号和最终 xlsx 字段。
- [ ] 归档目录预览：在写入前输出目录树、缺失项、重复文件、过大文件、命名不规范文件和将要生成的最终路径。
- [ ] 人工确认节点：下载、解压、Docker 执行、Hub 提交、镜像 retag、最终归档写入前都显示风险、影响和确认项。
- [ ] 批量报告：按赛事、年份、分类、状态、缺失资源、待人工确认、可归档、已归档输出 xlsx、markdown 和终端摘要。
- [ ] 失败案例库：记录搜索失败、下载失败、构建失败、Hub 退回、手册不一致等案例，沉淀成后续自动修复建议。
- [ ] 多 Agent 分工模板：Research、Asset、Docker、Writeup、Review、Hub、Archive 角色分工，适配大批量题目处理。
- [ ] 通知输出：每个阶段结束生成“已完成、失败、待人工处理、下一阶段输入”的短报告，方便接手继续处理。
