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
- [x] 对 `cloversec-ctf-research-intake` 做更多真实公网样例验收：CTFTime、GitHub archive、具体赛事 writeup、直接附件 URL。
- [ ] 可选 key 质量验收：默认不要求 Brave/Bing；后续只在已有 key 时验收 GitHub code search、Brave Search、Bing Search 的真实返回质量。
- [x] 插件重新安装后，在新的 Codex 会话确认 `cloversec-ctf-search` MCP 工具可通过 `tool_search` 发现并调用。
- [x] 对 `cloversec-ctf-asset-collector` 增加 GitHub release asset、raw 文件、目录树下载和压缩包内容预览。
- [x] 对 GitHub release asset、raw 文件、目录树下载和 zip 预览做真实公网烟测。
- [x] 为 `cloversec-ctf-quality-review` 增加受控 Docker 执行模式：load、inspect、run、端口探测、停止容器、记录执行证据。
- [x] 为 `cloversec-ctf-hub-retag` 增加受控执行模式：tag、save、load、inspect、amd64 校验、hash 记录。
- [x] 设计 Hub 浏览器辅助填表方案：只使用用户当前登录态，不读取或保存 Cookie、token、localStorage、sessionStorage。
- [x] 增加批量归档命令，支持 `ctf_cases.jsonl` 一次性生成所有题目的归档目录和最终报告。
- [x] 增加真实样例 fixture，覆盖容器题、附件题、缺手册、缺截图、Hub 已编号等场景。
- [x] 对 8 个非自研验证 skill 做真实链路质量验收，修复 GitHub Release 限流异常输出和 Hub retag 大写 Docker tag 问题。
- [x] 使用临时浏览器登录 Hub，验证 CTF 列表、提交页路由、表单字段、上传入口和提交接口；不保存 Cookie/token/session，不执行最终提交。
- [x] 扩展收集源：增加 `ctf-platforms` seeds，以及 CSDN、博客园、语雀 `site:` 定向搜索。
- [x] 使用临时官方 `busybox:1.36` amd64 镜像完成真实 Docker 验收，覆盖 `run`、`probe`、`tag`、`save`、`load`、`inspect`；没有执行未知题目镜像。
- [x] 本机插件已安装到 `0.1.8`，`.mcp.json` / `mcpServers` 配置存在。
- [x] 新开独立 Codex 会话验收 `cloversec-ctf-search` MCP 可发现并可调用：线程 `019ec18b-a5c2-7cd0-987a-929467d11dae`，通过 `tool_search` 加载后出现 `mcp__cloversec_ctf_search`，调用 `cloversec_ctf_ctftime_events(year=2026, limit=1)` 成功返回 `Scarlet CTF 2026`。
- [x] 使用 CloudRouter 真实 LLM 调用测试当前插件效果，主测 `gpt-5.4-mini`，抽样复测 `gpt-5.4` / `gpt-5.5`；记录搜索质量、Hub、retag、附件 fixture、prompt 体积等问题。
- [x] Google/Baidu 直连不作为默认稳定来源；已改为浏览器辅助 MCP 第一版。
- [ ] 验收更严格的 MCP 可见性标准：不调用 `tool_search`，新会话初始工具列表里是否直接出现 `cloversec-ctf-search`。
- [x] 搜索质量第一版改进：赛事名精确匹配、标题 token 评分、无关赛事降级、搜索引擎首页剔除，避免 `IrisCTF 2025 web writeup` 混入 NepCTF、Compfest 或 DuckDuckGo 首页。
- [x] 调整 `ctf-platforms` 数据层语义：平台首页默认标记为 `lead_only`，不和真实 writeup、附件、题目归档结果放在同一可信等级。
- [ ] 修复附件测试 fixture：`tests/fixtures/resources/attachment/challenge.zip` 当前只是 12 字节文本 `zip fixture`，但 case 名为 `fixture-attachment-ok`；需要替换为真实 zip，或改名为 broken fixture 并调整测试预期。
- [ ] 增强 Hub 提交自动化前置能力：把 `题目分类` 文本映射为 Hub 分类 ID，记录附件上传返回结果，检查 `题目内容`、`题目解答`、关键字和截图文件是否齐全。
- [ ] 明确 Hub 当前能力边界：插件现在能生成提交包、字段 payload 和浏览器填表计划；还没有真正实现自动填表、自动上传、自动提交。
- [ ] 强化 `cloversec-ctf-hub-retag` 小模型输出约束：停止条件下 `can_execute` 必须返回布尔 `false`，不能返回 `null`；在 skill/schema 中增加严格 JSON 示例。
- [ ] 降低真实 LLM 调用 prompt 体积：把 skill 的 Agent 可读摘要、严格 JSON 模板、深层参考文档分层，避免单次 6k-9k tokens 和 100 秒以上延迟。
- [ ] 把“内部 xlsx 必须写入完整 Flag”放到更浅层：插件级说明、workflow 参考、相关 skill description 都要能被只读 catalog 的 Agent 看到。

## 需要用户配合的验收项

- [ ] 如已有 GitHub/Brave/Bing key，再执行 key-backed 搜索质量验收；Brave/Bing 不作为默认要求。
- [x] 在新 Codex 会话中确认 `cloversec-ctf-search` MCP 工具可通过 `tool_search` 发现并调用，线程 `019ec18b-a5c2-7cd0-987a-929467d11dae`。
- [ ] 如需更严格验收，再确认新会话初始工具列表是否无需 `tool_search` 就直接包含 `cloversec-ctf-search`。

## 真实验收记录与问题台账

### 已完成 / 已验证

- [x] Docker 真实执行不是 mock：已用临时官方 `busybox:1.36` amd64 镜像验证 `quality-review` 与 `hub-retag` 的受控 Docker 路径，覆盖 `run`、`probe`、`tag`、`save`、`load`、`inspect`。
- [x] Docker 验收没有执行未知题目镜像：只使用官方临时镜像，不对来源不明镜像做 `run`。
- [x] 搜索 key 输入方式已明确：不要在聊天里发送 key；推荐使用本机 `gh auth login` 或终端环境变量 `GITHUB_TOKEN` / `GH_TOKEN`，Brave/Bing key 只作为可选增强。
- [x] 无 key 情况下的免费源已具备：CTFTime、GitHub public、公开归档 seeds、CTF 平台 seeds、CSDN、博客园、语雀 `site:` 定向搜索。
- [x] 本机 Codex 插件安装版本已确认：`cloversec-ctf-forexample@cloversec-ctf` 为 `0.1.8`，`mcpServers` 配置存在。
- [x] 新会话 MCP 可发现性已验收：线程 `019ec18b-a5c2-7cd0-987a-929467d11dae` 中通过 `tool_search` 发现 `mcp__cloversec_ctf_search`，并成功调用 `cloversec_ctf_ctftime_events` 返回 `Scarlet CTF 2026`。
- [x] Hub 页面真实验证已完成：可登录、进入 CTF 列表、打开提交表单；字段和接口已写入 `hub-submission`；没有最终提交、没有上传测试资源、没有保存账号密码、token 或 session。
- [x] Research 来源扩展已完成第一版：新增 `ctf-platforms`、`csdn`、`cnblogs`、`yuque`，并做过真实搜索样例测试。
- [x] Google/Baidu 直连搜索已判断为不适合默认稳定源，后续走浏览器辅助或独立 MCP 方案。
- [x] CloudRouter 真实 LLM 调用已完成：`/v1/models` 和 `/v1/chat/completions` 可用；主测 `gpt-5.4-mini`，抽样复测 `gpt-5.4`、`gpt-5.5`。
- [x] 真实 LLM 测试暴露的问题已记录到本台账：搜索质量、平台首页语义、附件 fixture、Hub 自动化、retag JSON 严格性、prompt 体积、Flag 规则可见性。
- [x] 默认搜索源改为免费源：GitHub、CTFTime、DuckDuckGo、公开归档 seeds、CTF 平台 seeds、CSDN、博客园、语雀；Brave/Bing 不再作为默认要求。
- [x] GitHub code search 改为优先使用 `GITHUB_TOKEN` / `GH_TOKEN`，没有环境变量时读取本机 `gh auth token`；可用 `CLOVERSEC_DISABLE_GH_AUTH_TOKEN=1` 禁用。
- [x] 已增加 Agent 联网搜索结果导入：`cloversec_ctf_import_agent_web_results` / `import-agent-search`，字段包含 `source_url`、`title`、`snippet`、`provider`、`confidence`、`evidence`、`layer`、`score`。
- [x] 已增加结果评分分层：`confirmed_challenge`、`writeup_candidate`、`attachment_candidate`、`platform_lead`、`noise`。
- [x] 已增加赛事名、年份、标题 token、WP/附件词、搜索首页和登录页过滤规则；`IrisCTF` 场景中 `NepCTF`、`Compfest CTF` 会降为 `noise`。
- [x] 已增加 `lead_only=true`：CTFTime、NSSCTF、CTFHub、BUUOJ 等平台入口只能作为 `platform_lead`。
- [x] 已增加浏览器辅助搜索第一版：`cloversec-ctf-browser-search` MCP server，支持 Google、Baidu、CSDN、博客园、语雀的搜索计划和页面可见结果导入，不读取 Cookie、token、localStorage、sessionStorage。

### 待处理问题

- [ ] Key-backed 搜索质量未验收：现在只把 GitHub token 作为推荐增强；Brave/Bing 属于可选项，不再要求用户申请付费 key。后续有 key 时再跑真实返回质量、限额、失败原因和排序效果。
- [ ] 更严格 MCP 可见性未验收：已验证 `tool_search` 可发现并加载 MCP；还没验证“新会话初始工具列表无需搜索就直接出现”。
- [ ] 搜索质量仍需真实世界扩大验证：已实现 query 评分、赛事名强匹配、无关赛事降权和首页剔除；还需要用多个赛事、多分类、多中文站点抽样确认误报率。
- [ ] `confirmed_challenge` 语义仍需收紧：当前 event-level writeup 页面可能因为赛事、年份、分类齐全被升为 confirmed；后续应要求明确题目名或题目页证据。
- [ ] 附件 fixture 与名称不一致：`fixture-attachment-ok` 指向的 `challenge.zip` 实际不是 zip；需要真实 zip fixture 或改为 broken fixture。
- [ ] Hub 提交还不是全自动：当前插件能生成提交包、字段 payload、浏览器填表计划；没有自动填表、没有自动上传、没有自动点击提交。
- [ ] Hub 分类映射缺失：`题目分类` 目前仍可能是 `Misc` 等文本，需要拉取或缓存 Hub 分类 ID 并完成映射。
- [ ] Hub 附件上传结果未自动回写：自动化方案需要在上传后记录 Hub 返回的文件路径、文件名和错误信息。
- [ ] Hub 提交前字段完整性不足：fixture 中 `题目内容`、`题目解答`、关键字、截图内容可能为空，需要提交前阻断和修复建议。
- [ ] `hub-retag` 小模型输出不够严格：`gpt-5.4-mini` 曾返回 `can_execute:null`；skill/schema 要强制布尔字段，停止时必须是 `false`。
- [ ] Prompt 体积偏大：真实 LLM 场景多次达到 6k-9k tokens，`flag_xlsx_policy` 曾耗时 135 秒；需要更短的摘要入口和按需加载参考文档。
- [ ] 完整 Flag 写入 xlsx 的规则可见性不足：只看 skill catalog 时模型可能漏写，需要放到插件级说明、workflow 和相关 skill description。

## MCP / App 后续规划

- [ ] MCP：`cloversec-ctf-search-plus`，统一 GitHub、Brave、Bing、CTFTime、公开归档站、writeup 站点和直接附件 URL 的搜索、证据记录、下载预览与来源评分。
- [x] MCP：`cloversec-ctf-browser-search` 第一版，生成 Google/Baidu/CSDN/博客园/语雀搜索计划，导入页面可见结果，只记录标题、URL、摘要、排名和 blocked 状态，不保存账号、Cookie 或搜索登录态。
- [ ] MCP：`cloversec-ctf-browser-search` 后续增强，接入 Codex/Chrome 浏览器可见 DOM 读取，把用户确认后的页面结果自动转成 `visible_results.json`。
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
