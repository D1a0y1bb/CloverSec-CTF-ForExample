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

- [x] 为收集阶段实现 C 方案：免费源优先，GitHub `gh auth` 增强，增加搜索脚本和 MCP server。
- [x] 完成真实公网烟测：CTFTime 2025 events、GitHub/公开 seeds 搜索、DuckDuckGo lite writeup 搜索、GitHub 页面抓取。
- [x] 审计搜索与下载边界：限制 fetch/download URL scheme、修正 `--max-bytes` 实际读取上限、HTTP 4xx/5xx 不再写成成功附件、GitHub code search 跳过信息独立为 `github-code`。
- [x] 修正 skill UI 占位介绍，完善 plugin 对外元数据、repo marketplace 名称和 GitHub 安装说明。
- [x] 配置 GitHub Release 工作流，增加发布前校验和插件包生成脚本。
- [x] 对 `cloversec-ctf-research-intake` 做更多真实公网样例验收：CTFTime、GitHub archive、具体赛事 writeup、直接附件 URL。
- [x] GitHub 增强搜索验收第一版：本机 `gh auth` 可用，GitHub code search 真实返回正常；不再要求付费搜索 API key。
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
- [x] 本机插件已更新安装到 `0.1.9`，`.mcp.json` / `mcpServers` 配置存在。
- [x] 新开独立 Codex 会话验收 `cloversec-ctf-search` MCP 可发现并可调用：线程 `019ec18b-a5c2-7cd0-987a-929467d11dae`，通过 `tool_search` 加载后出现 `mcp__cloversec_ctf_search`，调用 `cloversec_ctf_ctftime_events(year=2026, limit=1)` 成功返回 `Scarlet CTF 2026`。
- [x] 使用 CloudRouter 真实 LLM 调用测试当前插件效果，主测 `gpt-5.4-mini`，抽样复测 `gpt-5.4` / `gpt-5.5`；记录搜索质量、Hub、retag、附件 fixture、prompt 体积等问题。
- [x] Google/Baidu 直连不作为默认稳定来源；已改为浏览器辅助 MCP 第一版。
- [x] 验收更严格的 MCP 可见性标准：线程 `019ec1be-b48d-7452-a4aa-f057339bd952` 未调用 `tool_search`，新会话初始工具列表没有直接出现 `cloversec-ctf-search`；结果已记录为当前限制。
- [x] 搜索质量第一版改进：赛事名精确匹配、标题 token 评分、无关赛事降级、搜索引擎首页剔除，避免 `IrisCTF 2025 web writeup` 混入 NepCTF、Compfest 或 DuckDuckGo 首页。
- [x] 搜索质量扩大样本第二版：已验证 IrisCTF、LA CTF、强网杯、祥云杯、Google CTF、SUCTF、NSSCTF、picoCTF 查询；修复中文赛事名、届数前缀、年份前缀、slug 后缀和泛教程噪声问题。
- [x] 调整 `ctf-platforms` 数据层语义：平台首页默认标记为 `lead_only`，不和真实 writeup、附件、题目归档结果放在同一可信等级。
- [x] 修复附件测试 fixture：`tests/fixtures/resources/attachment/challenge.zip` 已替换为真实 zip，并增加回归测试。
- [x] 增强 Hub 提交自动化前置能力：已支持分类选项映射、上传结果回写、必填字段/关键字/题目解答/截图槽位检查。
- [x] 明确 Hub 当前能力边界：插件能生成提交包、字段 payload、浏览器/Chrome 填表计划、提交前检查和上传结果回写；仍不读取凭证、不自动点击最终提交。
- [x] 强化 `cloversec-ctf-hub-retag` 小模型输出约束：停止条件下 `can_execute` 必须返回布尔 `false`，不能返回 `null`；已增加严格 JSON 示例和校验脚本。
- [x] 降低真实 LLM 调用 prompt 体积：已把 `research-intake`、`asset-collector`、`hub-submission` 的 Agent 入口和深层 reference 分层；`build-dockerizer`、`writeup-scaffold` 按用户要求不做瘦身改造。
- [x] 把“内部 xlsx 必须写入完整 Flag”放到更浅层：已写入插件 manifest、workflow 参考、writeup/final-report skill description。

## 需要用户配合的验收项

- [x] GitHub code search 已通过本机 `gh auth` 验收；付费搜索 API key 路线已取消。
- [x] 在新 Codex 会话中确认 `cloversec-ctf-search` MCP 工具可通过 `tool_search` 发现并调用，线程 `019ec18b-a5c2-7cd0-987a-929467d11dae`。
- [x] 已获用户允许并创建独立新线程验收：线程 `019ec1be-b48d-7452-a4aa-f057339bd952` 证明新会话初始工具列表不直接包含 `cloversec-ctf-search`。

## 真实验收记录与问题台账

### 已完成 / 已验证

- [x] Docker 真实执行不是 mock：已用临时官方 `busybox:1.36` amd64 镜像验证 `quality-review` 与 `hub-retag` 的受控 Docker 路径，覆盖 `run`、`probe`、`tag`、`save`、`load`、`inspect`。
- [x] Docker 验收没有执行未知题目镜像：只使用官方临时镜像，不对来源不明镜像做 `run`。
- [x] 搜索 key 输入方式已明确：不要在聊天里发送 key；推荐使用本机 `gh auth login` 或终端环境变量 `GITHUB_TOKEN` / `GH_TOKEN`；默认不要求付费搜索 API key。
- [x] 无 key 情况下的免费源已具备：CTFTime、GitHub public、公开归档 seeds、CTF 平台 seeds、CSDN、博客园、语雀 `site:` 定向搜索。
- [x] 本机 Codex 插件安装版本已确认：`cloversec-ctf-forexample@cloversec-ctf` 为 `0.1.9`，`mcpServers` 配置存在。
- [x] 新会话 MCP 可发现性已验收：线程 `019ec18b-a5c2-7cd0-987a-929467d11dae` 中通过 `tool_search` 发现 `mcp__cloversec_ctf_search`，并成功调用 `cloversec_ctf_ctftime_events` 返回 `Scarlet CTF 2026`。
- [x] Hub 页面真实验证已完成：可登录、进入 CTF 列表、打开提交表单；字段和接口已写入 `hub-submission`；没有最终提交、没有上传测试资源、没有保存账号密码、token 或 session。
- [x] Research 来源扩展已完成第一版：新增 `ctf-platforms`、`csdn`、`cnblogs`、`yuque`，并做过真实搜索样例测试。
- [x] Google/Baidu 直连搜索已判断为不适合默认稳定源，后续走浏览器辅助或独立 MCP 方案。
- [x] CloudRouter 真实 LLM 调用已完成：`/v1/models` 和 `/v1/chat/completions` 可用；主测 `gpt-5.4-mini`，抽样复测 `gpt-5.4`、`gpt-5.5`。
- [x] 真实 LLM 测试暴露的问题已记录到本台账：搜索质量、平台首页语义、附件 fixture、Hub 自动化、retag JSON 严格性、prompt 体积、Flag 规则可见性。
- [x] 默认搜索源改为免费源：GitHub、CTFTime、DuckDuckGo、公开归档 seeds、CTF 平台 seeds、CSDN、博客园、语雀；付费搜索 API key 路线已取消。
- [x] GitHub code search 改为优先使用 `GITHUB_TOKEN` / `GH_TOKEN`，没有环境变量时读取本机 `gh auth token`；可用 `CLOVERSEC_DISABLE_GH_AUTH_TOKEN=1` 禁用。
- [x] 已增加 Agent 联网搜索结果导入：`cloversec_ctf_import_agent_web_results` / `import-agent-search`，字段包含 `source_url`、`title`、`snippet`、`provider`、`confidence`、`evidence`、`layer`、`score`。
- [x] 已增加结果评分分层：`confirmed_challenge`、`writeup_candidate`、`attachment_candidate`、`platform_lead`、`noise`。
- [x] 已增加赛事名、年份、标题 token、WP/附件词、搜索首页和登录页过滤规则；`IrisCTF` 场景中 `NepCTF`、`Compfest CTF` 会降为 `noise`。
- [x] 已增加 `lead_only=true`：CTFTime、NSSCTF、CTFHub、BUUOJ 等平台入口只能作为 `platform_lead`。
- [x] 已增加浏览器辅助搜索第一版：`cloversec-ctf-browser-search` MCP server，支持 Google、Baidu、CSDN、博客园、语雀的搜索计划和页面可见结果导入，不读取 Cookie、token、localStorage、sessionStorage。

### 待处理问题

- [x] Key-backed 搜索质量问题关闭：GitHub code search 已通过本机 `gh auth` 真实验收；付费搜索 API key 路线已取消。
- [x] 更严格 MCP 可见性已验收：线程 `019ec1be-b48d-7452-a4aa-f057339bd952` 不调用 `tool_search` 时初始工具列表没有直接暴露 `cloversec-ctf-search`。
- [x] 搜索质量扩大验证第二版已完成：抽样覆盖英文赛事、中文赛事、中文站点和平台入口；修复中文赛事名、年份前缀、slug 后缀和泛教程噪声。
- [x] 搜索召回增强已完成当前版本验收：`祥云杯 2024 pwn writeup` 会触发 `recall_recovery`，自动运行放宽年份的公开网页/site 查询，候选从 2 条增至 25 条；恢复结果全部带 `year_relaxed=true`，只作为线索，不冒充 2024 精确确认结果。
- [x] `confirmed_challenge` 语义已收紧：event-level writeup 不再升为 confirmed；需要查询中包含明确题目名或特定线索。
- [x] 附件 fixture 与名称不一致已修复：`fixture-attachment-ok` 的 `challenge.zip` 现在是合法 zip。
- [x] Hub assistant MCP 第一版已加入：`cloversec-ctf-hub-assistant` 可生成 browser/Chrome 计划、校验 manifest、回写上传结果；Chrome 计划停止在最终提交前。
- [x] Hub Chrome 真实登录态自动填写/上传已完成验收：在用户当前 Chrome 登录态下打开资源中心，确认无“登录/注册”且有用户头像后进入新增题目页，填入测试标题、内容、Flag、来源、分值、资源等级、备注、静态 Flag、附件型、题解富文本和关键字，上传测试 zip，停在最终提交前。
- [x] Hub Chrome 未登录态风险已修正进计划：`chrome-plan` 现在包含 `login_state_gate`，页面显示“登录/注册”、SSO、403 或未登录状态时停止，不填写字段、不上传附件。
- [x] Hub Chrome 附件上传已复验通过：`#formImg1 span.upload` 成功触发文件选择器并上传 `/tmp/cloversec-hub-chrome-e2e/resources/cloversec_codex_e2e_attachment.zip`；页面显示 `cloversec_codex_e2e_attachment.zip` 和删除入口。
- [x] Hub 验收后已把 Chrome 页面退回资源中心，避免误点测试提交；没有点击最终提交。
- [x] `v0.1.9` Release 页面问题已处理：Actions 失败原因是手动 Release 已存在，重跑后通过；正文重复标题已删除；资产列表清理为三个插件发布包。
- [x] Release workflow 已改为幂等：Release 已存在时执行 `gh release edit` + `gh release upload --clobber`，以后不会因同名 Release 已存在而失败；上传范围限制为 `dist/cloversec-ctf-forexample-*`。
- [x] `v0.1.9` 真实 LLM 抽样完成：CloudRouter `/v1/models` 与 `/v1/chat/completions` 可用；`gpt-5.4-mini` 通过搜索弱召回、Hub 登录态门槛、完整流程策略短 JSON 复测；`gpt-5.4` 通过 Hub 登录态门槛复核。
- [x] LLM 测试暴露的提示限制已记录：长 JSON 回答容易被 `max_tokens` 截断，自动化验收应要求短 JSON、分段输出或增大输出 token；全流程提示应显式包含“默认免费源”“不自动点击最终提交”“完整 Flag”等硬词。
- [x] Hub 分类映射前置能力已加入：`validate-manifest --classify-options` 可把分类文本映射为 Hub 分类 ID。
- [x] Hub 附件上传结果回写已加入：`apply-upload-results` 可记录上传返回 URL、文件 ID、状态和错误。
- [x] Hub 提交前字段完整性检查已加入：题目内容、题目解答、关键字、分类 ID、上传结果和截图槽位会进入 validation。
- [x] `hub-retag` 小模型输出约束已加强：布尔字段为 `null` 会判 invalid。
- [x] Prompt 体积偏大问题按本阶段范围处理：`research-intake` 约 2.8KB、`asset-collector` 约 2.1KB、`hub-submission` 约 2.6KB；`build-dockerizer` 和 `writeup-scaffold` 是用户自研验证 skill，本阶段不改。
- [x] 完整 Flag 写入 xlsx 的规则可见性已增强：插件级说明、workflow、writeup/final-report description 都可见。

## MCP / App 后续规划

## 当前版本大白话总结（v0.1.9）

- [x] 现在这个 plugin 已经不是空骨架了，可以按 CloverSec CTF 流程从“找比赛/找题目/找 writeup 和附件线索”一路走到“生成手册、Hub 提交材料、归档包、质量检查、Hub 编号 retag 计划、最终 xlsx/语雀表”。
- [x] 你原本的两个核心 skill 已保留并迁移进插件：`CloverSec-CTF-Build-Dockerizer` 和 `CloverSec-CTF-Writeup-Scaffold`，没有用简化替代版覆盖。
- [x] 搜索部分已经有真实公网能力：GitHub、CTFTime、DuckDuckGo、公开归档 seeds、CTF 平台 seeds、CSDN、博客园、语雀；不要求 Brave/Bing 付费 key。
- [x] 搜索质量比第一版强：会区分 confirmed/writeup/attachment/platform/noise，会把平台首页降为线索，会在默认源召回不足时用 `recall_recovery` 做放宽年份检索，并把历史线索标成 `year_relaxed=true`。
- [x] Hub 自动化已经过真实页面验收：确认 Chrome 已登录后再填写；字段、关键字、题解富文本、测试 zip 上传都跑到提交前；没有点击最终提交。
- [x] Docker 不是 mock：已用官方 `busybox:1.36` amd64 镜像做过真实 run/probe/tag/save/load/inspect；没有执行未知题目镜像。
- [x] 发布方式已正规化：GitHub marketplace 安装可用，`v0.1.9` Release 已发布，本机 Codex 已安装到 `0.1.9`。
- [x] 真实 LLM 验证结论：`gpt-5.4-mini` 对搜索弱召回、Hub 登录态门槛、完整流程短 JSON 能按规则回答；`gpt-5.4` 对 Hub 登录态门槛也能按规则回答。
- [ ] 仍不足：全网搜索不是万能下载器。遇到冷门比赛、中文站点收录差、附件下架、网盘失效时，仍需要 Agent 联网搜索、Chrome 浏览器辅助搜索或人工提供入口。
- [ ] 仍不足：Hub 目前是“辅助填写到提交前”，不是无人值守提交；最终提交、分类不确定、未知附件上传仍需要人确认。
- [ ] 仍不足：长 JSON LLM 输出可能被截断；批量自动化时要用短 JSON、分段输出或加大输出 token。
- [ ] 仍不足：还没有可视化 App 工作台；批量任务状态、失败重试、Hub 审核跟踪、归档浏览现在主要靠脚本和文件。

- [ ] MCP：`cloversec-ctf-search-plus`，统一 GitHub、CTFTime、公开归档站、writeup 站点、浏览器可见结果和直接附件 URL 的搜索、证据记录、下载预览与来源评分。
- [x] MCP：`cloversec-ctf-browser-search` 第一版，生成 Google/Baidu/CSDN/博客园/语雀搜索计划，导入页面可见结果，只记录标题、URL、摘要、排名和 blocked 状态，不保存账号、Cookie 或搜索登录态。
- [ ] MCP：`cloversec-ctf-browser-search` 后续增强，接入 Codex/Chrome 浏览器可见 DOM 读取，把用户确认后的页面结果自动转成 `visible_results.json`。
- [ ] MCP：`cloversec-ctf-docker`，受控执行 `docker build/load/inspect/run/logs/stop/save`，记录 amd64 校验、端口、启动日志、hash 和失败证据。
- [ ] MCP：`cloversec-ctf-archive`，批量读取 `ctf_cases.jsonl`，生成归档目录、资源索引、manifest、最终 xlsx、语雀表和缺失项报告。
- [x] MCP：`cloversec-ctf-hub-assistant` 第一版，生成 Hub browser/Chrome 填表计划、manifest 校验和上传结果回写；禁止读取或保存 Cookie、token、localStorage、sessionStorage，最终提交前停止。
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
- [ ] GitHub 配置向导：检测 `gh auth login`、`GITHUB_TOKEN` / `GH_TOKEN`，执行小样本查询，展示限额、失败原因和当前可用搜索源。
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
