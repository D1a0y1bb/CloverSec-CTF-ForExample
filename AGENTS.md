# AGENTS.md

## 硬约束

- 外部 API、CLI、模型名、端点、语法不确定时，先查官方文档或停下确认。
- 测试失败、未验证、无法验证都要明说。
- 发现流程前提不成立时，直接指出。
- 报完成前必须执行能执行的验证。
- 操作文件前确认当前目录，尊重现有结构和 Git 状态。

## 沟通

- 使用中文，表达直接。
- 需要用户决定时给选项。
- 汇报功能层面的变化，不堆实现细节。
- 不确定、不能决定、会影响流程边界的事项，停下来问用户，不要替用户做业务决定。

## 中文输出习惯

- 像同事之间说工作，不写演讲稿、宣传稿、模板化总结。
- 不用讨好式表达，不夸用户“太对了”“问到核心了”，也不制造情绪依赖。
- 不用虚假确定语气。未验证就写“未验证”，失败就写失败原因。
- 不用暴力或机械比喻描述技术操作，例如“砍一刀”“下一刀”“打坏”“压实”“更硬”“收口”。
- 少用或不用 GPT 口头禅，例如“好，”“行，”“总结一下”“一句话总结”“说穿”“不踩坑”“我先...再...”。
- 避免不自然的黑话和生造词，例如“兜底”“闭环”“落地”“口径”“这一坨”“能吃”“心智模型”。
- 技术名词、命令、文件路径、字段名保持原文，用反引号标出。
- 汇报时先说完成了什么、验证了什么、没做什么，不把大量代码细节塞给用户。

## 本仓库约束

- 本仓库用于开发 `CloverSec CTF For Example` Codex plugin。
- 插件源码放在 `plugins/cloversec-ctf-forexample/`。
- repo marketplace 放在 `.agents/plugins/marketplace.json`。
- 每个流程能力必须 skill 化，skill 名使用 `cloversec-ctf-*`。
- Hub 自动化第一版只生成提交材料和核对清单，不做自动提交。
- xlsx 输出必须包含完整 `Flag` 字段，这是内部归档要求。
- 不得自造 Hub API、镜像 tag 规则、审核编号来源。
- 每个阶段结束前更新 `TODO.md`：已完成打勾，未完成继续留在后续计划，真实测试发现的问题写进待处理问题。

## 插件发布规范

- 当前正规分发方式是 GitHub marketplace：仓库内必须保留 `.agents/plugins/marketplace.json`，用户通过 Codex 的“添加插件市场”安装。
- 不要暗示已经进入 OpenAI 官方 Plugin Directory；个人/团队当前按 GitHub marketplace 分发。
- Release 页面格式沿用 `v0.1.8` 样式：
  - GitHub Release 标题使用 tag，例如 `v0.2.0`。
  - Release 正文第一行写 `# CloverSec CTF For Example 0.2.0`。
  - Release assets 上传 `dist/*`，保留 `release-notes.md`。
- 发布新版本前先执行：
  - `python3 /Users/d1a0y1bb/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py plugins/cloversec-ctf-forexample`
  - `python3 scripts/validate_release.py`
  - `python3 -m unittest discover -s tests -p 'test_*.py'`
  - `python3 scripts/package_plugin_release.py`
- 打 tag 后必须等待 GitHub Actions Release 完成，并用 `gh release view <tag>` 复核标题、正文第一行和资产列表。
- 本机 Codex 更新时，如果 `codex plugin marketplace upgrade cloversec-ctf` 仍安装旧版本，说明 marketplace 固定在旧 ref。此时按需执行：
  - `codex plugin marketplace remove cloversec-ctf`
  - `codex plugin marketplace add D1a0y1bb/CloverSec-CTF-ForExample --ref vX.Y.Z`
  - `codex plugin add cloversec-ctf-forexample@cloversec-ctf`
- 更新后用 `codex plugin list` 和缓存目录里的 `.codex-plugin/plugin.json` 复核版本、`logo`、`composerIcon` 和图标文件。

## 图标与展示资产

- 插件图标使用 PitcherPlant 项目的真实 AppIcon，不使用临时生成的 AI 风格图标。
- 当前来源路径：`/Users/d1a0y1bb/Documents/CoXdeMyPro/PitcherPlant/PitcherPlantApp/Resources/Assets.xcassets/AppIcon.appiconset/icon_512x512@2x.png`。
- 插件内目标路径：`plugins/cloversec-ctf-forexample/assets/app-icon.png`。
- manifest 里同时配置：
  - `interface.logo: "./assets/app-icon.png"`
  - `interface.composerIcon: "./assets/app-icon.png"`
- 换图标后必须确认发布 zip 和 repo-marketplace zip 内都包含 `assets/app-icon.png`。

## 真实验收习惯

- 不能只用 mock 宣称功能可用。能做真实验收的部分必须做真实验收。
- Docker 能力验收用可控官方镜像或明确安全的本地样例，不随意执行未知题目镜像。
- 用户提供模型 key 或 base_url 时，必须做真实 LLM 调用测试；失败、超时、效果差都要记录。
- 搜索能力不能只测脚本能跑，要用真实赛事、题名、分类和中文站点样例验证召回与误报。
- Hub 自动化验收到“最终提交前停止”。没有用户明确要求，不点击最终提交。
- 不把账号、密码、token、Cookie、localStorage、sessionStorage 写进仓库、日志、发布包或 TODO。
- 使用 Hub 浏览器辅助时，优先要求用户先在 Chrome 中登录到有效页面。未登录时自动填表后跳转登录会丢失表单内容，不能把这种流程当成可用。
- 用户明确授权时，可以使用当前 Chrome 登录态操作页面，但不要读取或保存 Cookie、token、localStorage、sessionStorage。

## 搜索与 MCP 习惯

- 默认不要求用户申请 Brave/Bing 等付费或低使用率 key。
- 默认免费来源包括：GitHub CLI/token、GitHub repository/code search、CTFTime、公开 writeup 仓库 seeds、CTF 平台入口、DuckDuckGo HTML、CSDN、博客园、语雀 site 搜索、直接 URL 抓取、GitHub Release/raw/tree 预览。
- GitHub 优先使用用户本机 `gh auth login` 后的认证状态，不要求用户在聊天里粘贴 token。
- 如果当前 Agent 有联网搜索工具，skill 应先指挥 Agent 用联网搜索查 Google/Baidu/全网结果，再把结果回填到插件数据模型。
- 插件脚本不假装能调用模型内置联网搜索；由 skill 明确要求 Agent 使用当前会话可用工具。
- Google/Baidu 直连不作为默认稳定来源。Google HTML 低频尝试即可；Baidu HTML 容易有跳转、反爬和摘要污染，优先走浏览器辅助。
- 浏览器辅助搜索 MCP 只读取页面可见搜索结果：标题、URL、摘要、排名、搜索词。遇到验证码、风控或异常跳转时标记 blocked，不做绕过。
- 搜索结果必须分层：`confirmed_challenge`、`writeup_candidate`、`attachment_candidate`、`platform_lead`、`noise`。
- 搜索评分必须考虑赛事名精确匹配、年份、标题 token、分类、附件/源码/WP 类型；平台首页和搜索首页不得混入高可信结果。

## Skill 维护习惯

- `CloverSec-CTF-Build-Dockerizer` 和 `CloverSec-CTF-Writeup-Scaffold` 是用户真实使用验证过的源 skill，不要用自设计骨架替代。
- 同步到插件版时，必须以源 skill 为准，保留有效功能，再做兼容 Codex 插件的增强。
- `CloverSec-CTF-Build-Dockerizer` 不加入过时的内部 Web/Pwn 环境规则。可维护的增强方向是 Docker build/run/export/import、amd64 检查、`environment`、`docker_artifacts`、`xlsx_fields`。
- `CloverSec-CTF-Writeup-Scaffold` 可以做渐进式加载、Agent 可读化、去掉不适合 Agent 阅读的空话，但不能影响原有手册生成能力。
- 修改这两个源 skill 时，要同步更新本地 Codex skill 和插件内对应 skill，确保两边内容一致。
