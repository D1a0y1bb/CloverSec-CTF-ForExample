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
- [x] 验证两个源 Skill 与 ForExample 插件副本一致。

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
- [ ] 对 `cloversec-ctf-research-intake` 做更多真实公网样例验收：CTFTime、GitHub archive、具体赛事 writeup、直接附件 URL。
- [ ] 对 `cloversec-ctf-asset-collector` 增加 GitHub release asset、raw 文件、目录树下载和压缩包内容预览。
- [ ] 为 `cloversec-ctf-quality-review` 增加受控 Docker 执行模式：load、inspect、run、端口探测、停止容器、记录执行证据。
- [ ] 为 `cloversec-ctf-hub-retag` 增加受控执行模式：tag、save、load、inspect、amd64 校验、hash 记录。
- [ ] 设计 Hub 浏览器辅助填表方案：只使用用户当前登录态，不读取或保存 Cookie、token、localStorage、sessionStorage。
- [ ] 增加批量归档命令，支持 `ctf_cases.jsonl` 一次性生成所有题目的归档目录和最终报告。
- [ ] 增加真实样例 fixture，覆盖容器题、附件题、缺手册、缺截图、Hub 已编号等场景。
