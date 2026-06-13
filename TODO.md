# 后续开发计划

## 阶段 1：插件与 skill 骨架

- [x] 初始化 Git 仓库。
- [x] 使用官方 `plugin-creator` 创建 plugin manifest 和 repo marketplace。
- [x] 使用官方 `skill-creator` 创建 10 个 skill 骨架。
- [x] 写入统一数据模型，确认 xlsx 包含完整 `Flag`。
- [ ] 让用户确认第一阶段骨架命名和字段。

## 阶段 2：统一数据模型脚本

- [ ] 实现 `ctf_case.json` schema 校验脚本。
- [ ] 实现 xlsx 导入、导出、字段校验脚本。
- [ ] 实现批量状态汇总脚本。

## 阶段 3：收集与资料整理

- [ ] 实现赛事/赛题收集报告模板。
- [ ] 实现附件、源码、WP、链接的材料清单生成。
- [ ] 实现来源证据和缺失项检查。

## 阶段 4：构建与附件题处理

- [ ] 增强 `cloversec-ctf-build-dockerizer`：docker build/run/export/import 与 amd64 检查。
- [ ] 输出 `environment`、`docker_artifacts`、`xlsx_fields`。
- [ ] 实现附件题压缩包检查、hash、目录清单。

## 阶段 5：手册与 Hub 提交材料

- [ ] 增强 `cloversec-ctf-writeup-scaffold`：HUB 字段、10 级难度、星级、xlsx 行草稿。
- [ ] 生成 Hub 提交材料目录和上传核对表。
- [ ] 明确截图命名和附件清单格式。

## 阶段 6：归档、审核、最终报告

- [ ] 实现归档目录生成。
- [ ] 实现质量检查报告。
- [ ] 实现审核通过后的 HUB 编号回填和镜像 tag 处理。
- [ ] 实现最终 xlsx 和语雀粘贴表。

