---
name: cloversec-ctf-resource-classifier
description: CloverSec CTF 资源智能识别 skill。用于扫描本地题目资源目录，判断 Docker/compose/source/attachment/writeup/screenshot/pcap/binary/database 等资源类型，输出 resource_classification.json，并推荐下一步 skill。
---

# CloverSec CTF Resource Classifier

## 何时使用

- 用户给了题目目录、下载沙箱目录、附件解压目录或归档前资源目录，需要判断里面是什么。
- 需要区分容器题、compose 项目、源码包、附件题、writeup、截图、pcap、binary、数据库 dump、镜像 tar。
- 批量任务中需要把资源分流给 `cloversec-ctf-build-dockerizer`、`cloversec-ctf-attachment-packager`、`cloversec-ctf-writeup-scaffold` 或人工处理。

## 默认行为

1. 优先使用 `cloversec_ctf_resource_route`。它会同时生成资源识别、必要时生成容器推断，并输出下一步 handoff。
2. 只读取文件名、目录结构、size、SHA256、少量文本样本和压缩包清单。
3. 不执行未知脚本，不启动 Docker，不解压到正式题目目录。
4. 输出 `resource_classification.json`、`resource_route.json`，容器相关目录还会输出 `container_inference.json` 和 `dockerizer_handoff`。
5. 对低置信度、未知文件、压缩包预览异常写入 `warnings`。
6. 资源识别只是分流建议，不把推断写成最终事实。

## 资源状态分流

| 资源状态 | 推荐下一步 | 必须说明 |
|---|---|---|
| 没有源码、没有附件，只有题名、链接或 WP | `manual_review` 或 `cloversec-ctf-writeup-scaffold` | 写 `missing_source` / `needs_user_material`，不能声明可复现 |
| 只有附件压缩包、pcap、binary、数据库 dump | `cloversec-ctf-attachment-packager` | 非容器附件题不进入 Dockerizer |
| 有源码，没有 Dockerfile | `cloversec-ctf-build-dockerizer` | 需要生成 CloverSec 平台交付方案 |
| 有源码和上游 Dockerfile | `cloversec-ctf-build-dockerizer` | Dockerfile 只是参考，不能直接当最终交付 |
| 有 compose/Vulhub-like 结构 | `cloversec-ctf-build-dockerizer` | compose 只用于迁移分析，平台最终交付仍按单题目录 |
| 只有 Docker image tar | `cloversec-ctf-docker` + 人工确认 | 只能 inspect/hash，缺平台契约时不能直接归档为通过 |
| writeup/screenshot 为主 | `cloversec-ctf-writeup-scaffold` | 只生成手册草稿和缺失项 |
| 只有 `challenge.yml`、solver、writeup、截图、Flag | `cloversec-ctf-asset-collector` 或 `cloversec-ctf-writeup-scaffold` | 这是题目线索或手册材料，缺官方附件/源码，不能交付 |

`resource_classification.json` 里的 `recommended_next_skill` 对容器相关资源必须指向 `cloversec-ctf-build-dockerizer`。如果目录里有 Dockerfile 或 compose，分类结果也要在 `recommendations` 里提醒“上游 Dockerfile/compose 不等于 CloverSec 平台交付”。

容器相关资源必须直接进入 Dockerizer handoff。这里不做审批式确认，也不允许 Agent 直接沿用上游 Dockerfile/compose 当最终交付。

`challenge.yml`、`challenge.json`、`solve.py`、`solve.sage`、`writeup.md` 这类文件不能单独当成服务源码。只有出现服务源码、包管理文件、Dockerfile、compose、镜像 tar、端口服务或明确构建需求时，才进入 Dockerizer。

## 平台契约摘要

- 发现源码、Dockerfile、compose、官方启动脚本、镜像构建信息、端口服务或 Web/Pwn 在线服务题时，下一步必须是 `cloversec-ctf-build-dockerizer`。
- 上游 Dockerfile、compose、镜像 tar、README 启动命令只作为迁移输入，不算 CloverSec 平台交付。
- 未完成 Dockerizer 自动渲染和静态校验前，机器字段必须写：`auto_action=auto-render`、`failure_category=platform_conversion_required`、`next_skill=cloversec-ctf-build-dockerizer`、`can_archive=false`。
- 平台交付必须有 Dockerizer 产物：`Dockerfile`、`start.sh`、`changeflag.sh`、`flag`，并输出 `environment`、`docker_artifacts`、`xlsx_fields`。
- `/start.sh`、`/bin/bash /changeflag.sh`、`/flag`、端口、`linux/amd64` 都要有验证证据。直接 `docker build/run` 只能当证据，不能替代 Dockerizer 改造。

## 常用命令

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_resource.py classify \
  path/to/challenge \
  --output resource_classification.json
```

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py route-resource \
  path/to/challenge \
  --output-dir path/to/challenge/classification
```

## MCP Tool

- `cloversec_ctf_resource_route`
- `cloversec_ctf_resource_classify`

输入：

```json
{
  "root": "path/to/challenge",
  "output_path": "resource_classification.json",
  "max_files": 2000,
  "archive_preview_entries": 200
}
```

## 输出字段

```json
{
  "schema_version": "cloversec.ctf.resource_classification.v1",
  "root_classification": {
    "project_type": "container_project",
    "confidence": "high",
    "recommended_next_skill": "cloversec-ctf-build-dockerizer",
    "platform_delivery": {
      "requires_cloversec_contract": true,
      "must_use_dockerizer": true,
      "existing_docker_is_reference_only": true,
      "auto_action": "auto-render",
      "blocking_until_rendered": true
    },
    "evidence": ["Dockerfile found"]
  },
  "summary": {},
  "resources": [],
  "recommendations": [],
  "warnings": []
}
```

## 停止条件

- 需要执行未知脚本、真实启动 Docker、访问外部服务或解压到正式题目目录时，先让用户确认。
- 分类结果低置信度时，不自动进入 Dockerizer 或归档步骤，先输出人工确认项。
- 发现 Dockerfile、compose 或官方启动脚本时，不直接执行成最终交付；直接交给 `cloversec-ctf-build-dockerizer` 做平台化改造。
