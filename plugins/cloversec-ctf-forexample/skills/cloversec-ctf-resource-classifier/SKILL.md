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

1. 只读取文件名、目录结构、size、SHA256、少量文本样本和压缩包清单。
2. 不执行未知脚本，不启动 Docker，不解压到正式题目目录。
3. 输出 `resource_classification.json`，包含 `root_classification`、每个文件的 `resource_type`、`confidence`、`evidence`、`recommended_next_skill`。
4. 对低置信度、未知文件、压缩包预览异常写入 `warnings`。
5. 资源识别只是分流建议，不把推断写成最终事实。

## 常用命令

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_resource.py classify \
  path/to/challenge \
  --output resource_classification.json
```

## MCP Tool

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
    "evidence": ["Dockerfile found"]
  },
  "summary": {},
  "resources": [],
  "recommendations": [],
  "warnings": []
}
```

## 停止条件

- 需要执行未知脚本、启动 Docker、访问外部服务或解压到正式题目目录时，先让用户确认。
- 分类结果低置信度时，不自动进入 Dockerizer 或归档步骤，先输出人工确认项。
