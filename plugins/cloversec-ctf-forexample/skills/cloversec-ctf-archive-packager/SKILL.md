---
name: cloversec-ctf-archive-packager
description: CloverSec CTF 资源归档 skill。用于整理题目源码包、附件包、手册、截图、amd64 镜像 tar、hash 清单和归档目录，形成清楚可交付的题目资源包。
---

# CloverSec CTF Archive Packager

## 任务定位

生成最终归档目录。归档结果要让人直接看到有哪些题目、每题有哪些资源、哪些已验证、哪些需要处理。

## 输入

- `ctf_case.json` 或 `ctf_cases.jsonl`。
- 容器交付件、附件包、手册、截图。
- `docker_artifacts.json`、`attachment_manifest.json`。

## 输出

- `archive_manifest.json`。
- 每题归档目录。
- 总 hash 清单。
- 可供 xlsx 引用的路径字段。

推荐目录：

```text
archive/
  <case_id>-<title>/
    source/
    attachments/
    image/
    writeup/
    screenshots/
    manifests/
```

## 验证

- manifest 中记录的文件必须存在。
- hash 可复算。
- 镜像 tar 已确认 `linux/amd64`。
- 手册和题目名称一致。

## 停止条件

归档命名规则、镜像包存放位置、外部上传地址、敏感文件处理方式不确定时，停止并给用户选择。

