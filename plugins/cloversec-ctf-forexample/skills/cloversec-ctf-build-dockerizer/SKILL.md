---
name: cloversec-ctf-build-dockerizer
description: CloverSec CTF 容器题目构建转换 skill。用于把环境型赛题材料转换为容器交付件，并执行 docker build/run/export/import、linux/amd64 架构检查，输出 environment、docker_artifacts、xlsx_fields 给归档流程。
---

# CloverSec CTF Build Dockerizer

## 任务定位

处理环境型题目，生成或接入容器交付件。当前插件版本保留对既有 `CloverSec-CTF-Build-Dockerizer` 正式仓库的集成位置；本 skill 的新增职责是归档流程适配和镜像验证结果输出。

## 输入

- 题目源码目录。
- 已有 Dockerfile、compose、启动脚本或 `challenge.yaml`。
- `ctf_case.json` 中的题名、分类、端口、Flag 类型。

## 输出

- 容器交付目录。
- `docker_artifacts.json`。
- `environment.json`。
- `xlsx_fields.json`。

`docker_artifacts.json` 至少记录：`image_name`、`image_id`、`platform`、`ports`、`tar_path`、`sha256`、`build_command`、`run_command`、`export_command`、`import_command`。

## 工作流程

1. 读取题目目录和已有构建材料。
2. 使用既有 Dockerizer 逻辑生成或审查交付件。
3. 执行 Docker build。
4. 执行 Docker run，并按端口或检查脚本确认服务。
5. 导出镜像 tar。
6. 重新 import 后再次 run，确认 tar 可用。
7. 检查镜像平台必须为 `linux/amd64`。
8. 输出给 xlsx 使用的字段。

## 脚本入口

先生成 Docker 执行计划：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_build.py plan \
  --project-dir <题目目录> \
  --image-name <镜像名:tag> \
  --tar-path <输出.tar> \
  --port <host:container> \
  --output docker_plan.json
```

校验 artifacts：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_build.py validate-artifacts docker_plan.json
```

该脚本只生成计划和校验结构化结果，不自动执行 Docker。真实执行后的 `docker image inspect` 平台结果必须回写，且必须是 `linux/amd64`。

## 验证

- `docker build` 成功。
- `docker run` 成功并能访问预期端口或通过检查脚本。
- `docker export` 或项目要求的导出方式成功。
- `docker import` 后镜像仍可运行。
- 平台为 `linux/amd64`，Apple Silicon 本机不能只看命令成功。

## 停止条件

镜像 tag 规则、Hub 编号、平台导出规范、启动命令或端口不确定时，停止并给用户选择。
