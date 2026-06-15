---
name: cloversec-ctf-container-validator
description: CloverSec CTF 容器题识别与验证分级 skill。用于从 Dockerfile、compose、README、challenge manifest 和资源分类结果生成 container_inference.json，选择 static_only/inspect_only/build_only/run_probe/solve_verify 验证等级，并准备 proof 证据包。
---

# CloverSec CTF Container Validator

## 何时使用

- 用户给了题目目录，需要判断它是不是容器题、compose 项目、镜像 tar 交付或非容器附件题。
- 已经有 `resource_classification.json`，需要提取 Dockerfile、compose、端口、启动命令和验证等级。
- 质量检查前需要明确 Docker 应该验证到哪一步。
- 需要把资源识别、容器推断、Docker evidence 和质量检查结果整理为 `proof/` 证据包。

## 默认行为

1. 只做静态读取：Dockerfile、compose、README、challenge manifest、已有资源分类 JSON。
2. 不执行未知脚本，不启动 Docker，不运行解题脚本。
3. 输出 `container_inference.json`，包含项目类型、置信度、端口、镜像名建议、验证等级、warnings 和 next_actions。
4. Docker 验证等级只给建议。真实执行 `build/run/logs/stop/save` 前必须有用户明确授权。
5. `solve_verify` 只表示需要按手册验证解题，不自动执行未知 solver。

## 平台交付规则

- Dockerfile、compose、README 里的 `docker build/run` 命令只用于推断运行时和生成验证证据。
- 上游 Dockerfile 或 compose 不能直接作为 CloverSec 平台最终交付。
- 容器题最终必须进入 `cloversec-ctf-build-dockerizer`，生成或校验 `/start.sh`、`/changeflag.sh`、`/flag`、端口、amd64、镜像 tar 和 xlsx 字段。
- `cloversec-ctf-docker` 的 build/run/probe 结果只能证明上游环境能否启动，不能替代 Dockerizer 的平台契约。
- 需要 `--privileged`、capability、KVM、eBPF/tc、宿主目录挂载或内网访问时，必须写入 warnings，并等待单独确认。
- 没有 Dockerizer 方案确认或 `platform_contract_verified=true` 证据时，容器题只能标 `Dockerizer 改造待确认`，不能写成可归档。
- 输出机器字段时必须使用精确值：`confirmation_action=dockerizer`、`failure_category=platform_conversion_required`、`next_skill=cloversec-ctf-build-dockerizer`、`can_archive=false`。

## 平台契约摘要

- 只要涉及题目镜像构建、源码服务、Dockerfile、compose、镜像 tar、端口服务或 Web/Pwn 在线服务，最终平台交付必须经过 `cloversec-ctf-build-dockerizer`。
- 上游 Dockerfile、compose 和原始镜像只能用于推断端口、依赖、启动命令和风险，不能直接进入最终交付。
- Dockerizer 方案未确认时，容器验证只能输出证据和待确认项，不能把题目写成可归档。
- 平台交付证据至少覆盖：`Dockerfile`、`start.sh`、`changeflag.sh`、`flag`、`environment`、`docker_artifacts`、`xlsx_fields`、`linux/amd64`、端口一致性。
- `cloversec-ctf-docker` 的 build/run/probe 结果只能说明环境启动情况，不替代 Dockerizer 平台改造。
- Docker 验证状态必须拆开写：契约通过、镜像构建/导入通过、服务启动通过、题目可解通过。端口或 health 检查通过，只能说明服务启动，不代表解题通过。

## 常用命令

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_container.py infer \
  path/to/challenge \
  --resource-classification resource_classification.json \
  --output container_inference.json
```

生成 Docker 验证计划：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_docker.py plan \
  --container-inference container_inference.json \
  --validation-level run_probe \
  --image-name cloversec/example:local \
  --output docker_validation_plan.json
```

生成 proof 证据包：

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_proof.py \
  --output-dir proof \
  --case-json ctf_case.json \
  --resource-classification resource_classification.json \
  --container-inference container_inference.json \
  --docker-evidence docker_evidence.json \
  --quality-review quality_review.json
```

## MCP Tools

- `cloversec_ctf_container_infer`
- `cloversec_ctf_docker_validation_plan`
- `cloversec_ctf_proof_pack`

## 验证等级

```json
{
  "static_only": "只读文件和 JSON，不执行 Docker",
  "inspect_only": "只 load/inspect 已有镜像或镜像 tar",
  "build_only": "docker build --platform linux/amd64 后 inspect",
  "run_probe": "build/inspect/run/logs/stop，并对端口或 probe URL 检查",
  "solve_verify": "需要人工确认后按手册验证解题，不自动执行未知 solver"
}
```

## 输出字段

```json
{
  "schema_version": "cloversec.ctf.container_inference.v1",
  "summary": {
    "project_type": "container_project",
    "confidence": "high",
    "ports": ["18080:80"],
    "recommended_validation_level": "run_probe",
    "platform_contract_required": true,
    "must_use_dockerizer": true,
    "requires_manual_review": false
  },
  "platform_delivery": {
    "status": "requires_cloversec_contract",
    "existing_docker_is_reference_only": true,
    "final_delivery_skill": "cloversec-ctf-build-dockerizer",
    "confirmation_action": "dockerizer",
    "blocking_until_confirmed": true
  },
  "runtime": {
    "image_name": "cloversec/example:local",
    "build_context": "path/to/challenge",
    "dockerfile": "Dockerfile",
    "ports": ["18080:80"],
    "probe_urls": ["http://127.0.0.1:18080/"]
  },
  "warnings": [],
  "next_actions": []
}
```

## 停止条件

- `warnings` 非空时，不直接执行 Docker，先把风险讲清楚。
- 需要执行 `docker run`、上传 Hub、运行未知 solver、访问内网服务或读取浏览器凭证时，必须等用户确认。
- 题目类型低置信度时，不把它强行当成容器题。
- 只生成了 `container_inference.json` 或 `docker_validation_plan.json` 时，不能说平台交付已完成；还需要 Dockerizer 产物和质量检查证据。
- 如果出现 Pasteboard 构建断连、eBPF/tc 不适配 Docker Desktop、jail/seccomp 失败、solver 断开等题目级问题，先生成 Dockerizer 改造确认请求，让用户选择改造、降级验收或剔除。
