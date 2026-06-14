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
    "requires_manual_review": false
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
