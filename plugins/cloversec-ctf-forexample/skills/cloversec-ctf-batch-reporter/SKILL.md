---
name: cloversec-ctf-batch-reporter
description: Generate CloverSec CTF batch reports, confirmation requests, failure cases, and stage notifications. Use when the user asks for batch status by event/year/category, missing resources, human confirmation items, archive readiness, failure history, or handoff reports.
---

# CloverSec CTF Batch Reporter

Use this skill for batch progress, handoff, and audit reports across many CTF cases.

## Inputs

- `ctf_cases.jsonl`.
- Optional `workflow_state.json`.
- Optional failure records from search, download, Docker, Hub, or manual review.

## Required Behavior

- Report by event, year, category, validation status, archive status, missing resources, and pending human actions.
- Generate human confirmation requests before risky stages: download, extract, Docker, Hub, retag, archive, final.
- Record failures in `failure_cases.jsonl` with stage, category, message, evidence path, retryable flag, and suggested next action.
- Generate short stage notifications for handoff.
- For multi-agent work, use `../../references/agent-roles.json` and keep each role's input/output files explicit.
- Do not hide failed or unverified items.

## Tooling

Common commands:

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py batch-report \
  --cases ctf_cases.jsonl \
  --output-dir reports/batch

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py confirmation \
  --action hub \
  --case-json ctf_case.json \
  --output-dir confirmations/hub

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_audit.py failure-library \
  --cases ctf_cases.jsonl \
  --output failure_cases.jsonl
```

MCP tool IDs:

- `cloversec_ctf_batch_status_report`
- `cloversec_ctf_failure_cases`
- `cloversec_ctf_confirmation_request`
- `cloversec_ctf_stage_notification`
- `cloversec_ctf_codex_warning_report`

Exact skill ID:

- `cloversec-ctf-batch-reporter`

## Outputs

- `batch_status_report.json`
- `batch_status_report.md`
- `batch_status_report.xlsx`
- `confirmation_request.json`
- `failure_cases.jsonl`
- `stage_notification.json`
