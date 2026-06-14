---
name: cloversec-ctf-manual-quality
description: Check CloverSec CTF manual quality before review or Hub preparation. Use when the user asks to verify a writeup/manual, compare ctf_case.json with hub_fields.json, confirm screenshots/attachments, keep the full Flag in xlsx fields, or decide whether a manual is ready for Hub draft generation.
---

# CloverSec CTF Manual Quality

Use this skill when a challenge already has a manual draft, `ctf_case.json`, or `hub_fields.json`, and the next step is review or Hub preparation.

## Inputs

- `ctf_case.json` or a case object.
- Manual Markdown, usually `manual_filled_draft.md`.
- Optional `hub_fields.json`.
- Optional archive/resource manifest.

## Required Behavior

- Check title, category, challenge type, Flag type, full Flag, description, knowledge points, environment, solve steps, screenshots, attachments, and Hub field consistency.
- Keep the complete Flag in structured `xlsx_fields_patch.json`.
- Do not print the complete Flag in prose reports unless the user explicitly asks for the xlsx fields.
- Treat missing Hub classify ID, missing upload result, missing screenshot, or mismatched category as review items.
- Do not submit anything to Hub.

## Tooling

Prefer the script or MCP tool:

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_manual_quality.py \
  --case-json ctf_case.json \
  --manual manual_filled_draft.md \
  --hub-fields hub_fields.json \
  --output-dir manual_quality
```

MCP tool ID:

- `cloversec_ctf_manual_quality`

Exact skill ID:

- `cloversec-ctf-manual-quality`

## Outputs

- `manual_quality.json`
- `manual_quality_report.md`
- `xlsx_fields_patch.json`

If any required field is missing, mark the status as needing human review and list the exact missing item.
