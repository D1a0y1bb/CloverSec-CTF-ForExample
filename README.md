<p align="center">
  <img src="plugins/cloversec-ctf-forexample/assets/app-icon.png" width="112" alt="CloverSec CTF For Example" />
</p>

<h1 align="center">CloverSec CTF For Example</h1>

<p align="center">
  The CloverSec competition-work Codex plugin, built for the recurring grind of the competition role —<br/>
  challenge collection, gap triage, standardized containerization, manual writing, archiving, and internal Hub submission.
</p>

<p align="center">
  <a href="https://github.com/D1a0y1bb/CloverSec-CTF-ForExample/releases"><img alt="Version" src="https://img.shields.io/badge/version-v1.1.4-2563eb"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-22c55e"></a>
  <img alt="Codex Plugin" src="https://img.shields.io/badge/Codex-Plugin-111827">
  <img alt="Skills" src="https://img.shields.io/badge/skills-15-f59e0b">
  <img alt="MCP" src="https://img.shields.io/badge/MCP%20servers-8-8b5cf6">
</p>

<p align="center">
  <b>English</b>&nbsp;&nbsp;·&nbsp;&nbsp;<a href="README.zh-CN.md">简体中文</a>
</p>

---

## Overview

**CloverSec CTF For Example** is a Codex plugin built by the CloverSec Security AI Lab for competition work — it tackles the slowest, most repetitive part of CTF challenge prep (and competition work in general): finding source and writeups, sorting attachments, turning source into platform containers, writing Chinese solution manuals, archiving, quality-checking, and getting everything ready right up to the Hub submit button.

It isn't one command. It's a set of skills, scripts, and MCP servers that Codex reaches for as the task demands. You state the goal — say, *"collect the Web challenges, writeups, and attachment leads from 2025 IrisCTF"* — and Codex routes through search, download preview, resource classification, Dockerizer handoff, manual writing, archiving, quality review, and Hub prep on its own.

Judgment stays with you where it matters. Running an unknown Docker image, the final Hub submit, an ambiguous category, missing material, a platform-incompatible challenge — each of these stops and waits for you instead of guessing.

## Quick start

In the Codex plugin page, choose **Add plugin marketplace**:

```text
Source:    D1a0y1bb/CloverSec-CTF-ForExample
Git ref:   v1.1.4
Sparse path: (leave empty)
```

Or from the command line:

```bash
codex plugin marketplace add D1a0y1bb/CloverSec-CTF-ForExample --ref v1.1.4
codex plugin add cloversec-ctf-forexample@cloversec-ctf
```

After installing (or updating), open a fresh Codex session and just describe the goal:

```text
Using CloverSec CTF For Example, collect the Web challenges, writeups,
and attachment leads from 2025 IrisCTF.
```

```text
From this ctf_cases.jsonl, sort the attachments, source, and writeups,
decide which challenges need the Dockerizer, and produce a Chinese deliverable.
```

## Setup

| Item | Required? | Why |
| --- | --- | --- |
| `gh auth login` | Recommended | Steadier GitHub search, repo preview, and Release assets |
| Docker Desktop | For container challenges | build / run / inspect / save / load, amd64 checks |
| PyYAML | For containerization | Dockerizer parses `challenge.yaml`, `stacks.yaml`, template data |
| openpyxl | Recommended | Cleaner xlsx; basic xlsx still exports without it |
| Chrome signed in to Hub | For Hub assist | Drives the live page; never stores cookies, tokens, or passwords |
| A challenge dir or list | Recommended | `ctf_case.json`, `ctf_cases.jsonl`, xlsx, zip, or URL |

Install the Dockerizer dependencies:

```bash
pip install -r plugins/cloversec-ctf-forexample/skills/cloversec-ctf-build-dockerizer/scripts/requirements.txt
```

Check what your machine can do:

```bash
python3 scripts/doctor.py
```

## What to ask for

| Say something like | What the plugin usually does | Main output |
| --- | --- | --- |
| *Collect the Web challenges, WPs, and attachment leads from 2024 LA CTF* | Searches public sources, builds a challenge list, Chinese collection sheet, and evidence | `search_results.json`, `ctf_cases.jsonl`, `赛事题目信息收集表.xlsx` |
| *From this ctf_cases.jsonl, gather attachments and writeups* | Download preview, GitHub Release/tree preview, records hashes and failure reasons | `downloads_sandbox/`, `material_candidates.json` |
| *Tell me how to handle this challenge directory* | Classifies Docker / compose / source / attachment / writeup, with a Chinese next-step suggestion | `resource_classification.json`, `资源整理与处理建议表.xlsx`, `Dockerizer交接表.xlsx` |
| *Turn this source challenge into a platform container* | Hands off to `cloversec-ctf-build-dockerizer` for platform conversion | `Dockerfile`, `start.sh`, `changeflag.sh`, `flag` |
| *Check and archive this attachment challenge* | Inspects the archive, hashes, extraction, path risk | `attachment_manifest.json` |
| *Write the manual and Hub fields from this directory* | Generates the formal Chinese manual, Hub fields, xlsx fields | `题目解题手册.md`, `hub_fields.json`, `xlsx_fields.json` |
| *Prepare the Hub submission* | Builds fields, upload list, Chrome fill plan — stops before the final submit | `hub_upload_manifest.json`, `hub_session_state.json` |
| *Produce the final deliverable* | Assembles the Chinese folders, final sheets, Yuque table, quality report | `交付说明.md`, `最终归档表.xlsx`, `语雀粘贴表.md` |

## Running a full batch

To take a whole batch end to end, hand Codex a task like this:

```text
Using CloverSec CTF For Example, process 10 public 2026 CTF challenges end to end.
Requirements:
1. Create the working directory and a task plan first.
2. Collect candidates, source evidence, writeups, attachment and source leads.
3. Only write challenges with a clear source and a confirmable year/category into ctf_cases.jsonl.
4. Download into downloads_sandbox first — hash, size, archive preview, risk checks.
5. Produce a resource_classification.json per challenge.
6. Source challenges, Dockerfiles, compose, image tars, and Web/Pwn service challenges must go through cloversec-ctf-build-dockerizer.
7. Attachment challenges go through attachment checks and archiving.
8. Produce the formal Chinese manual, Hub fields, xlsx fields, archive layout, quality review, and final deliverable.
9. Stop and wait for me before any Docker run, final Hub submit, or image retag.
```

Resume after an interruption:

```text
Continue the runs/xxxxxxxxx working directory, picking up the unfinished
stages from workflow_state.json.
```

Check progress:

```bash
python3 scripts/show_progress.py runs/xxxxxxxxx/workflow_state.json
python3 scripts/show_progress.py runs/xxxxxxxxx/workflow_state.json --watch
python3 scripts/show_progress.py runs/xxxxxxxxx/workflow_state.json --table
```

The default output is a Chinese progress report meant for a human to read; `--json` is for scripts and agents, and `--table` keeps the old compact view for debugging stage state. If all you have is the installed plugin directory, run `python3 scripts/show_progress.py workflow_state.json` from inside it.

<details>
<summary><b>Advanced — drive the stages directly</b></summary>

Run safe stages over existing material with the workflow engine:

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_workflow.py run \
  --workdir runs/xxxxxxxxx \
  --stage research \
  --stage collect \
  --stage dedupe \
  --stage download_preview \
  --stage archive \
  --stage quality \
  --stage final_report
```

Authorize a Docker batch over an explicit scope. The authorization is written into the working directory; the Docker executor reads it, and without it no real Docker action runs:

```bash
python3 scripts/authorize_batch.py --workdir runs/xxxxxxxxx --action docker_build --case-id case-001 --case-id case-002
```

Verify search quality. The report stays in `docs/validation/` and never ships in a release:

```bash
python3 scripts/search_recall_benchmark.py \
  --run-search \
  --benchmark plugins/cloversec-ctf-forexample/references/search-recall-benchmark.json \
  --input-dir docs/validation/search-recall-v1.1.4 \
  --output docs/validation/search-recall-benchmark-v1.1.4.md \
  --json-output docs/validation/search-recall-benchmark-v1.1.4.json
```

This benchmark doesn't check whether a keyword appeared — it checks whether a public resource that a human confirmed exists was actually found. It currently covers XDSEC miniLCTF, USTC Hackergame, HGAME, IrisCTF, LA CTF, and Google CTF, scoring recall by normalized GitHub repo / URL hits.

</details>

## Capabilities

| Capability | What it does |
| --- | --- |
| Workflow intake | Builds the task directory, search plan, and state file from year / event / category / count |
| Research intake | Multi-source search, agent web-search import, browser-visible result import |
| Handoff tables | Chinese xlsx + JSONL + schema — readable by people, resumable by the agent |
| Asset collection | Download preview, GitHub Release/tree preview, hashes, failure reasons |
| Resource classifier | Identifies source, Dockerfile, compose, attachment, writeup, screenshot, binary, pcap |
| Container validator | Extracts ports, start command, Flag path, Dockerizer handoff info |
| Dockerizer | The user-verified skill for CloverSec-platform container conversion |
| Writeup scaffold | The user-verified skill for the Chinese manual and field generation |
| Archive packager | Builds the Chinese archive layout, manifest, resource index |
| Quality review | Checks resources, manual, Flag, archive, and Docker-evidence state |
| Hub submission | Builds the Hub draft, upload list, browser fill plan — stops before final submit |
| Hub retag | After approval, generates the image tag and export plan from the official `HUB编号` |
| Final report | Produces the final xlsx, Yuque table, report, and open issues |

## Sheets for people, data for the agent

Every handoff stage emits both a sheet a human can read and the structured data the agent keeps working from. Same record, two views.

| Stage | For people | For the agent | Point |
| --- | --- | --- | --- |
| Collection | `赛事题目信息收集表.xlsx` | `赛事题目信息收集表.jsonl`, `ctf_cases.jsonl` | What's workable, what's missing, what's next |
| Resource ID | `资源整理与处理建议表.xlsx` | `资源整理与处理建议表.jsonl` | Source, attachment, WP, screenshot, or unknown |
| Dockerizer handoff | `Dockerizer交接表.xlsx` | `Dockerizer交接表.jsonl` | Which challenges enter the Dockerizer |

An existing Dockerfile or compose file is a migration input only — never a finished CloverSec-platform deliverable on its own.

## Resource rules

| Situation | How it's handled |
| --- | --- |
| Only a title, platform page, or WP | Treated as a lead — logged as missing material, not written up as deliverable |
| Only an attachment zip/tar | Attachment check, manual, archive, quality review |
| Source but no Dockerfile | Must enter the Dockerizer to produce a platform deliverable |
| Source plus an upstream Dockerfile/compose | Upstream files are migration input only — still must enter the Dockerizer |
| Only an image tar | Can inspect/hash, but not counted as a platform deliverable |
| Pwn jail, kernel, eBPF, QEMU, high-privilege | Platform differences and run conditions logged — never assumed passing |

A container challenge must end up satisfying `/start.sh`, `/changeflag.sh`, `/flag`, the port, linux/amd64, the image tar, and the internal xlsx fields. A bare `docker build/run` counts only as verification evidence — it does not replace Dockerizer platform conversion.

## Under the hood

- User-facing strings live in `plugins/cloversec-ctf-forexample/references/i18n.zh-CN.json` — swap this catalog first if an English build comes later.
- HTTP requests (search, download preview, port probing) all go through `cloversec_ctf_http.py`, so timeouts, retries, and redirects are handled in one place rather than re-invented per script.
- MCP tool calls are logged to a local runtime dir — `~/.codex/cloversec-ctf-forexample/mcp-runtime/` by default — to trace which tool failed in a batch.
- `cloversec_ctf_workflow.py run` writes `workflow_engine_run.json`, `logs/workflow_engine.jsonl`, and `当前状态.md`, so an interrupted batch can resume in the same directory.
- The final Hub submit can't be pre-authorized in bulk — it always needs a human.

## References

- [Workflow](plugins/cloversec-ctf-forexample/references/workflow.md)
- [Data model](plugins/cloversec-ctf-forexample/references/data-model.md)
- [Research & search](plugins/cloversec-ctf-forexample/references/research-intake.md)
- [Asset collection](plugins/cloversec-ctf-forexample/references/asset-collector.md)
- [Hub submission](plugins/cloversec-ctf-forexample/references/hub-submission.md)
- [Scripts](plugins/cloversec-ctf-forexample/scripts/README.md)

## Development

```bash
python3 scripts/validate_release.py
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/package_plugin_release.py
```

Codex users can additionally validate against the local plugin-creator (`validate_plugin.py` under `~/.codex/skills/.system/plugin-creator/`). Bump the version with `scripts/bump_version.py` before a release; the Release title is the tag (e.g. `v1.1.4`) and the body's first line is `# CloverSec CTF For Example 1.1.4`.

## License

MIT © D1a0y1bb - CloverSec Security
