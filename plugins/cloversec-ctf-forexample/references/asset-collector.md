# Asset Collector Reference

## Scope

Collect challenge source, attachments, writeups, screenshots, hashes, and evidence from confirmed research results or user-provided materials. Do not build Docker images and do not write final manuals.

## Asset Records

Each record should include:

- `asset_type`
- `name`
- `source_url`
- `local_path`
- `sha256`
- `size`
- `license_or_notice`
- `status`
- `evidence`

## Collection Rules

- Separate GitHub repositories, GitHub Release assets, GitHub raw/blob files, CTFTime writeups, public archives, and direct attachment URLs.
- Automatically download only direct file URLs such as `.zip`, `.tar.gz`, `.pdf`, `.md`, and images.
- Record cloud drives, login pages, and dynamic pages as source leads unless the user provides credentials or files.
- Always compute SHA256 for downloaded/local files.
- Record HTTP 4xx/5xx, failed downloads, suspicious content types, and likely wrong-problem materials as issues.
- Preview zip/tar archives before archive handoff; report path traversal and file inventory.

## Commands

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-from-manifest \
  --manifest search_results.json \
  --output-dir downloads \
  --max-files 10 \
  --output asset_downloads.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py github-release-assets \
  --repo owner/repo \
  --output github_release_assets.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-github-release-assets \
  --repo owner/repo \
  --output-dir downloads \
  --max-files 10 \
  --output release_downloads.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-github-raw \
  https://github.com/owner/repo/blob/main/path/challenge.zip \
  --output-dir downloads \
  --output raw_download.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-github-tree \
  --repo owner/repo \
  --ref main \
  --path-prefix challenges \
  --output-dir downloads \
  --asset-only \
  --output tree_downloads.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py preview-archive \
  downloads/challenge.zip \
  --output archive_preview.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py asset-inventory <题目材料目录> asset_inventory.json
```

## Validation

- Local files must exist and hash successfully.
- Undownloaded remote materials must keep `source_url` and failure reason.
- Challenge/event names and asset names must be checked for mismatch risk.
- GitHub tree downloads preserve relative paths.
- Unsafe archive paths block direct archive delivery.

## Stop Conditions

Stop when collection requires account login, captcha, cloud-drive extraction code, copyright authorization, or large-scale download permission.
