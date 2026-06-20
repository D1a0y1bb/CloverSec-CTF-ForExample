#!/usr/bin/env python3
"""Create release artifacts for the CloverSec CTF Codex plugin."""

from __future__ import annotations

import json
import shutil
import tarfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_NAME = "cloversec-ctf-forexample"
PLUGIN = ROOT / "plugins" / PLUGIN_NAME
DIST = ROOT / "dist"
RELEASE_NOTES = ROOT / ".github" / "release-notes"
SKIP_DIR_NAMES = {"__pycache__", ".pytest_cache"}
SKIP_FILE_SUFFIXES = {".pyc", ".pyo"}
SKIP_FILE_NAMES = {".DS_Store"}


def main() -> int:
    clean_generated_files(PLUGIN)
    DIST.mkdir(exist_ok=True)
    for path in DIST.iterdir():
        if path.is_file():
            path.unlink()

    manifest = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
    version = manifest["version"]
    display_name = manifest.get("interface", {}).get("displayName", PLUGIN_NAME)
    archive_base = f"{PLUGIN_NAME}-{version}"

    plugin_zip = DIST / f"{archive_base}.zip"
    repo_zip = DIST / f"{archive_base}-repo-marketplace.zip"

    zip_dir(PLUGIN, plugin_zip, prefix=PLUGIN_NAME)
    with zipfile.ZipFile(repo_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        add_file(archive, ROOT / ".agents" / "plugins" / "marketplace.json")
        add_dir(archive, PLUGIN, prefix=Path("plugins") / PLUGIN_NAME)
        add_file(archive, ROOT / "README.md")

    notes = DIST / "release-notes.md"
    notes.write_text(render_release_notes(display_name, version), encoding="utf-8")

    tar_dir(PLUGIN, DIST / f"{archive_base}.tar.gz", prefix=PLUGIN_NAME)
    print(f"created release artifacts in {DIST}")
    return 0


def zip_dir(source: Path, output: Path, *, prefix: str | Path) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        add_dir(archive, source, prefix=Path(prefix))


def tar_dir(source: Path, output: Path, *, prefix: str | Path) -> None:
    with tarfile.open(output, "w:gz") as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file() and not should_skip(path):
                archive.add(path, arcname=(Path(prefix) / path.relative_to(source)).as_posix())


def add_dir(archive: zipfile.ZipFile, source: Path, *, prefix: Path) -> None:
    for path in sorted(source.rglob("*")):
        if path.is_file() and not should_skip(path):
            relative = prefix / path.relative_to(source)
            archive.write(path, relative.as_posix())


def add_file(archive: zipfile.ZipFile, path: Path) -> None:
    if should_skip(path):
        return
    archive.write(path, path.relative_to(ROOT).as_posix())


def clean_generated_files(root: Path) -> None:
    for directory in sorted(root.rglob("*"), reverse=True):
        if directory.is_dir() and directory.name in SKIP_DIR_NAMES:
            shutil.rmtree(directory)


def should_skip(path: Path) -> bool:
    if any(part in SKIP_DIR_NAMES for part in path.parts):
        return True
    if path.name in SKIP_FILE_NAMES:
        return True
    return path.suffix in SKIP_FILE_SUFFIXES


def render_release_notes(display_name: str, version: str) -> str:
    custom = RELEASE_NOTES / f"v{version}.md"
    if custom.is_file():
        return custom.read_text(encoding="utf-8")
    return "\n".join(
        [
            f"# {display_name} {version}",
            "",
            "Install as a Codex marketplace from GitHub:",
            "",
            "```bash",
            f"codex plugin marketplace add D1a0y1bb/CloverSec-CTF-ForExample --ref v{version}",
            "codex plugin add cloversec-ctf-forexample@cloversec-ctf",
            "```",
            "",
            "Release assets include a plugin-only zip and a repo-marketplace zip.",
            "",
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
