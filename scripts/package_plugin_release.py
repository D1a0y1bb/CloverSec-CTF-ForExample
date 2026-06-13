#!/usr/bin/env python3
"""Create release artifacts for the CloverSec CTF Codex plugin."""

from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_NAME = "cloversec-ctf-forexample"
PLUGIN = ROOT / "plugins" / PLUGIN_NAME
DIST = ROOT / "dist"


def main() -> int:
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
    notes.write_text(
        "\n".join(
            [
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
        ),
        encoding="utf-8",
    )

    shutil.make_archive(str(DIST / archive_base), "gztar", root_dir=PLUGIN.parent, base_dir=PLUGIN_NAME)
    print(f"created release artifacts in {DIST}")
    return 0


def zip_dir(source: Path, output: Path, *, prefix: str | Path) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        add_dir(archive, source, prefix=Path(prefix))


def add_dir(archive: zipfile.ZipFile, source: Path, *, prefix: Path) -> None:
    for path in sorted(source.rglob("*")):
        if path.is_file():
            relative = prefix / path.relative_to(source)
            archive.write(path, relative.as_posix())


def add_file(archive: zipfile.ZipFile, path: Path) -> None:
    archive.write(path, path.relative_to(ROOT).as_posix())


if __name__ == "__main__":
    raise SystemExit(main())
