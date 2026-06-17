#!/usr/bin/env python3
"""Update CloverSec CTF plugin version strings across release files."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_NAME = "cloversec-ctf-forexample"
PLUGIN = ROOT / "plugins" / PLUGIN_NAME
MANIFEST = PLUGIN / ".codex-plugin" / "plugin.json"
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")

TARGETS = [
    ROOT / "README.md",
    PLUGIN / ".codex-plugin" / "plugin.json",
    PLUGIN / "references" / "agent-roles.json",
    PLUGIN / "references" / "data-model.md",
    PLUGIN / "references" / "workflow.md",
]

TARGET_GLOBS = [
    ROOT / "scripts" / "*.py",
    PLUGIN / "scripts" / "*.py",
    ROOT / "tests" / "test_*.py",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Bump CloverSec CTF For Example plugin version")
    parser.add_argument("new_version", help="new semver, for example 0.3.5")
    parser.add_argument("--old-version", default="", help="old semver; defaults to plugin.json version")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    new_version = args.new_version.strip().removeprefix("v")
    if not SEMVER_RE.match(new_version):
        raise SystemExit(f"invalid semver: {args.new_version}")
    old_version = args.old_version.strip().removeprefix("v") or read_manifest_version()
    if not SEMVER_RE.match(old_version):
        raise SystemExit(f"invalid old semver: {old_version}")
    if old_version == new_version:
        print(f"version already {new_version}")
        return 0

    paths = collect_targets()
    changed: list[Path] = []
    for path in paths:
        if not path.is_file():
            continue
        original = path.read_text(encoding="utf-8")
        updated = original.replace(f"v{old_version}", f"v{new_version}")
        updated = updated.replace(old_version, new_version)
        if updated == original:
            continue
        changed.append(path)
        if not args.dry_run:
            path.write_text(updated, encoding="utf-8")

    print(f"{'would update' if args.dry_run else 'updated'} {len(changed)} file(s)")
    for path in changed:
        print(path.relative_to(ROOT).as_posix())
    return 0


def read_manifest_version() -> str:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    return str(data.get("version") or "")


def collect_targets() -> list[Path]:
    paths = list(TARGETS)
    for pattern in TARGET_GLOBS:
        paths.extend(sorted(pattern.parent.glob(pattern.name)))
    return sorted(set(paths))


if __name__ == "__main__":
    raise SystemExit(main())
