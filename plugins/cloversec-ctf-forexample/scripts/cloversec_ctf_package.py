#!/usr/bin/env python3
"""Attachment package inspection helpers for CloverSec CTF workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import cloversec_ctf_search as search


def inspect_attachment_package(path: str | Path) -> dict[str, Any]:
    package = Path(path)
    manifest = {
        "name": package.name,
        "path": package.as_posix(),
        "package_type": _package_type(package),
        "size": package.stat().st_size if package.exists() else 0,
        "sha256": sha256_file(package) if package.exists() else "",
        "can_extract": False,
        "entry_count": 0,
        "entries": [],
        "issues": [],
        "status": "missing" if not package.exists() else "unknown",
    }
    if not package.exists():
        manifest["issues"].append("file does not exist")
        return manifest

    try:
        if manifest["package_type"] == "zip":
            entries = _zip_entries(package)
        elif manifest["package_type"] in {"tar", "tar.gz"}:
            entries = _tar_entries(package)
        else:
            manifest["issues"].append("unsupported package type")
            manifest["status"] = "unsupported"
            return manifest
    except (zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
        manifest["issues"].append(f"cannot read package: {exc}")
        manifest["status"] = "broken"
        return manifest

    manifest["entries"] = entries
    manifest["entry_count"] = len(entries)
    unsafe = [entry["path"] for entry in entries if _is_unsafe_path(entry["path"])]
    if unsafe:
        manifest["issues"].extend(f"unsafe path: {item}" for item in unsafe)
        manifest["status"] = "unsafe"
        return manifest
    manifest["can_extract"] = True
    manifest["status"] = "ok"
    return manifest


def build_attachment_manifest(paths: list[str | Path]) -> dict[str, Any]:
    packages = [inspect_attachment_package(path) for path in paths]
    ok_count = sum(1 for item in packages if item["status"] == "ok")
    manifest = {
        "packages": packages,
        "summary": {
            "total_packages": len(packages),
            "ok_packages": ok_count,
            "problem_packages": len(packages) - ok_count,
        },
        "xlsx_fields": {
            "题目类型": "附件型",
            "材料状态": search.MATERIAL_STATUS_ASSET_ONLY if packages and ok_count == len(packages) else search.MATERIAL_STATUS_MISSING,
            "环境包/附件包路径": ";".join(item["path"] for item in packages),
        },
    }
    return manifest


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _zip_entries(path: Path) -> list[dict[str, Any]]:
    with zipfile.ZipFile(path) as archive:
        return [
            {
                "path": info.filename,
                "size": info.file_size,
                "compressed_size": info.compress_size,
                "is_dir": info.is_dir(),
            }
            for info in archive.infolist()
        ]


def _tar_entries(path: Path) -> list[dict[str, Any]]:
    with tarfile.open(path) as archive:
        return [
            {
                "path": member.name,
                "size": member.size,
                "compressed_size": "",
                "is_dir": member.isdir(),
            }
            for member in archive.getmembers()
        ]


def _package_type(path: Path) -> str:
    suffixes = [suffix.lower() for suffix in path.suffixes]
    if path.suffix.lower() == ".zip":
        return "zip"
    if path.suffix.lower() == ".tar":
        return "tar"
    if suffixes[-2:] == [".tar", ".gz"] or path.suffix.lower() == ".tgz":
        return "tar.gz"
    return "unknown"


def _is_unsafe_path(value: str) -> bool:
    path = Path(value)
    return path.is_absolute() or ".." in path.parts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloverSec CTF attachment package utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="inspect one attachment package")
    inspect_parser.add_argument("package")
    inspect_parser.add_argument("--output", required=True)

    manifest_parser = subparsers.add_parser("manifest", help="write manifest for one or more packages")
    manifest_parser.add_argument("packages", nargs="+")
    manifest_parser.add_argument("--output", required=True)

    args = parser.parse_args(argv)

    if args.command == "inspect":
        result = inspect_attachment_package(args.package)
    elif args.command == "manifest":
        result = build_attachment_manifest(args.packages)
    else:
        parser.error("unknown command")
        return 2

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
