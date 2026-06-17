#!/usr/bin/env python3
"""Small message catalog helper for user-visible CloverSec CTF text."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
PLUGIN_ROOT = SCRIPT_DIR.parent
DEFAULT_CATALOG = PLUGIN_ROOT / "references" / "i18n.zh-CN.json"


@lru_cache(maxsize=8)
def load_catalog(path: str = "") -> dict[str, str]:
    catalog_path = Path(path) if path else DEFAULT_CATALOG
    payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    messages = payload.get("messages") if isinstance(payload, dict) else {}
    return {str(key): str(value) for key, value in messages.items()} if isinstance(messages, dict) else {}


def text(key: str, **values: Any) -> str:
    template = load_catalog().get(key, key)
    try:
        return template.format(**values)
    except Exception:  # noqa: BLE001 - formatting failures should still show the key.
        return template


if __name__ == "__main__":
    print(json.dumps(load_catalog(), ensure_ascii=False, indent=2))
