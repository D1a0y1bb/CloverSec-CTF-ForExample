#!/usr/bin/env python3
"""Repository wrapper for the plugin doctor."""

from __future__ import annotations

import sys
from pathlib import Path


PLUGIN_SCRIPTS = Path(__file__).resolve().parents[1] / "plugins" / "cloversec-ctf-forexample" / "scripts"
sys.path.insert(0, str(PLUGIN_SCRIPTS))

from cloversec_ctf_doctor import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
