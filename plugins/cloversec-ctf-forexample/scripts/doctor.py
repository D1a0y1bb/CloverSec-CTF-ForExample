#!/usr/bin/env python3
"""Plugin-local doctor entrypoint."""

from __future__ import annotations

from cloversec_ctf_doctor import main


if __name__ == "__main__":
    raise SystemExit(main())
