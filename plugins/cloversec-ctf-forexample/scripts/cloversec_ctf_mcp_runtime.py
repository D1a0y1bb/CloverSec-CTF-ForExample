#!/usr/bin/env python3
"""Persistent runtime records for CloverSec CTF stdio MCP servers."""

from __future__ import annotations

import json
import os
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


SCHEMA_VERSION = "cloversec.ctf.mcp_runtime.v1"
DEFAULT_STATE_DIR = Path.home() / ".codex" / "cloversec-ctf-forexample" / "mcp-runtime"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def state_dir() -> Path:
    override = os.environ.get("CLOVERSEC_CTF_MCP_STATE_DIR", "").strip()
    return Path(override).expanduser() if override else DEFAULT_STATE_DIR


def runtime_log_path(server_name: str) -> Path:
    safe_name = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in server_name).strip(".-") or "server"
    return state_dir() / f"{safe_name}.jsonl"


def record_tool_call(
    *,
    server_name: str,
    request_id: Any,
    tool_name: str,
    arguments: dict[str, Any],
    handler: Callable[[], Any],
) -> Any:
    started = time.monotonic()
    started_at = utc_now()
    try:
        result = handler()
    except Exception as exc:  # noqa: BLE001 - MCP callers still receive JSON-RPC errors from the server.
        append_runtime_record(
            server_name,
            {
                "schema_version": SCHEMA_VERSION,
                "server": server_name,
                "request_id": request_id,
                "tool": tool_name,
                "status": "error",
                "started_at": started_at,
                "finished_at": utc_now(),
                "duration_ms": int((time.monotonic() - started) * 1000),
                "argument_summary": summarize_arguments(arguments),
                "error": str(exc),
                "traceback": traceback.format_exc(limit=5),
            },
        )
        raise
    append_runtime_record(
        server_name,
        {
            "schema_version": SCHEMA_VERSION,
            "server": server_name,
            "request_id": request_id,
            "tool": tool_name,
            "status": "ok",
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "argument_summary": summarize_arguments(arguments),
            "result_summary": summarize_result(result),
        },
    )
    return result


def append_runtime_record(server_name: str, record: dict[str, Any]) -> None:
    path = runtime_log_path(server_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with file_lock(lock_path):
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


@contextmanager
def file_lock(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = None
    deadline = time.monotonic() + 10
    while fd is None:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            if time.monotonic() >= deadline:
                stale_age = time.time() - lock_path.stat().st_mtime if lock_path.exists() else 0
                if stale_age > 30:
                    try:
                        lock_path.unlink()
                    except FileNotFoundError:
                        pass
                    continue
                raise TimeoutError(f"timeout waiting for MCP runtime lock: {lock_path}")
            time.sleep(0.05)
    try:
        os.write(fd, str(os.getpid()).encode("utf-8"))
        yield
    finally:
        if fd is not None:
            os.close(fd)
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def summarize_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key, value in (arguments or {}).items():
        if looks_secret_key(str(key)):
            summary[key] = "***"
        elif isinstance(value, (str, int, float, bool)) or value is None:
            summary[key] = value if len(str(value)) <= 200 else str(value)[:200] + "..."
        elif isinstance(value, list):
            summary[key] = {"type": "list", "length": len(value)}
        elif isinstance(value, dict):
            summary[key] = {"type": "object", "keys": sorted(str(item) for item in value.keys())[:20]}
        else:
            summary[key] = {"type": type(value).__name__}
    return summary


def summarize_result(result: Any) -> dict[str, Any]:
    if isinstance(result, dict):
        output = {
            "type": "object",
            "keys": sorted(str(item) for item in result.keys())[:30],
        }
        for key in ["schema_version", "status", "workdir", "output_dir", "summary"]:
            if key in result:
                output[key] = result[key]
        return output
    if isinstance(result, list):
        return {"type": "list", "length": len(result)}
    return {"type": type(result).__name__}


def looks_secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(token in lowered for token in ["token", "cookie", "password", "secret", "session", "authorization"])

