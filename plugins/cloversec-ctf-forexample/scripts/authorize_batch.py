#!/usr/bin/env python3
"""Create a scoped batch authorization record for installed plugin workflows."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import cloversec_ctf_i18n as i18n


ALLOWED_ACTIONS = {
    "docker_all",
    "docker_build",
    "docker_load",
    "docker_inspect",
    "docker_run_probe",
    "docker_save",
    "download_accept",
    "archive",
    "quality_review",
}
FORBIDDEN_ACTIONS = {"hub_final_submit"}


def create_authorization(
    *,
    workdir: str | Path,
    action: str,
    case_ids: list[str],
    expires_minutes: int,
    note: str,
) -> dict[str, Any]:
    if action in FORBIDDEN_ACTIONS:
        raise SystemExit(i18n.text("hub.final_submit_batch_forbidden"))
    if action not in ALLOWED_ACTIONS:
        raise SystemExit(i18n.text("batch.unsupported_action", action=action))
    root = Path(workdir)
    root.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = {
        "schema_version": "cloversec.ctf.batch_authorization.v1",
        "authorization_id": f"auth-{now.strftime('%Y%m%d%H%M%S')}-{action}",
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=max(expires_minutes, 1))).isoformat(),
        "action": action,
        "case_ids": case_ids,
        "scope": "listed_cases" if case_ids else "all_cases_in_workdir",
        "note": note,
        "limits": {
            "hub_final_submit": "not_allowed",
        },
    }
    auth_dir = root / "authorizations"
    auth_dir.mkdir(parents=True, exist_ok=True)
    auth_path = auth_dir / f"{payload['authorization_id']}.json"
    auth_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    state_path = root / "workflow_state.json"
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state.setdefault("authorizations", [])
        state["authorizations"].append({k: payload[k] for k in ["authorization_id", "action", "case_ids", "scope", "expires_at"]})
        state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    payload["authorization_path"] = auth_path.as_posix()
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Create CloverSec CTF batch authorization")
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--expires-minutes", type=int, default=120)
    parser.add_argument("--note", default="")
    args = parser.parse_args()
    payload = create_authorization(
        workdir=args.workdir,
        action=args.action,
        case_ids=args.case_id,
        expires_minutes=args.expires_minutes,
        note=args.note,
    )
    print(json.dumps({"authorization_path": payload["authorization_path"], "action": payload["action"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
