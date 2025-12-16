#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from pathlib import Path
from collector.incidents import create_incident

ALLOWED_EVENT_TYPES = {"file_open", "exec"}
ALLOWED_SOURCES = {"stdin", "ebpf"}

DEFAULT_OUTFILE = "alerts.jsonl"

incidents_base = Path.home() / "ghosttrail" / "incidents"
incidents_base.mkdir(parents=True, exist_ok=True)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")



def is_non_empty_str(x: Any) -> bool:
    return isinstance(x, str) and len(x.strip()) > 0


def is_int_like(x: Any) -> bool:
    return isinstance(x, int) and x >= 0


def parse_iso8601(ts: str) -> bool:
    """
    Best-effort timestamp validation:
    - Accepts ISO 8601 with Z (recommended) or offset
    """
    if not isinstance(ts, str):
        return False
    try:
        if ts.endswith("Z"):
            datetime.fromisoformat(ts.replace("Z", "+00:00"))
        else:
            datetime.fromisoformat(ts)
        return True
    except Exception:
        return False


@dataclass
class ValidationResult:
    ok: bool
    error: Optional[str] = None


def validate_event(evt: Dict[str, Any]) -> ValidationResult:
    # Required fields
    required = ["ts", "event_type", "pid", "ppid", "uid", "comm", "exe", "target", "source"]
    for k in required:
        if k not in evt:
            return ValidationResult(False, f"Missing required field: {k}")

    # ts
    if not parse_iso8601(evt["ts"]):
        return ValidationResult(False, "Invalid ts: must be ISO 8601 string (recommended: ...Z)")

    # event_type
    if evt["event_type"] not in ALLOWED_EVENT_TYPES:
        return ValidationResult(False, f"Invalid event_type: must be one of {sorted(ALLOWED_EVENT_TYPES)}")

    # pid, ppid, uid
    for k in ["pid", "ppid", "uid"]:
        if not is_int_like(evt[k]):
            return ValidationResult(False, f"Invalid {k}: must be a non-negative integer")

    # comm, exe, target
    for k in ["comm", "exe", "target"]:
        if not is_non_empty_str(evt[k]):
            return ValidationResult(False, f"Invalid {k}: must be a non-empty string")

    # source
    if evt["source"] not in ALLOWED_SOURCES:
        return ValidationResult(False, f"Invalid source: must be one of {sorted(ALLOWED_SOURCES)}")

    # Optional fields (validate if present)
    if "tags" in evt and not isinstance(evt["tags"], list):
        return ValidationResult(False, "Invalid tags: must be a list if present")
    if "meta" in evt and not isinstance(evt["meta"], dict):
        return ValidationResult(False, "Invalid meta: must be an object/dict if present")

    return ValidationResult(True)


def normalize_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalization rule: If fields are missing in early testing, we can fill safely.
    In production (later), eBPF feed should already include these.
    """
    evt = dict(raw)

    if "ts" not in evt or not is_non_empty_str(evt.get("ts")):
        evt["ts"] = utc_now_iso()
    if "source" not in evt or not is_non_empty_str(evt.get("source")):
        evt["source"] = "stdin"

    return evt


def summarize(evt: Dict[str, Any]) -> str:
    et = evt["event_type"]
    pid = evt["pid"]
    ppid = evt["ppid"]
    uid = evt["uid"]
    comm = evt["comm"]
    target = evt["target"]

    if et == "file_open":
        return f"[{evt['ts']}] FILE pid={pid} ppid={ppid} uid={uid} comm={comm} -> {target}"
    if et == "exec":
        return f"[{evt['ts']}] EXEC pid={pid} ppid={ppid} uid={uid} comm={comm} -> {target}"
    return f"[{evt['ts']}] {et} pid={pid} comm={comm} -> {target}"


def main() -> int:
    outfile = os.environ.get("GHOSTTRAIL_OUTFILE", DEFAULT_OUTFILE)

    # Open in append mode so you can run multiple times
    try:
        out = open(outfile, "a", encoding="utf-8")
    except Exception as e:
        print(f"ERROR: Could not open output file '{outfile}': {e}", file=sys.stderr)
        return 2

    good = 0
    bad = 0

    print(f"GhostTrail collector started. Writing valid events to: {outfile}", file=sys.stderr)
    print("Send newline-delimited JSON events to STDIN. Ctrl+C to stop.", file=sys.stderr)

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                raw = json.loads(line)
                if not isinstance(raw, dict):
                    raise ValueError("Top-level JSON must be an object")
            except Exception as e:
                bad += 1
                print(f"DROP (bad json): {e} | line={line[:200]}", file=sys.stderr)
                continue

            evt = normalize_event(raw)
            vr = validate_event(evt)
            if not vr.ok:
                bad += 1
                print(f"DROP (schema): {vr.error} | evt={evt}", file=sys.stderr)
                continue

            out.write(json.dumps(evt, ensure_ascii=False) + "\n")
            out.flush()
            good += 1
            print(summarize(evt))

            if evt["event_type"] == "file_open":
                inc_dir = create_incident(evt, incidents_base)
                print(f"[INCIDENTS] created {inc_dir}")


    except KeyboardInterrupt:
        pass
    finally:
        out.close()

    print(f"Stopped. accepted={good} dropped={bad}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
