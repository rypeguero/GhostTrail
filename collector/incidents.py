
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict

from collector.lineage import build_lineage, lineage_to_dot, lineage_to_text


def create_incident(evt: Dict, base_dir: Path) -> Path:
    """
    Create an incident folder for a file_open event.
    Writes:
      - incident.json
      - lineage.txt
      - lineage.dot
    """
    ts = time.strftime("%Y%m%d-%H%M%S")
    inc_dir = base_dir / ts
    inc_dir.mkdir(parents=True, exist_ok=True)

    # Write the triggering event
    (inc_dir / "incident.json").write_text(
        json.dumps(evt, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # Build lineage from the triggering PID
    pid = int(evt.get("pid", 0))
    chain = build_lineage(pid)

    (inc_dir / "lineage.txt").write_text(
        lineage_to_text(chain),
        encoding="utf-8",
    )
    (inc_dir / "lineage.dot").write_text(
        lineage_to_dot(chain),
        encoding="utf-8",
    )

    return inc_dir
