#!/usr/bin/env python3
from __future__ import annotations

import os
import time
from pathlib import Path
from collector.lineage import build_lineage, lineage_to_dot, lineage_to_text


def main() -> int:
    pid = os.getpid()  # demo: show lineage of THIS python process
    ts = time.strftime("%Y%m%d-%H%M%S")
    outdir = Path.home() / "ghosttrail" / "incidents" / ts
    outdir.mkdir(parents=True, exist_ok=True)

    chain = build_lineage(pid)

    (outdir / "lineage.txt").write_text(lineage_to_text(chain), encoding="utf-8")
    (outdir / "lineage.dot").write_text(lineage_to_dot(chain), encoding="utf-8")

    print(f"Wrote: {outdir / 'lineage.txt'}")
    print(f"Wrote: {outdir / 'lineage.dot'}")
    print("\nPreview:")
    print((outdir / "lineage.txt").read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
