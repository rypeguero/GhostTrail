#!/usr/bin/env python3
from __future__ import annotations

import os
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional


@dataclass
class ProcNode:
    pid: int
    ppid: int
    uid: int
    comm: str
    exe: str
    cmdline: str


def _read_text(path: str, max_bytes: int = 8192) -> str:
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _read_cmdline(pid: int) -> str:
    raw = _read_text(f"/proc/{pid}/cmdline", 16384)
    if not raw:
        return ""
    # cmdline is NUL-separated
    parts = [p for p in raw.split("\x00") if p]
    return " ".join(parts)


def _read_comm(pid: int) -> str:
    return _read_text(f"/proc/{pid}/comm", 1024).strip()


def _read_exe(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception:
        return ""


def _read_uid(pid: int) -> int:
    status = _read_text(f"/proc/{pid}/status", 16384)
    # Look for: Uid:    1000    1000    1000    1000
    for line in status.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    return -1


def _read_ppid(pid: int) -> int:
    """
    /proc/<pid>/stat: "pid (comm) state ppid ..."
    comm can contain spaces, but it's wrapped in parentheses.
    """
    stat = _read_text(f"/proc/{pid}/stat", 4096)
    if not stat:
        return -1

    try:
        rparen = stat.rfind(")")
        after = stat[rparen + 2 :]  # skip ") "
        fields = after.split()
        # fields[0]=state, fields[1]=ppid
        if len(fields) >= 2 and fields[1].isdigit():
            return int(fields[1])
    except Exception:
        pass

    return -1


def get_proc_node(pid: int) -> Optional[ProcNode]:
    if pid <= 0:
        return None
    if not os.path.isdir(f"/proc/{pid}"):
        return None

    ppid = _read_ppid(pid)
    uid = _read_uid(pid)
    comm = _read_comm(pid) or ""
    exe = _read_exe(pid) or ""
    cmdline = _read_cmdline(pid) or ""

    return ProcNode(
        pid=pid,
        ppid=ppid if ppid >= 0 else 0,
        uid=uid if uid >= 0 else 0,
        comm=comm,
        exe=exe,
        cmdline=cmdline,
    )


def build_lineage(pid: int, max_depth: int = 25) -> List[ProcNode]:
    """
    Returns a list ordered from root -> ... -> target pid.
    """
    chain: List[ProcNode] = []
    seen = set()

    cur = pid
    depth = 0
    while cur > 0 and depth < max_depth and cur not in seen:
        seen.add(cur)

        node = get_proc_node(cur)
        if node is None:
            break

        chain.append(node)
        if node.ppid <= 0 or node.ppid == node.pid:
            break

        cur = node.ppid
        depth += 1

    chain.reverse()
    return chain


def lineage_to_text(chain: List[ProcNode]) -> str:
    lines = []
    for n in chain:
        cmd = n.cmdline if n.cmdline else n.comm
        lines.append(
            f"pid={n.pid} ppid={n.ppid} uid={n.uid} comm={n.comm} exe={n.exe} cmdline={cmd}"
        )
    return "\n".join(lines) + ("\n" if lines else "")


def lineage_to_dot(chain: List[ProcNode]) -> str:
    """
    Simple DOT graph: parent -> child edges for the chain.
    """
    def label(n: ProcNode) -> str:
        cmd = (n.cmdline if n.cmdline else n.comm).replace('"', "'")
        return f'{n.pid}\\n{n.comm}\\nuid={n.uid}\\n{cmd[:120]}'

    lines = [
        "digraph lineage {",
        '  rankdir="LR";',
        '  node [shape="box"];'
    ]

    # Nodes
    for n in chain:
        lines.append(f'  "{n.pid}" [label="{label(n)}"];')

    # Edges
    for i in range(1, len(chain)):
        parent = chain[i - 1].pid
        child = chain[i].pid
        lines.append(f'  "{parent}" -> "{child}";')

    lines.append("}")
    return "\n".join(lines) + "\n"


def lineage_to_jsonable(chain: List[ProcNode]) -> List[Dict]:
    return [asdict(n) for n in chain]
