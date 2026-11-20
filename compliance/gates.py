#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unified gate runner — one command a pipeline calls before it acts.

Runs every configured gate (workflow conformance + public-release) and exits
non-zero if ANY of them blocks. Wire it in front of a publish/deploy step:

    python compliance/gates.py            # or: compliance\\gate.cmd
    if errorlevel 1 -> do not publish

Config: compliance/gates.config.json  { "workflows": [...], "artifacts": [...] }
Exit: 0 = all PASS/OVERRIDE, 1 = at least one BLOCK/ERROR.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(cmd: list[str]) -> tuple[int, str]:
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def gate_line(out: str) -> str:
    for ln in out.splitlines():
        if ln.startswith("GATE="):
            return ln.strip()
    return "GATE=?"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Unified compliance gate runner")
    ap.add_argument("--config", default=str(HERE / "gates.config.json"))
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    plan = [("workflow", HERE / "workflow_gate.py", m) for m in cfg.get("workflows", [])]
    plan += [("artifact", HERE / "prepublish_gate.py", m) for m in cfg.get("artifacts", [])]

    worst = 0
    failed = []
    for kind, script, manifest in plan:
        rc, out = run([sys.executable, str(script), "check", str(HERE / manifest)])
        g = gate_line(out)
        blocked = rc != 0
        status = "BLOCK" if blocked else "OK"
        print(f"{status:5s} {g:16s} [{kind}] {manifest}")
        if blocked:
            worst = 1
            failed.append((manifest, rc, out))

    if failed:
        print("\n=== blocked detail ===")
        for manifest, rc, out in failed:
            print(f"\n--- {manifest} (exit {rc}) ---")
            print(out.strip())
    return worst


if __name__ == "__main__":
    sys.exit(main())