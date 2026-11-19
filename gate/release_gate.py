#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generic release gate — a fail-closed finite state machine in front of
consequential actions.

The gate is READ-ONLY: it never writes the state file. The acting agent advances
the state only AFTER a successful action, so a failed production run cannot
silently consume the signal and lock the gate forever.

States emitted on stdout:
    GATE=BASELINE   first run, no stored state -> initialize only, do not act
    GATE=OPEN       at least one new event since the last run -> act
    GATE=CLOSED     no new event -> do not act
    GATE=ERROR      signal unreachable / unparsable -> fail closed, report honestly

See docs/gate-state-machine.md for the transition table and invariants.
Standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

STATES = ("BASELINE", "OPEN", "CLOSED", "ERROR")


def read_signal(source: str, timeout: int = 25) -> str:
    """Fetch the signal from an http(s) URL or read it from a local file."""
    if source.startswith(("http://", "https://")):
        req = urllib.request.Request(
            source,
            headers={
                "User-Agent": "governance-gate/1.0",
                "Cache-Control": "no-cache",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")
    return Path(source).read_text(encoding="utf-8")


def extract_ids(text: str, mode: str) -> list[str]:
    """Extract the ordered list of event ids from the signal text."""
    if mode == "lines":
        return [ln.strip() for ln in text.splitlines() if ln.strip()]

    if mode == "json":
        data = json.loads(text)
        if isinstance(data, dict):
            for key in ("ids", "items", "entries", "events"):
                if key in data:
                    data = data[key]
                    break
        out = []
        for item in data:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                for key in ("id", "videoId", "guid", "key"):
                    if key in item:
                        out.append(str(item[key]))
                        break
        return out

    # default: xml / atom / rss style
    ids = re.findall(r"<yt:videoId>(.*?)</yt:videoId>", text, re.S)
    if not ids:
        ids = re.findall(r"<id>(.*?)</id>", text, re.S)
    if not ids:
        ids = re.findall(r"<guid[^>]*>(.*?)</guid>", text, re.S)
    return [i.strip() for i in ids]


def load_state(state_path: Path) -> dict:
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def decide(seen: set[str], now: list[str]) -> str:
    if not seen:
        return "BASELINE"
    if set(now) - seen:
        return "OPEN"
    return "CLOSED"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Fail-closed release gate (BASELINE/OPEN/CLOSED/ERROR)."
    )
    ap.add_argument("--source", required=True,
                    help="http(s) URL or local file holding the signal")
    ap.add_argument("--state", required=True,
                    help="path to the JSON state file (read-only for the gate)")
    ap.add_argument("--mode", default="xml", choices=("xml", "json", "lines"),
                    help="signal format (default: xml)")
    args = ap.parse_args(argv)

    state_path = Path(args.state)

    try:
        text = read_signal(args.source)
        ids = extract_ids(text, args.mode)
    except Exception as exc:  # noqa: BLE001
        print("GATE=ERROR")
        print(f"REASON=signal not retrievable/parsable: {exc!r}")
        print("INSTRUCTION=Do not act. Report honestly that nothing was verified.")
        return 0

    if not ids:
        print("GATE=ERROR")
        print("REASON=signal contained no ids (format changed or source empty).")
        print("INSTRUCTION=Do not act. Report honestly.")
        return 0

    state = load_state(state_path)
    seen = set(state.get("seen_ids") or [])
    new = [i for i in ids if i not in seen]
    gate = decide(seen, ids)

    print(f"GATE={gate}")
    print(f"SIGNAL_SOURCE={args.source}")
    print(f"SIGNAL_STAND={datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"STATE_FILE={state_path}")
    print(f"SEEN_BEFORE={len(seen)}")
    print(f"IN_SIGNAL_NOW={len(ids)}")
    if new:
        print("NEW_EVENTS:")
        for i in new:
            print(f" - {i}")
    else:
        print("NEW_EVENTS=none")
    print(f"ALL_IDS_NOW={json.dumps(ids)}")

    if gate == "CLOSED":
        print("INSTRUCTION=No new event -> do NOT act. Report and stop.")
    elif gate == "BASELINE":
        print("INSTRUCTION=First run -> initialize state only. Do NOT act.")
    elif gate == "OPEN":
        print("INSTRUCTION=Gate open -> action authorized. Advance state ONLY after success.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
