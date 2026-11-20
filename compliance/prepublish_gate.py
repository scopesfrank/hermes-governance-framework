#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Public Release Gate — a fail-closed pre-publication checker.

One deterministic gate in front of anything that goes public (YouTube, GitHub,
LinkedIn, web). It reads a per-artifact MANIFEST and answers one question:
*may this artifact be published right now?*

Verdict is PASS only if EVERY check is CLOSED. Any OPEN (a duty not met,
remediation known) or ERROR (could not verify) BLOCKS the release — the gate
never assumes compliance it did not measure. This is the same BASELINE / OPEN /
CLOSED / ERROR discipline as gate/release_gate.py, applied to compliance.

Checks (surface-dependent):
  FILES_PRESENT        referenced files/media exist            -> ERROR if not
  DISCLOSURE_HUMAN     human-readable AI notice present        -> OPEN if missing
  DISCLOSURE_MACHINE   machine-readable marking declared       -> OPEN if not
  DISCLOSURE_EXPOSURE  notice perceivable at first exposure    -> OPEN if not (K1)
  LEKTORAT             public text proof-read                  -> OPEN if not
  SECRETS              secret/PII scan over text files         -> OPEN if hits
  PII                  personal data in public text            -> OPEN if hits
  CLAIMS               every factual claim has a source        -> OPEN if not
  THIRD_PARTY_MEDIA    no unlicensed third-party media         -> OPEN if not
  YT_LIMITS            title<=100, description<=5000           -> OPEN if exceeded
  GH_FILES             LICENSE + DISCLAIMER present            -> OPEN if not
  GH_INTERNAL          no internal paths / credentials         -> OPEN if found

Records an evidence file per run (hash, time, checks, verdict) under
compliance/evidence/ (atomic swap). Stdlib only. Deterministic (no randomness,
UTC timestamp only in the evidence record, never in the verdict text).

Usage:
  python prepublish_gate.py check <manifest.json> [--evidence-dir DIR] [--quiet]
  python prepublish_gate.py selftest
Exit: 0 = PASS, 1 = BLOCK (OPEN or ERROR present), 2 = bad usage/manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0"
SURFACES = ("youtube", "github", "linkedin", "web")

CLOSED, OPEN, ERROR, BASELINE = "CLOSED", "OPEN", "ERROR", "BASELINE"

# --- detectors --------------------------------------------------------------
SECRET_PATTERNS = [
    ("aws-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |PGP )?PRIVATE KEY-----")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("assigned-secret", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
]
PII_PATTERNS = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}\b")),
    ("phone", re.compile(r"\+\d{2}[ \-/]?\d{3,4}[ \-/]?\d{6,}")),
]
INTERNAL_PATHS = re.compile(r"[A-Za-z]:\\Users\\|[A-Za-z]:/Users/|/home/[a-z]+/|localhost:\d{2,5}")
TEXT_EXT = {".md", ".markdown", ".txt", ".json", ".yaml", ".yml", ".py", ".js", ".ts",
            ".html", ".css", ".sh", ".bat", ".ps1", ".cfg", ".ini", ".toml"}
MAX_READ = 2 * 1024 * 1024

# --- helpers ----------------------------------------------------------------
def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def read_text(path: Path) -> str:
    try:
        data = path.read_bytes()[:MAX_READ]
        return data.decode("utf-8", "replace")
    except Exception:
        return ""


def collect_text(manifest: dict, base: Path) -> str:
    chunks = []
    df = manifest.get("description_file")
    if df:
        chunks.append(read_text(base / df))
    for f in manifest.get("files", []) or []:
        p = base / f
        if p.is_file() and p.suffix.lower() in TEXT_EXT:
            chunks.append(read_text(p))
    for c in manifest.get("claims", []) or []:
        if isinstance(c, dict):
            chunks.append(str(c.get("text", "")))
    return "\n".join(chunks)


def resolve(base: Path, rel: str) -> Path:
    p = Path(rel)
    return p if p.is_absolute() else (base / p)


# --- checks: each returns (state, reason) -----------------------------------
def c_files_present(m, base):
    missing = []
    refs = list(m.get("files", []) or []) + list(m.get("media", []) or [])
    if m.get("description_file"):
        refs.append(m["description_file"])
    for r in refs:
        if not resolve(base, r).exists():
            missing.append(str(r))
    if missing:
        return ERROR, f"referenced files missing: {missing}"
    return CLOSED, f"{len(refs)} referenced file(s) present"


def c_disclosure_human(m, base):
    disc = m.get("disclosure") or {}
    notice = (disc.get("human_notice_text") or "").strip()
    if not notice:
        return OPEN, "no human-readable AI notice declared"
    desc = read_text(base / m["description_file"]) if m.get("description_file") else ""
    if notice.lower() not in desc.lower():
        return OPEN, "declared notice not found in description text"
    return CLOSED, "human-readable notice present in description"


def c_disclosure_machine(m, base):
    if (m.get("disclosure") or {}).get("machine_marking") is True:
        return CLOSED, "machine-readable marking declared"
    return OPEN, "machine-readable marking not set"


def c_disclosure_exposure(m, base):
    if (m.get("disclosure") or {}).get("perceivable_at_exposure") is True:
        return CLOSED, "notice perceivable at first exposure"
    return OPEN, "notice not perceivable at first exposure (Art. 50(5) / K1)"


def c_lektora(m, base):
    if m.get("lektoriert") is True:
        return CLOSED, "public text proof-read"
    return OPEN, "public text not proof-read"


def c_secrets(m, base):
    text = collect_text(m, base)
    hits = []
    for name, rx in SECRET_PATTERNS:
        for mo in rx.finditer(text):
            hits.append(name)
            break
    if hits:
        return OPEN, f"possible secret(s): {sorted(set(hits))}"
    return CLOSED, "no secret patterns found"


def c_pii(m, base):
    text = collect_text(m, base)
    hits = []
    for name, rx in PII_PATTERNS:
        if rx.search(text):
            hits.append(name)
    if hits:
        return OPEN, f"possible personal data: {hits}"
    return CLOSED, "no PII patterns found"


def c_claims(m, base):
    claims = m.get("claims", []) or []
    unsourced = [i for i, c in enumerate(claims) if not (isinstance(c, dict) and str(c.get("source", "")).strip())]
    if unsourced:
        return OPEN, f"{len(unsourced)} claim(s) without a source"
    return CLOSED, f"{len(claims)} claim(s) sourced"


def c_third_party(m, base):
    tpm = m.get("third_party_media", []) or []
    unlicensed = [x for x in tpm if not (isinstance(x, dict) and x.get("license"))]
    if unlicensed:
        return OPEN, f"{len(unlicensed)} third-party item(s) without license"
    return CLOSED, "no unlicensed third-party media"


def c_yt_limits(m, base):
    title = str(m.get("title", ""))
    desc = read_text(base / m["description_file"]) if m.get("description_file") else ""
    problems = []
    if len(title) > 100:
        problems.append(f"title {len(title)}>100")
    if len(desc) > 5000:
        problems.append(f"description {len(desc)}>5000")
    if problems:
        return OPEN, "; ".join(problems)
    return CLOSED, f"title<=100, description<=5000"


def c_gh_files(m, base):
    names = {Path(f).name.upper() for f in (m.get("files", []) or [])}
    need = []
    if not any("LICENSE" in n for n in names):
        need.append("LICENSE")
    if not any("DISCLAIMER" in n for n in names):
        need.append("DISCLAIMER")
    if need:
        return OPEN, f"missing: {need}"
    return CLOSED, "LICENSE + DISCLAIMER present"


def c_gh_internal(m, base):
    text = collect_text(m, base)
    hits = sorted({mo.group(0) for mo in INTERNAL_PATHS.finditer(text)})
    if hits:
        return OPEN, f"internal paths/endpoints found: {hits[:5]}"
    return CLOSED, "no internal paths found"


# --- registry ---------------------------------------------------------------
BASE_CHECKS = [
    ("FILES_PRESENT", c_files_present),
    ("SECRETS", c_secrets),
    ("PII", c_pii),
    ("CLAIMS", c_claims),
    ("THIRD_PARTY_MEDIA", c_third_party),
]
DISCLOSURE_CHECKS = [
    ("DISCLOSURE_HUMAN", c_disclosure_human),
    ("DISCLOSURE_MACHINE", c_disclosure_machine),
    ("DISCLOSURE_EXPOSURE", c_disclosure_exposure),
]


def profile_for(manifest: dict) -> list:
    """Build the ordered check list for a manifest (surface + content type)."""
    surface = manifest.get("surface")
    if surface not in SURFACES:
        raise ValueError(f"unknown surface: {surface!r} (expected one of {SURFACES})")
    checks = list(BASE_CHECKS)
    # Disclosure duties apply to content surfaces, or when the artifact itself
    # is declared AI-generated. A plain code repo with no AI content does not
    # carry Art. 50 disclosure duties, so those checks are not run there.
    text_surface = surface in ("youtube", "linkedin")
    if text_surface or manifest.get("ai_generated_content"):
        checks += DISCLOSURE_CHECKS
    if text_surface:
        checks.append(("LEKTORAT", c_lektora))
    if surface == "youtube":
        checks.append(("YT_LIMITS", c_yt_limits))
    if surface == "github":
        checks += [("GH_FILES", c_gh_files), ("GH_INTERNAL", c_gh_internal)]
    return checks


def run_check(manifest: dict, base: Path) -> dict:
    checks = profile_for(manifest)
    results = []
    for name, fn in checks:
        try:
            state, reason = fn(manifest, base)
        except Exception as exc:  # noqa: BLE001
            state, reason = ERROR, f"check crashed: {type(exc).__name__}: {exc}"
        results.append({"check": name, "state": state, "reason": reason})
    verdict = "PASS" if all(r["state"] == CLOSED for r in results) else "BLOCK"
    return {"verdict": verdict, "surface": manifest["surface"], "checks": results}


def write_evidence(result: dict, manifest_path: Path, manifest_bytes: bytes,
                   evidence_dir: Path) -> Path:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    art = str(result.get("id") or manifest_path.stem)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    record = {
        "gate": "public-release", "version": VERSION, "artifact": art,
        "surface": result["surface"], "verdict": result["verdict"],
        "manifest": str(manifest_path), "manifest_sha256": sha256_bytes(manifest_bytes),
        "checked_at_utc": ts, "checks": result["checks"],
    }
    target = evidence_dir / f"{art}-{ts}.json"
    tmp = target.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, target)  # atomic swap
    return target


# --- commands ---------------------------------------------------------------
def cmd_check(args) -> int:
    mp = Path(args.manifest)
    if not mp.is_file():
        print(f"GATE=ERROR\nREASON=manifest not found: {mp}")
        return 2
    raw = mp.read_bytes()
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"GATE=ERROR\nREASON=manifest not valid JSON: {exc}")
        return 2
    try:
        result = run_check(manifest, mp.parent)
    except ValueError as exc:
        print(f"GATE=ERROR\nREASON={exc}")
        return 2
    result["id"] = manifest.get("id")

    ev = None
    if not args.no_evidence:
        try:
            ev = write_evidence(result, mp, raw, Path(args.evidence_dir))
        except Exception as exc:  # noqa: BLE001
            print(f"GATE=ERROR\nREASON=evidence write failed: {exc}")
            return 2

    print(f"GATE={result['verdict']}")
    if not args.quiet:
        print(f"ARTIFACT={result.get('id') or mp.stem}")
        print(f"SURFACE={result['surface']}")
        for r in result["checks"]:
            print(f"CHECK={r['check']} STATE={r['state']} REASON={r['reason']}")
        if ev:
            print(f"EVIDENCE={ev}")
    return 0 if result["verdict"] == "PASS" else 1


def cmd_selftest(_args) -> int:
    import tempfile
    ok = True
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        (base / "desc.txt").write_text("Video. mit Unterstützung künstlicher Intelligenz erstellt (Bild und Ton)", encoding="utf-8")
        (base / "LICENSE").write_text("MIT", encoding="utf-8")
        (base / "DISCLAIMER.md").write_text("no warranty", encoding="utf-8")
        (base / "app.py").write_text("print('hello')\n", encoding="utf-8")

        good = {
            "id": "self-youtube-ok", "surface": "youtube", "title": "Kurzes Demo",
            "description_file": "desc.txt", "media": [],
            "disclosure": {"human_notice_text": "mit Unterstützung künstlicher Intelligenz erstellt",
                           "machine_marking": True, "perceivable_at_exposure": True},
            "lektoriert": True, "claims": [{"text": "x", "source": "https://example.org"}],
            "third_party_media": [], "files": [],
        }
        r = run_check(good, base)
        print(f"SELFTEST pass-case: GATE={r['verdict']} (expect PASS)")
        ok &= r["verdict"] == "PASS"

        bad = json.loads(json.dumps(good))
        bad["id"] = "self-youtube-block"
        bad["disclosure"]["perceivable_at_exposure"] = False  # K1
        bad["lektoriert"] = False
        r = run_check(bad, base)
        print(f"SELFTEST k1-case:   GATE={r['verdict']} (expect BLOCK)")
        ok &= r["verdict"] == "BLOCK"

        leak = json.loads(json.dumps(good))
        leak["id"] = "self-leak"
        leak["files"] = ["leak.txt"]
        (base / "leak.txt").write_text("token = 'sk-ABCDEFGHIJKLMNOPQRSTUVWX'\n", encoding="utf-8")
        r = run_check(leak, base)
        secrets = [c for c in r["checks"] if c["check"] == "SECRETS"][0]
        print(f"SELFTEST secret-case: SECRETS={secrets['state']} GATE={r['verdict']} (expect OPEN/BLOCK)")
        ok &= secrets["state"] == OPEN and r["verdict"] == "BLOCK"

        miss = json.loads(json.dumps(good))
        miss["id"] = "self-missing"
        miss["files"] = ["nope.bin"]
        r = run_check(miss, base)
        files = [c for c in r["checks"] if c["check"] == "FILES_PRESENT"][0]
        print(f"SELFTEST missing-case: FILES_PRESENT={files['state']} (expect ERROR)")
        ok &= files["state"] == ERROR

        gh = json.loads(json.dumps(good))
        gh.update(id="self-gh", surface="github", files=["LICENSE", "DISCLAIMER.md", "app.py"])
        r = run_check(gh, base)
        print(f"SELFTEST github-case: GATE={r['verdict']} (expect PASS)")
        ok &= r["verdict"] == "PASS"

    print(f"SELFTEST={'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Public Release Gate (fail-closed)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="check one manifest")
    c.add_argument("manifest")
    c.add_argument("--evidence-dir", default=str(Path(__file__).resolve().parent / "evidence"))
    c.add_argument("--no-evidence", action="store_true")
    c.add_argument("--quiet", action="store_true")
    s = sub.add_parser("selftest", help="run built-in fixtures")
    args = ap.parse_args(argv)
    if args.cmd == "check":
        return cmd_check(args)
    return cmd_selftest(args)


if __name__ == "__main__":
    sys.exit(main())