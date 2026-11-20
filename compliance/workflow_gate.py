#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Workflow Conformance Gate — fail-closed, two-layer.

Layer A — DETERMINISTIC gates (run synchronously; block with exit 1):
  * Data quality: null rates, primary-key uniqueness, schema drift, value
    ranges, cross-table sum checks, freshness (max source age), lineage
    presence (source/transforms/destination/owner).
  * Transport & secrets: plaintext http:// endpoints, hardcoded credentials.

Layer B — ATTESTATION gates (governance/sign-off; the pipeline validates the
PROOF, not the content). Each control is a machine-checkable attestation object
(JSON or YAML, e.g. governance-attestation.yaml) with:
    control_id, status, reviewer, reviewed_at, valid_until, evidence_uri,
    scope_hash (optional), scope (optional)
Enforced audit rules (no rubber-stamping):
  1. FOUR-EYES  — reviewer must differ from the commit author / pipeline trigger.
  2. SCOPE-BINDING — infra controls bind to a scope_hash (config/IAM/Terraform);
     a changed hash invalidates the attestation immediately, not at TTL.
  3. STAGGERED TTL — high-dynamics controls (bias/causality on new data) are
     bound to a data/model version (scope_hash, no time TTL); low-dynamics
     controls (restore drill, FinOps, catalog) get a time TTL (90/180 days).

EMERGENCY OVERRIDE — an explicit break-glass entry may pass a BLOCK caused ONLY
by an attestation control (never by a deterministic data/security failure). It
writes a P1 audit ticket with a hard 48 h follow-up deadline.

Verdicts: PASS (exit 0) | OVERRIDE (exit 0, ticket written) | BLOCK (exit 1).
Stdlib only. Deterministic (UTC timestamps only in evidence/tickets).

Usage:
  python workflow_gate.py check <manifest.(json|yaml)> [--evidence-dir DIR] [--quiet]
  python workflow_gate.py selftest
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "2.0"
CLOSED, OPEN, ERROR, BASELINE, OVERRIDE = "CLOSED", "OPEN", "ERROR", "BASELINE", "OVERRIDE"

# ---------------------------------------------------------------------------
# detectors
# ---------------------------------------------------------------------------
SECRET_PATTERNS = [
    ("aws-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |PGP )?PRIVATE KEY-----")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b")),
    ("assigned-secret", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
]
ISO_CCY = re.compile(r"^[A-Z]{3}$")
HTTP_PLAIN = re.compile(r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>)]+")

# ---------------------------------------------------------------------------
# attestation control catalog
#   dynamics: "version" -> bound to a data/model version (scope_hash), no TTL
#             "time"    -> time TTL (ttl_days), optionally also scope-bound
# ---------------------------------------------------------------------------
CONTROLS = {
    "SEC-01-LEAST-PRIVILEGE":    dict(family="Security",     title="Least-privilege access review",       dynamics="time", ttl_days=180, scope_bound=True),
    "SEC-02-ENCRYPTION-AT-REST": dict(family="Security",     title="Encryption at rest (AES-256)",          dynamics="time", ttl_days=180, scope_bound=True),
    "SEC-03-BACKUP-RESTORE":     dict(family="Security",     title="Backup restore drill succeeded",        dynamics="time", ttl_days=180, scope_bound=False),
    "ETH-01-BIAS-REVIEW":        dict(family="Ethics",       title="Bias / representativeness review",      dynamics="version", ttl_days=None, scope_bound=True, delegate="qwen"),
    "ETH-02-CONTEXT-REVIEW":     dict(family="Ethics",       title="Context & causality review",            dynamics="version", ttl_days=None, scope_bound=True, delegate="qwen"),
    "ETH-03-TRANSPARENCY":       dict(family="Ethics",       title="Stakeholder transparency artifact",     dynamics="time", ttl_days=180, scope_bound=False, delegate="qwen"),
    "ARC-01-SCALABILITY":        dict(family="Architecture", title="Scalability / performance review",      dynamics="time", ttl_days=180, scope_bound=True),
    "ARC-02-METADATA-CATALOG":   dict(family="Architecture", title="Metadata catalog / definitions",        dynamics="time", ttl_days=90,  scope_bound=False),
    "FIN-01-FINOPS":             dict(family="Architecture", title="FinOps / cost-efficiency review",       dynamics="time", ttl_days=90,  scope_bound=False),
    "LIFE-01-LIFECYCLE":         dict(family="Architecture", title="Data lifecycle / deletion policy",      dynamics="time", ttl_days=180, scope_bound=False),
}

# ---------------------------------------------------------------------------
# minimal YAML subset parser (no pyyaml dependency)
# ---------------------------------------------------------------------------
def _scalar(s: str):
    s = s.strip()
    if s == "":
        return None
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    low = s.lower()
    if s in ("[]", "{}"):
        return [] if s == "[]" else {}
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~", "none"):
        return None
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    if re.fullmatch(r"-?\d+\.\d+", s):
        return float(s)
    return s


def _strip_comment(line: str) -> str:
    out, q = [], None
    for ch in line:
        if q:
            out.append(ch)
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out)


def parse_yaml(text: str):
    raw = []
    for ln in text.splitlines():
        ln = _strip_comment(ln).rstrip()
        if not ln.strip():
            continue
        raw.append((len(ln) - len(ln.lstrip(" ")), ln.strip()))

    def parse_block(i, indent):
        if i >= len(raw):
            return None, i
        if raw[i][1].startswith("- "):
            return parse_list(i, indent)
        return parse_map(i, indent)

    def parse_list(i, indent):
        items = []
        while i < len(raw) and raw[i][0] == indent and raw[i][1].startswith("- "):
            content = raw[i][1][2:].strip()
            if content == "":
                nxt = raw[i + 1][0] if i + 1 < len(raw) else indent + 2
                child, i = parse_block(i + 1, nxt)
                items.append(child)
                continue
            if ":" in content:
                k, v = content.split(":", 1)
                d = {k.strip(): _scalar(v)}
                i += 1
                if i < len(raw) and raw[i][0] > indent:
                    more, i = parse_map(i, raw[i][0])
                    if isinstance(more, dict):
                        d.update(more)
                items.append(d)
            else:
                items.append(_scalar(content))
                i += 1
        return items, i

    def parse_map(i, indent):
        d = {}
        while i < len(raw) and raw[i][0] == indent and not raw[i][1].startswith("- "):
            if ":" not in raw[i][1]:
                raise ValueError(f"YAML: expected 'key: value', got {raw[i][1]!r}")
            k, v = raw[i][1].split(":", 1)
            k = k.strip()
            if v.strip() == "":
                if i + 1 < len(raw) and raw[i + 1][0] > indent:
                    child, i = parse_block(i + 1, raw[i + 1][0])
                    d[k] = child
                else:
                    d[k] = None
                    i += 1
            else:
                d[k] = _scalar(v)
                i += 1
        return d, i

    value, _ = parse_block(0, raw[0][0] if raw else 0)
    return value


def parse_manifest(path: Path):
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
            return yaml.safe_load(text)
        except ImportError:
            return parse_yaml(text)
    return json.loads(text)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def read_text(path: Path) -> str:
    try:
        return path.read_bytes()[:2_000_000].decode("utf-8", "replace")
    except Exception:
        return ""


def resolve(base: Path, rel: str) -> Path:
    p = Path(rel)
    return p if p.is_absolute() else (base / p)


def is_blank(v) -> bool:
    return v is None or (isinstance(v, str) and v.strip() == "")


def today() -> datetime:
    return datetime.now()


def load_rows(path: Path, delimiter: str = ",") -> list[dict]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            return list(csv.DictReader(f, delimiter=delimiter))
    if suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        raise ValueError("JSON dataset must be a list of objects")
    raise ValueError(f"unsupported dataset format: {suffix}")


# ---------------------------------------------------------------------------
# Layer A — deterministic checks (per dataset)
# ---------------------------------------------------------------------------
def dq_completeness(ds, rows, base):
    req = ds.get("required_columns") or []
    if not req:
        return BASELINE, "no required_columns declared"
    if not rows:
        return ERROR, "dataset empty"
    thr = float(ds.get("null_max", 0.0))
    bad = {c: sum(1 for r in rows if is_blank(r.get(c))) for c in req}
    bad = {c: n for c, n in bad.items() if n}
    worst = max((n / len(rows) for n in bad.values()), default=0.0)
    if worst > thr:
        return OPEN, f"null ratio {worst:.0%} > {thr:.0%} in {bad}"
    return CLOSED, f"no missing values above {thr:.0%} in required columns"


def dq_duplicates(ds, rows, base):
    pk = ds.get("primary_key")
    if not pk:
        return BASELINE, "no primary_key declared"
    vals = [str(r.get(pk)) for r in rows]
    dupes = len(vals) - len(set(vals))
    if dupes:
        return OPEN, f"{dupes} duplicate {pk} value(s)"
    return CLOSED, f"{pk} unique"


def dq_staleness(ds, rows, base):
    col = ds.get("date_column")
    fmt = ds.get("date_format", "%Y-%m-%d")
    max_age = ds.get("max_age_days")
    if not col or max_age is None:
        return BASELINE, "no date_column/max_age_days declared"
    newest = None
    for r in rows:
        v = r.get(col)
        if is_blank(v):
            continue
        try:
            d = datetime.strptime(str(v).strip(), fmt)
        except ValueError:
            continue
        newest = d if newest is None or d > newest else newest
    if newest is None:
        return ERROR, f"no parsable dates in {col}"
    age = (today() - newest).days
    if age > int(max_age):
        return OPEN, f"newest {col} is {age} days old (> {max_age})"
    return CLOSED, f"newest {col} {age} days old (<= {max_age})"


def dq_schema(ds, rows, base):
    declared = set(ds.get("required_columns") or []) | set(ds.get("expected_columns") or [])
    if not declared:
        return BASELINE, "no schema declared"
    if not rows:
        return ERROR, "dataset empty"
    missing = declared - set(rows[0].keys())
    if missing:
        return OPEN, f"missing columns: {sorted(missing)}"
    return CLOSED, f"columns present: {len(declared)}"


def dq_schema_drift(ds, rows, base):
    baseline = ds.get("baseline_schema")
    if not baseline:
        return BASELINE, "no baseline_schema declared"
    if not rows:
        return ERROR, "dataset empty"
    have = set(rows[0].keys())
    base_set = set(baseline)
    added = sorted(have - base_set)
    removed = sorted(base_set - have)
    if added or removed:
        return OPEN, f"schema drift: added={added} removed={removed}"
    return CLOSED, f"schema matches baseline ({len(base_set)} cols)"


def dq_ranges(ds, rows, base):
    ranges = ds.get("ranges") or {}
    if not ranges:
        return BASELINE, "no value ranges declared"
    problems = []
    for col, spec in ranges.items():
        lo, hi = (list(spec) + [None, None])[:2] if isinstance(spec, list) else (None, None)
        for r in rows:
            v = r.get(col)
            if is_blank(v):
                continue
            try:
                x = float(v)
            except (TypeError, ValueError):
                problems.append(f"{col} non-numeric {v!r}")
                break
            if (lo is not None and x < lo) or (hi is not None and x > hi):
                problems.append(f"{col}={x} outside [{lo},{hi}]")
                break
    if problems:
        return OPEN, "; ".join(problems[:5])
    return CLOSED, f"{len(ranges)} range(s) respected"


def dq_standardization(ds, rows, base):
    problems = []
    col = ds.get("date_column")
    fmt = ds.get("date_format", "%Y-%m-%d")
    if col:
        bad = 0
        for r in rows:
            v = r.get(col)
            if is_blank(v):
                continue
            try:
                datetime.strptime(str(v).strip(), fmt)
            except ValueError:
                bad += 1
        if bad:
            problems.append(f"{bad} {col} value(s) not in {fmt}")
    ccy = ds.get("currency_column")
    if ccy:
        bad = sum(1 for r in rows if not is_blank(r.get(ccy)) and not ISO_CCY.match(str(r.get(ccy)).strip()))
        if bad:
            problems.append(f"{bad} {ccy} value(s) not ISO-4217")
    if problems:
        return OPEN, "; ".join(problems)
    return CLOSED, "dates/currency standardized"


def dq_lineage(ds, rows, base):
    lin = ds.get("lineage") or {}
    miss = []
    if not str(lin.get("source", "")).strip():
        miss.append("source")
    if not lin.get("transforms"):
        miss.append("transforms")
    if not str(lin.get("destination", "")).strip():
        miss.append("destination")
    if not str(lin.get("owner", "")).strip():
        miss.append("owner")
    if miss:
        return OPEN, f"lineage missing: {miss}"
    return CLOSED, "lineage documented (source/transforms/destination/owner)"


DQ_CHECKS = [
    ("DQ-COMPLETENESS", dq_completeness),
    ("DQ-DUPLICATES", dq_duplicates),
    ("DQ-STALENESS", dq_staleness),
    ("DQ-SCHEMA", dq_schema),
    ("DQ-SCHEMA-DRIFT", dq_schema_drift),
    ("DQ-RANGES", dq_ranges),
    ("DQ-STANDARDIZATION", dq_standardization),
    ("DQ-LINEAGE", dq_lineage),
]

# ---------------------------------------------------------------------------
# Layer A — security automated + cross-table sums (workflow level)
# ---------------------------------------------------------------------------
def sec_transport(manifest, base, blob):
    hits = sorted(set(HTTP_PLAIN.findall(blob)))
    if hits:
        return OPEN, f"plaintext http:// found: {hits[:5]}"
    return CLOSED, "no plaintext transport URLs"


def sec_secrets(manifest, base, blob):
    hits = sorted({n for n, rx in SECRET_PATTERNS if rx.search(blob)})
    if hits:
        return OPEN, f"possible secret(s): {hits}"
    return CLOSED, "no secret patterns found"


def cross_sums(manifest, base, blob):
    checks = manifest.get("cross_sums") or []
    if not checks:
        return BASELINE, "no cross_sums declared"
    rows_by = {}
    for ds in manifest.get("datasets") or []:
        p = ds.get("path")
        if p and resolve(base, p).exists():
            try:
                rows_by[ds.get("name")] = load_rows(resolve(base, p), ds.get("delimiter", ","))
            except Exception:  # noqa: BLE001
                rows_by[ds.get("name")] = []
    problems = []
    for cs in checks:
        try:
            ln, lc = str(cs["left"]).split(".")
            rn, rc = str(cs["right"]).split(".")
            tol = float(cs.get("tolerance", 0.0))
            ls = sum(float(r[lc]) for r in rows_by.get(ln, []) if not is_blank(r.get(lc)))
            rs = sum(float(r[rc]) for r in rows_by.get(rn, []) if not is_blank(r.get(rc)))
            if abs(ls - rs) > tol:
                problems.append(f"{cs['left']}({ls}) != {cs['right']}({rs}) tol={tol}")
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{cs}: {exc}")
    if problems:
        return OPEN, "; ".join(problems)
    return CLOSED, f"{len(checks)} cross-sum(s) balanced"


SEC_CHECKS = [
    ("SEC-TRANSPORT", sec_transport),
    ("SEC-SECRETS", sec_secrets),
    ("CROSS-SUMS", cross_sums),
]

# ---------------------------------------------------------------------------
# Layer B — attestation checks
# ---------------------------------------------------------------------------
def normalize_attestations(manifest) -> dict:
    atts = manifest.get("attestations") or {}
    if not isinstance(atts, (dict, list)):
        return {}
    if isinstance(atts, list):
        out = {}
        for a in atts:
            if isinstance(a, dict) and a.get("control_id"):
                out[str(a["control_id"])] = a
        return out
    return atts


def current_scope_hash(cid: str, manifest: dict, base: Path):
    """Current scope hash: explicit value, else sha256 of a declared file
    (version-bound controls: change the data/model -> attestation invalidates)."""
    v = (manifest.get("scope_hashes") or {}).get(cid)
    if v:
        return str(v)
    fp = (manifest.get("scope_from_files") or {}).get(cid)
    if fp:
        p = resolve(base, fp)
        if p.is_file():
            return hashlib.sha256(p.read_bytes()).hexdigest()[:16]
    return None


def _evidence_ok(base: Path, uri: str):
    if not uri:
        return OPEN, "no evidence reference"
    if "://" in uri:
        return CLOSED, "remote evidence declared"
    if not resolve(base, uri).exists():
        return ERROR, f"evidence file missing ({uri})"
    return CLOSED, "local evidence present"


def attestation_check(cid: str, manifest: dict, base: Path, atts: dict):
    ctl = CONTROLS[cid]
    title = ctl["title"]
    a = atts.get(cid)
    if not a:
        return OPEN, f"missing attestation: {title}"

    if str(a.get("status", "")).strip().lower() not in ("verified", "verified_ok"):
        return OPEN, f"{title}: status not 'verified' ({a.get('status')!r})"

    reviewer = str(a.get("reviewer", "")).strip()
    if not reviewer:
        return OPEN, f"{title}: no reviewer"
    authors = {str(manifest.get("author", "")).strip().lower(),
               str(manifest.get("triggered_by", "")).strip().lower()}
    if reviewer.lower() in authors:
        return OPEN, f"{title}: four-eyes violation (reviewer == author/trigger)"

    delegates = manifest.get("review_delegates") or {}
    want = delegates.get(cid) or ctl.get("delegate")
    if want and reviewer.lower() != str(want).lower():
        return OPEN, f"{title}: delegated to {want}, signed by {reviewer!r}"

    st, rs = _evidence_ok(base, str(a.get("evidence_uri", "")))
    if st != CLOSED:
        return st, f"{title}: {rs}"

    cur = current_scope_hash(cid, manifest, base)
    if ctl.get("scope_bound"):
        if not cur:
            return OPEN, f"{title}: no current scope_hash declared to bind against"
        if not str(a.get("scope_hash", "")).strip():
            return OPEN, f"{title}: not scope-bound (missing scope_hash)"
        if str(a["scope_hash"]).strip() != str(cur).strip():
            return OPEN, f"{title}: scope changed (attestation invalidated)"

    vu = str(a.get("valid_until", "")).strip()
    if vu:
        try:
            if datetime.strptime(vu, "%Y-%m-%d") < today():
                return OPEN, f"{title}: expired on {vu}"
        except ValueError:
            return OPEN, f"{title}: valid_until invalid ({vu!r})"
    elif ctl["dynamics"] == "version":
        if not str(a.get("scope_hash", "")).strip():
            return OPEN, f"{title}: version-bound but no scope_hash (data/model version)"
    else:
        rd = str(a.get("reviewed_at", a.get("date", ""))).strip()
        try:
            dt = datetime.strptime(rd, "%Y-%m-%d")
        except ValueError:
            return OPEN, f"{title}: reviewed_at missing/invalid ({rd!r})"
        ttl = int(ctl.get("ttl_days") or manifest.get("max_attestation_age_days", 365))
        age = (today() - dt).days
        if age > ttl:
            return OPEN, f"{title}: {age} days old (> TTL {ttl})"

    return CLOSED, f"{title} verified by {reviewer}"


def valid_breakglass(entry):
    if not isinstance(entry, dict):
        return False, "no break-glass entry"
    for k in ("token", "reason", "opened_by", "expires"):
        if not str(entry.get(k, "")).strip():
            return False, f"break-glass incomplete (missing {k})"
    try:
        if datetime.strptime(str(entry["expires"]), "%Y-%m-%d") < today():
            return False, "break-glass expired"
    except ValueError:
        return False, "break-glass expires invalid"
    return True, "valid"


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
def run_check(manifest: dict, base: Path) -> dict:
    results = []
    datasets = manifest.get("datasets") or []

    blob_parts = [json.dumps(manifest, default=str)]
    for ds in datasets:
        if ds.get("path"):
            blob_parts.append(read_text(resolve(base, ds["path"])))
    for sp in manifest.get("scan_paths") or []:
        p = resolve(base, sp)
        if p.is_file():
            blob_parts.append(read_text(p))
    blob = "\n".join(blob_parts)

    for ds in datasets:
        name = ds.get("name", "?")
        dpath = ds.get("path")
        if not dpath or not resolve(base, dpath).exists():
            results.append({"id": f"DQ-DATASET:{name}", "family": "Data quality", "attestation": False,
                            "state": ERROR, "reason": f"dataset file missing: {dpath}"})
            continue
        try:
            rows = load_rows(resolve(base, dpath), ds.get("delimiter", ","))
        except Exception as exc:  # noqa: BLE001
            results.append({"id": f"DQ-DATASET:{name}", "family": "Data quality", "attestation": False,
                            "state": ERROR, "reason": f"cannot load: {exc}"})
            continue
        for cid, fn in DQ_CHECKS:
            try:
                st, rs = fn(ds, rows, base)
            except Exception as exc:  # noqa: BLE001
                st, rs = ERROR, f"check crashed: {type(exc).__name__}: {exc}"
            results.append({"id": f"{cid}:{name}", "family": "Data quality", "attestation": False,
                            "state": st, "reason": rs})

    for cid, fn in SEC_CHECKS:
        try:
            st, rs = fn(manifest, base, blob)
        except Exception as exc:  # noqa: BLE001
            st, rs = ERROR, f"check crashed: {type(exc).__name__}: {exc}"
        results.append({"id": cid, "family": "Security", "attestation": False, "state": st, "reason": rs})

    atts = normalize_attestations(manifest)
    selected = manifest["controls"] if "controls" in manifest else list(CONTROLS.keys())
    for cid in selected:
        ctl = CONTROLS.get(cid)
        if ctl is None:
            continue
        try:
            st, rs = attestation_check(cid, manifest, base, atts)
        except Exception as exc:  # noqa: BLE001
            st, rs = ERROR, f"check crashed: {type(exc).__name__}: {exc}"
        results.append({"id": f"ATT-{cid}", "family": ctl["family"], "attestation": True,
                        "control_id": cid, "state": st, "reason": rs})

    # BASELINE = "not applicable / not declared" -> reported, but non-blocking.
    # Only OPEN (duty unmet) and ERROR (could not verify) block.
    failing = [r for r in results if r["state"] in (OPEN, ERROR)]
    overrides = []
    remaining = []
    bg = manifest.get("break_glass") or {}
    for r in failing:
        entry = bg.get(r.get("control_id")) if r.get("attestation") else None
        ok, _why = valid_breakglass(entry) if entry else (False, "")
        if ok:
            r["state"] = OVERRIDE
            r["reason"] = f"BREAK-GLASS override: {entry.get('reason')} (ticket {entry.get('ticket', '?')})"
            overrides.append(r)
        else:
            remaining.append(r)

    if not failing:
        verdict = "PASS"
    elif not remaining:
        verdict = "OVERRIDE"
    else:
        verdict = "BLOCK"
    return {"workflow": manifest.get("workflow"), "verdict": verdict,
            "checks": results, "overrides": overrides}


def write_evidence(result, manifest_path: Path, raw: bytes, evidence_dir: Path) -> Path:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    wf = str(result.get("workflow") or manifest_path.stem)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rec = {"gate": "workflow-conformance", "version": VERSION, "workflow": wf,
           "verdict": result["verdict"], "manifest": str(manifest_path),
           "manifest_sha256": hashlib.sha256(raw).hexdigest(), "checked_at_utc": ts,
           "checks": result["checks"]}
    target = evidence_dir / f"{wf}-{ts}.json"
    tmp = target.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, target)
    return target


def write_breakglass_tickets(result, evidence_dir: Path) -> list:
    tdir = evidence_dir / "break-glass"
    tdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    deadline = (datetime.now() + timedelta(hours=48)).strftime("%Y-%m-%d %H:%M")
    out = []
    for r in result["overrides"]:
        f = tdir / f"P1-{r['control_id']}-{ts}.ticket.md"
        f.write_text(
            "# P1 AUDIT TICKET — break-glass override\n\n"
            f"- Workflow: {result.get('workflow')}\n"
            f"- Control: {r['control_id']} ({r['family']})\n"
            f"- Reason: {r['reason']}\n"
            f"- Opened: {ts}\n"
            f"- HARD follow-up deadline: {deadline} (48 h)\n"
            "- Action: obtain the missing/expired attestation; close this ticket.\n",
            encoding="utf-8")
        out.append(f)
    return out


def cmd_check(args) -> int:
    mp = Path(args.manifest)
    if not mp.is_file():
        print(f"GATE=ERROR\nREASON=manifest not found: {mp}")
        return 2
    raw = mp.read_bytes()
    try:
        manifest = parse_manifest(mp)
    except Exception as exc:  # noqa: BLE001
        print(f"GATE=ERROR\nREASON=bad manifest: {exc}")
        return 2
    result = run_check(manifest, mp.parent)
    edir = Path(args.evidence_dir)
    ev = None
    if not args.no_evidence:
        try:
            ev = write_evidence(result, mp, raw, edir)
            if result["verdict"] == "OVERRIDE":
                result["tickets"] = [str(p) for p in write_breakglass_tickets(result, edir)]
        except Exception as exc:  # noqa: BLE001
            print(f"GATE=ERROR\nREASON=evidence write failed: {exc}")
            return 2
    print(f"GATE={result['verdict']}")
    if not args.quiet:
        print(f"WORKFLOW={result.get('workflow')}")
        for r in result["checks"]:
            print(f"[{r['family']}] {r['id']} STATE={r['state']} REASON={r['reason']}")
        if ev:
            print(f"EVIDENCE={ev}")
        for t in result.get("tickets", []):
            print(f"TICKET={t}")
    return 0 if result["verdict"] in ("PASS", "OVERRIDE") else 1


def cmd_request_reviews(args) -> int:
    """Dispatch missing/invalid delegated reviews (e.g. ethics -> qwen)."""
    import subprocess
    mp = Path(args.manifest)
    if not mp.is_file():
        print(f"ERROR: manifest not found: {mp}")
        return 2
    manifest = parse_manifest(mp)
    base = mp.parent
    delegates = manifest.get("review_delegates") or {}
    if not delegates:
        print("no review_delegates declared")
        return 0
    atts = normalize_attestations(manifest)
    rc = 0
    for cid, agent in delegates.items():
        st, rs = attestation_check(cid, manifest, base, atts)
        if st == CLOSED:
            print(f"SKIP {cid}: already satisfied")
            continue
        prompt = (f"Independent review (four-eyes) of control {cid} "
                  f"({CONTROLS[cid]['title']}) for workflow '{manifest.get('workflow')}'. "
                  f"Return a short verdict (PASS / CONCERNS), your reasoning, and a scope_hash "
                  f"of the reviewed data/model version. Current gate finding: {rs}")
        if not args.execute:
            print(f"HANDOFF {cid} -> hermes -p {agent} chat -q {json.dumps(prompt)}")
            continue
        evdir = base / "evidence" / "reviews"
        evdir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        f = evdir / f"{cid}-{ts}.md"
        try:
            res = subprocess.run(["hermes", "-p", agent, "chat", "-q", prompt],
                                 capture_output=True, text=True, timeout=600)
            f.write_text(res.stdout or res.stderr, encoding="utf-8")
            print(f"REVIEW {cid} by {agent} -> {f} (exit {res.returncode})")
            rc = rc or res.returncode
        except Exception as exc:  # noqa: BLE001
            print(f"REVIEW {cid} FAILED: {exc}")
            rc = 1
    return rc


def cmd_selftest(_args) -> int:
    import tempfile
    ok = True
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        (base / "bad.csv").write_text(
            "id,title,published_at,amount,currency\n"
            "1,a,2020-01-01,10,EUR\n"
            "1,b,,999,eur\n"
            "3,,2026-01-01,30,EUR\n", encoding="utf-8")
        (base / "good.csv").write_text(
            "id,title,published_at,amount,currency\n"
            "1,a,2026-11-10,10,EUR\n"
            "2,b,2026-11-12,20,EUR\n", encoding="utf-8")
        (base / "ev.txt").write_text("evidence", encoding="utf-8")

        ds = {"name": "uploads", "path": "good.csv", "primary_key": "id",
              "date_column": "published_at", "date_format": "%Y-%m-%d", "max_age_days": 60,
              "required_columns": ["id", "title", "published_at"], "currency_column": "currency",
              "baseline_schema": ["id", "title", "published_at", "amount", "currency"],
              "ranges": {"amount": [0, 100]},
              "lineage": {"source": "s", "transforms": ["t"], "destination": "d", "owner": "o"}}

        scope = {c: "HASH1" for c, v in CONTROLS.items() if v.get("scope_bound")}

        def base_atts():
            a = {}
            for c, v in CONTROLS.items():
                rev = v.get("delegate") or "reviewer-x"
                e = {"control_id": c, "status": "verified", "reviewer": rev,
                     "reviewed_at": "2026-11-01", "valid_until": "2027-05-01", "evidence_uri": "ev.txt"}
                if v.get("scope_bound"):
                    e["scope_hash"] = "HASH1"
                a[c] = e
            return a

        def mk(**kw):
            atts = base_atts()
            for k, v in kw.items():
                if k in CONTROLS:
                    atts[k] = v
            m = {"workflow": kw.get("workflow", "st"), "author": "author-1", "triggered_by": "ci",
                 "datasets": kw.get("datasets", [dict(ds)]), "attestations": atts,
                 "scope_hashes": dict(scope),
                 "review_delegates": {"ETH-01-BIAS-REVIEW": "qwen", "ETH-02-CONTEXT-REVIEW": "qwen", "ETH-03-TRANSPARENCY": "qwen"}}
            if "break_glass" in kw:
                m["break_glass"] = kw["break_glass"]
            return m

        r = run_check(mk(workflow="clean"), base)
        print(f"1 clean: {r['verdict']} (expect PASS)"); ok &= r["verdict"] == "PASS"

        r = run_check(mk(workflow="messy", datasets=[dict(ds, path="bad.csv")]), base)
        st = {c["id"]: c["state"] for c in r["checks"]}
        print(f"2 messy: {r['verdict']} dup={st.get('DQ-DUPLICATES:uploads')} stale={st.get('DQ-STALENESS:uploads')} range={st.get('DQ-RANGES:uploads')} (expect BLOCK)")
        ok &= r["verdict"] == "BLOCK" and st.get("DQ-DUPLICATES:uploads") == OPEN and st.get("DQ-RANGES:uploads") == OPEN

        r = run_check(mk(workflow="4eyes", **{"SEC-03-BACKUP-RESTORE": {"control_id": "SEC-03-BACKUP-RESTORE", "status": "verified", "reviewer": "author-1", "reviewed_at": "2026-11-01", "evidence_uri": "ev.txt"}}), base)
        st = {c["id"]: c["state"] for c in r["checks"]}
        print(f"3 four-eyes: {st.get('ATT-SEC-03-BACKUP-RESTORE')} (expect OPEN)"); ok &= st.get("ATT-SEC-03-BACKUP-RESTORE") == OPEN

        r = run_check(mk(workflow="deleg", **{"ETH-01-BIAS-REVIEW": {"control_id": "ETH-01-BIAS-REVIEW", "status": "verified", "reviewer": "gpt", "reviewed_at": "2026-11-01", "evidence_uri": "ev.txt", "scope_hash": "HASH1"}}), base)
        st = {c["id"]: c["state"] for c in r["checks"]}
        print(f"4 delegate: {st.get('ATT-ETH-01-BIAS-REVIEW')} (expect OPEN)"); ok &= st.get("ATT-ETH-01-BIAS-REVIEW") == OPEN

        r = run_check(mk(workflow="scope", **{"SEC-02-ENCRYPTION-AT-REST": {"control_id": "SEC-02-ENCRYPTION-AT-REST", "status": "verified", "reviewer": "reviewer-x", "reviewed_at": "2026-11-01", "evidence_uri": "ev.txt", "scope_hash": "OLD"}}), base)
        st = {c["id"]: c["state"] for c in r["checks"]}
        print(f"5 scope-change: {st.get('ATT-SEC-02-ENCRYPTION-AT-REST')} (expect OPEN)"); ok &= st.get("ATT-SEC-02-ENCRYPTION-AT-REST") == OPEN

        r = run_check(mk(workflow="exp", **{"FIN-01-FINOPS": {"control_id": "FIN-01-FINOPS", "status": "verified", "reviewer": "reviewer-x", "reviewed_at": "2025-01-01", "valid_until": "2025-06-01", "evidence_uri": "ev.txt"}}), base)
        st = {c["id"]: c["state"] for c in r["checks"]}
        print(f"6 expired: {st.get('ATT-FIN-01-FINOPS')} (expect OPEN)"); ok &= st.get("ATT-FIN-01-FINOPS") == OPEN

        r = run_check(mk(workflow="bg", **{
            "FIN-01-FINOPS": {"control_id": "FIN-01-FINOPS", "status": "verified", "reviewer": "reviewer-x", "reviewed_at": "2025-01-01", "valid_until": "2025-06-01", "evidence_uri": "ev.txt"},
            "break_glass": {"FIN-01-FINOPS": {"token": "BG-1", "reason": "hotfix 2am", "opened_by": "F", "expires": "2027-01-01", "ticket": "P1-1"}}}), base)
        print(f"7 break-glass: {r['verdict']} (expect OVERRIDE)"); ok &= r["verdict"] == "OVERRIDE"

        r = run_check(mk(workflow="bg2", datasets=[dict(ds, path="bad.csv")],
                         break_glass={"FIN-01-FINOPS": {"token": "BG", "reason": "x", "opened_by": "F", "expires": "2027-01-01"}}), base)
        print(f"8 break-glass-vs-data: {r['verdict']} (expect BLOCK)"); ok &= r["verdict"] == "BLOCK"

        y = ('attestations:\n'
             '  - control_id: "SEC-02-ENCRYPTION-AT-REST"\n'
             '    status: "verified"\n'
             '    reviewer: "ciso"\n'
             '    reviewed_at: "2026-09-15"\n'
             '    valid_until: "2027-03-15"\n'
             '    evidence_uri: "s3://bucket/x.json"\n'
             '    scope_hash: "a1b2c3d4"\n')
        d = parse_yaml(y)
        good_yaml = (isinstance(d, dict) and d["attestations"][0]["control_id"] == "SEC-02-ENCRYPTION-AT-REST"
                     and d["attestations"][0]["reviewed_at"] == "2026-09-15")
        print(f"9 yaml-parse: {'OK' if good_yaml else 'BAD'} (expect OK)"); ok &= good_yaml

    print(f"SELFTEST={'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Workflow Conformance Gate (fail-closed)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("manifest")
    c.add_argument("--evidence-dir", default=str(Path(__file__).resolve().parent / "evidence"))
    c.add_argument("--no-evidence", action="store_true")
    c.add_argument("--quiet", action="store_true")
    r = sub.add_parser("request-reviews", help="dispatch delegated reviews (e.g. qwen)")
    r.add_argument("manifest")
    r.add_argument("--execute", action="store_true", help="actually run the reviewer agent")
    sub.add_parser("selftest")
    args = ap.parse_args(argv)
    if args.cmd == "check":
        return cmd_check(args)
    if args.cmd == "request-reviews":
        return cmd_request_reviews(args)
    return cmd_selftest(args)


if __name__ == "__main__":
    sys.exit(main())