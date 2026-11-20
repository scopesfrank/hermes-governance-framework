# Compliance gates

Two fail-closed gates with the same `BASELINE / OPEN / CLOSED / ERROR` discipline
as the release gate, applied to compliance. Stdlib only, deterministic.

| File | Purpose |
|---|---|
| `prepublish_gate.py` | Pre-publication check of one artifact (AI disclosure, secrets, PII, claims, licenses, YouTube limits, GitHub LICENSE/DISCLAIMER). |
| `workflow_gate.py` | Conformance for a whole workflow: Layer A deterministic (nulls, duplicates, freshness, schema drift, ranges, cross-sums, lineage, transport, secrets) + Layer B attestations (four-eyes, scope-binding, staggered TTL, break-glass). |
| `gates.py` | Unified runner: runs every configured gate, exits **1** if any blocks. |
| `gates.config.json` | Which manifests to run. |

## Run

```bash
python compliance/gates.py          # all gates; exit 0 = PASS/OVERRIDE, 1 = BLOCK
python compliance/prepublish_gate.py check compliance/examples/manifest-youtube.json
python compliance/workflow_gate.py selftest
```

## Attestations

A control is a machine-checkable object (`workflow.yaml` or JSON) with
`control_id, status, reviewer, reviewed_at, valid_until, evidence_uri, scope_hash`.
Enforced audit rules:

- **Four-eyes** — reviewer ≠ author / trigger.
- **Scope-binding** — infra controls bind to a `scope_hash`; a changed hash
  invalidates immediately (not at TTL).
- **Staggered TTL** — version-bound controls bind to a data/model version;
  low-dynamics controls get a 90/180-day TTL.
- **Break-glass** — an expiring override passes an *attestation* block only
  (never a deterministic data/security failure) and opens a P1 ticket with a 48 h
  deadline.

`PASS` only if every applicable check is `CLOSED`; `OVERRIDE` passes a valid
break-glass; anything else is `BLOCK` (exit 1). `BASELINE` = not applicable,
non-blocking.

The examples under `examples/` are generic and runnable from the repo root.