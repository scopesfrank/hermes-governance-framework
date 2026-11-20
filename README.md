# Hermes Governance Framework

Reference architecture for **governance gates around autonomous, multi-agent AI workflows** —
with evidence-based release control and EU AI Act (Article 50) transparency.

> **Status: sanitized reference implementation.**
> Every identifier, channel, customer reference and internal path has been removed.
> This shows *how* the patterns work, **not** a production deployment. See `DISCLAIMER.md`.

---

## Why this exists

Autonomous agent fleets can take consequential actions: publish content, modify systems,
send messages, spend budget. Two failure modes dominate in practice:

1. **Silent autonomy** — an agent acts because a heuristic fired, not because policy or a
   human approved it. Nobody can reconstruct afterwards *why* it acted.
2. **Standing errors** — a transient upstream failure is misread as "no change", or a rolling
   window of events moves and is misread as "new event". The result is either a stalled system
   or a *repeating* unwanted action (a daily false positive).

This framework addresses both with three layers that stay deliberately boring and inspectable:

| Layer | What it is | Where |
|---|---|---|
| **Gate** | A finite state machine in front of every consequential action | `gate/` |
| **Policy** | Governance rules as versioned, human-readable Markdown | `docs/governance-policy.md` |
| **Evidence** | Every gate decision prints a machine-readable reason | every gate run (stdout) |

## Core concept: the gate state machine

A gate never *does* the consequential thing. It only **says whether the action is authorized
right now**, and it does so with one of four states:

```
            no prior state
                 │
                 ▼
   ┌──────────┐      new event       ┌────────┐
   │ BASELINE │───── initialize ────▶│ CLOSED │
   └──────────┘                      └────────┘
                                        │   ▲
                        new event       │   │  state written after
                                        ▼   │  a *successful* action
                                     ┌──────┴─┐
                                     │  OPEN  │
                                     └────────┘
              signal unreachable / unparsable  →  ┌───────┐
                                                  │ ERROR │  (fail-closed)
                                                  └───────┘
```

* **BASELINE** — first run, no stored state. Initialize only. **Do not act.**
* **OPEN** — a new event that requires action was detected. Action **authorized**.
* **CLOSED** — no new event. **Do not act.** Report and stop.
* **ERROR** — the signal could not be retrieved or parsed. **Fail-closed: do not act.** Report honestly.

Design rules (the important part):

- The gate is **read-only**. It never writes state.
- The acting agent writes state **only after a successful action** — so a failed production run
  cannot silently consume the signal and lock the gate forever.
- State is **monotonic** for seen events: ids accumulate, they are never replaced by a rolling window.
- On any ambiguity the gate is **fail-closed** (`ERROR`), not fail-open.

Full definition and transition table: [`docs/gate-state-machine.md`](docs/gate-state-machine.md).

## Layered governance

```
        ┌─────────────────────────────────────────────────────┐
        │  Orchestrator agent  (single point of contact)      │
        └───────────────┬─────────────────────────────────────┘
                        │  AUFGABE / TASK  (one owner per task)
        ┌───────────────┼───────────────┬─────────────────────┐
        ▼               ▼               ▼                     ▼
   Specialist A    Specialist B    Compliance gate      Specialist C
   (build)         (build)         (independent review) (build)
        │               │               │                     │
        └───────────────┴───────┬───────┴─────────────────────┘
                                ▼
                        Shared project files
                    (specs, reports, artifacts on disk —
                     never large payloads in chat/logs)

                    release_gate  ──▶  OPEN / CLOSED / BASELINE / ERROR
                                ▼
                      human approval (final)
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the abstracted fleet design and
[`docs/governance-policy.md`](docs/governance-policy.md) for the policy that binds it.

## EU AI Act — Article 50

Article 50 governs **transparency obligations** for AI systems that generate or manipulate
content. The framework's own content pipeline is a *deployer* case: it applies
machine-readable AI disclosure and a human-readable notice. A worked, anonymized check —
including one **open finding (K1)** that is *not* yet satisfied — lives in
[`examples/compliance-check-art50.md`](examples/compliance-check-art50.md).

The point of shipping an *open* finding is deliberate: honest governance evidence records
what is **not** yet compliant, and why, rather than showing only green checks.

## Compliance gates

Beyond the release gate, `compliance/` ships two fail-closed gates that apply to
any workflow — one for a single public artifact (AI disclosure, secrets, PII,
claims, licenses) and one for a whole workflow (data quality + audited
attestations with four-eyes, scope-binding, staggered TTL and break-glass). A
unified runner (`compliance/gates.py`) exits `1` if any gate blocks. See
[`compliance/README.md`](compliance/README.md).

## Repository layout

```
hermes-governance-framework/
├── README.md
├── ARCHITECTURE.md
├── DISCLAIMER.md
├── LICENSE
├── docs/
│   ├── governance-policy.md        # rules as versioned Markdown (policy-as-code)
│   ├── gate-state-machine.md       # formal definition + transition table
│   ├── ai-act-article-50.md        # how Art. 50 obligations map to gates
│   └── production-hardening.md     # known limits + mitigations for live deployment
├── gate/
│   └── release_gate.py             # generic, dependency-free gate implementation
├── compliance/
│   ├── prepublish_gate.py          # pre-publication artifact gate (diffuse)
│   ├── workflow_gate.py            # data-quality + attestation conformance (diffuse)
│   └── gates.py                    # unified runner (exit 1 on any block)
└── examples/
    └── compliance-check-art50.md   # anonymized check incl. open finding K1
```

## Run the gate

```bash
python gate/release_gate.py --help
```

Dependency-free (standard library only) and fail-closed by default.

## Origin

The patterns here were distilled from a private multi-agent orchestration system
(orchestrator + specialist agents + independent compliance review) that is used to operate a
real, governed content pipeline. This repository is the **sanitized, reusable extract** —
no production code, data or credentials are included.
