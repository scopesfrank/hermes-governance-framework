# Architecture (abstracted)

This document describes the fleet/agent architecture that the gate and policy layers were
built to govern — abstracted and with all deployment specifics removed.

## 1. Roles

**Orchestrator (single point of contact).**
Exactly one agent faces the human user and owns coordination. It triages, frames tasks,
delegates to specialists, and synthesizes results. It does not do deep specialist work itself.
This keeps the user-facing channel single-owner and the context budget small.

**Specialist agents.**
Each has a narrow, declared mission (e.g. build, write, review, verify). They are strictly
scoped and are handed *one* task with context and acceptance criteria.

**Independent reviewer / compliance gate.**
A separate agent that is *not* the author of the artifact. Its job is to re-check work against
the policy before anything ships. The author never certifies its own output.

Key rule: **exactly one owner per task.** The same task is never dispatched to two agents.

## 2. Communication model

Two channels, deliberately separated:

- **Control channel** — task handover, decisions, blockers. ASCII-short, one line where possible:
  `TASK: [what] | OWNER: [@agent] | DUE: [when]`.
- **Artifact channel** — the actual content (code, specs, reports, data) lives **in files**,
  never pasted into chat. The control message carries only the absolute path, a status flag
  ("new file" / "changed file") and one sentence on what changed. The receiver reads the file.

This avoids context bloat, avoids divergent copies, and makes every handover auditable.

## 3. Shared state discipline

- Before touching shared state, an agent re-reads it — never works from its own last snapshot.
  (Another agent or session may have changed it.)
- Obsolete processes (watchers, duplicate dispatches) are stopped **before** a new version starts.
- Ordering rule for start/stop jobs: put the **stop** job in place *before* the start job
  ("bar the door before opening it"); the start job re-checks the stop flag when it wakes.

## 4. Release control

Consequential actions (publishing, deploying, spending) pass through the gate
(`docs/gate-state-machine.md`):

1. The gate reads the external signal and emits `BASELINE | OPEN | CLOSED | ERROR`.
2. The agent acts **only** on `OPEN`.
3. On `CLOSED`/`BASELINE` it reports and stops. On `ERROR` it fails closed and reports honestly.
4. State is advanced **only after** a successful action.
5. A human approval step is the final gate for anything public.

## 5. Safety invariants (non-negotiable)

- **Never delete the user's files.** No destructive options/defaults in tools pointing at user folders.
- **No sensitive data in generated media or uploads.**
- **No communication with agents outside the local environment** (the human-facing chat bridge is not an agent).
- **UI / end-to-end checks are deterministic and headless** — no injected synthetic desktop input.
- **Shipped scripts pin their interpreter** (the ambient `python` on `PATH` is not the project venv).
- Read-only analysis agents stay read-only; their fixes are applied by the owning agent.

## 6. Self-correction

- On a failed tool call, the retry **must change the arguments** — no identical blind retry.
- After two varied attempts, escalate to the human.
- Success is measured by *effect* (did the external state change as intended?), not by a
  tool's "ok" message.

## 7. What this buys you

- A single accountable owner per action.
- Every consequential action authorized by an explicit, inspectable state — never by a heuristic.
- A written trail of *why* each action was allowed, refused, or failed closed.

## 8. Known limits (and why we publish them)

The gate is a reference implementation, not a finished production service. Three
failure modes appear at the state boundary once the pattern runs live — and each has
a standard mitigation:

1. **Non-atomic action + state write** (at-least-once): a crash between a successful
   side effect and the state write re-fires the action. Mitigation: an idempotency
   key, or a `PENDING → COMMITTED` intent log.
2. **Unbounded state growth & concurrency**: `seen_ids` grows monotonically and
   concurrent writers race. Mitigation: atomic `.tmp → os.replace()` swap, a single
   writer, or SQLite in WAL mode.
3. **Art. 50 marking persistence**: embedded EXIF/XMP/C2PA is often stripped on
   upload, so the check uses the platform's native flag and verifies the *published*
   item. "Flag set" is still not "perceivable at first exposure" — that stays the
   `OPEN` finding K1.

Full detail and mitigations: [`docs/production-hardening.md`](docs/production-hardening.md).
Recording these is the same discipline as keeping K1 open: a gate that advertises
only its strengths is marketing, not evidence.
