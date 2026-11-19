# Known Limits & Production Hardening

> The reference gate (`gate/release_gate.py`) is deliberately small and honest. It
> demonstrates the *shape* of a fail-closed gate; it is not, by itself, a
> concurrency-safe, crash-safe production service. This page records the failure
> modes that appear when the pattern is moved from a single-agent demo into a live
> multi-agent deployment — and the standard mitigations.

Recording these limits is the same discipline as K1 in
[`examples/compliance-check-art50.md`](../examples/compliance-check-art50.md): a
gate that only advertises its strengths is marketing, not evidence.

---

## 1. Non-atomic action + state write (at-least-once side effects)

**The gap.** Invariant 2 says state advances *only after* a successful action. The
acting agent performs the external side effect first, then writes the event id to
the state file. If the process crashes (or the host dies) **between** the external
call succeeding and the local write completing, the gate is still `OPEN` on the next
run — and the action fires **again**. This is the classic at-least-once delivery
window.

**Mitigations** (in order of preference):

- **Idempotency key.** Derive a key from the event id and send it on the downstream
  API call, so a repeat is a no-op the receiver deduplicates.
- **Two-phase intent log.** Write a `PENDING` record before the external call and
  flip it to `COMMITTED` after; on startup, reconcile every `PENDING` entry against
  the external system before acting.
- Idempotent external operations (upserts keyed by event id) where the API allows them.

The read-only gate design makes this *survivable* (the signal is never silently
lost) — but it does not make the external call idempotent. That is the acting
agent's job.

## 2. Unbounded state growth & concurrency

**The gap.** Monotonic membership (invariant 3) is exactly what prevents
rolling-window false positives, but the `seen_ids` set only ever grows. For
low-to-medium volume pipelines this is irrelevant. For high-frequency signals it
becomes three problems: JSON parse/whole-file-rewrite latency grows with state
size, and two agents writing the same state file concurrently **race** (last writer
wins; the loser's event is lost).

**Mitigations:**

- **Atomic file swap.** Never rewrite in place. Write to `state.json.tmp`, `fsync`,
  then `os.replace()` onto the live path (atomic on POSIX and NTFS).
- **A single writer.** Serialize state updates behind one owner (a queue, a lock
  file, or one "recorder" agent) rather than letting every specialist write.
- **SQLite in WAL mode** once state size or concurrency grows past a single flat
  file: a `seen(id PRIMARY KEY, first_seen)` table, `INSERT OR IGNORE`, and WAL for
  concurrent readers with a single serialized writer.
- **Optional pruning** only where the *freshness* invariant (invariant 5) still
  holds: ids older than the newest id ever seen can be compacted — but never below
  the freshness horizon, or window-shift false positives return.

## 3. Article 50 marking: pre-publish vs. post-publish verification

**The gap.** Art. 50 requires outputs to carry a machine-readable indication of
synthetic origin that survives to the point of exposure. Downstream platforms, CDNs
and image processors **strip** embedded EXIF/XMP/C2PA metadata on upload. A gate
that verifies a manifest *before* upload can therefore certify a marking that no
longer exists once the asset is live.

**What this framework does — and its limit.** Finding F-1 does **not** depend on
embedded metadata. It checks the **platform's own per-item "synthetic / altered"
flag** against the *published* item — precisely to sidestep stripping. The remaining
open question is different from "is the metadata intact?":

- the gate verifies the *flag is set*, not that the disclosure is *perceivable at
  first exposure* — that is the exact gap recorded as **K1** (collapsed description
  in autoplay), and it must stay `OPEN` until an in-frame notice exists.

**Mitigations / control points:**

- Prefer **platform-native flags / account-level labels** over embedded metadata
  when the delivery platform strips metadata.
- Verify against the **live, published artifact** (or its public API representation),
  not the pre-upload manifest, wherever the obligation is about what the audience sees.
- Keep a per-item **evidence record** of *which* marking mechanism was checked and
  *when*, so a later platform change can be re-audited.
- Treat "mechanism intact but not perceivable" as `OPEN`, never `CLOSED` — see K1.

---

## Summary table

| Failure mode | Where it bites | Mitigation |
|---|---|---|
| Crash between side effect and state write | Act step | Idempotency key / `PENDING→COMMITTED` intent log |
| Concurrent state writers / growing file | State file | Atomic `os.replace()` swap, single writer, SQLite WAL |
| Metadata stripping on upload | Art. 50 evidence | Platform-native flag + post-publish verification (F-1) |
| Marking present but not perceivable | Art. 50(5) | Keep open (K1) until an in-frame/at-exposure notice exists |

None of these are reasons to distrust the gate — they are the boundary of what a
*reference* gate promises. A production deployment pairs the gate with idempotent
side effects, an atomic single-writer state store, and post-publish evidence checks.