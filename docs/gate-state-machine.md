# The Gate State Machine

A **fail-closed finite state machine** that sits in front of every consequential action
(publish, deploy, send, spend). The gate never performs the action. It only answers one
question: *is the action authorized right now?*

## States

| State | Meaning | Action authorized? |
|---|---|---|
| `BASELINE` | First run — no stored prior state. Initialize only. | **No** |
| `OPEN` | A new event that requires action was detected. | **Yes** |
| `CLOSED` | No new event since the last run. | **No** |
| `ERROR` | Signal could not be retrieved or parsed. Fail-closed. | **No** |

The gate emits exactly one of these to stdout, followed by machine-readable evidence lines
(`REASON`, `SEEN_BEFORE`, `IN_SIGNAL_NOW`, the event list, and an `INSTRUCTION` line).

## Transition table

Let `SEEN` be the set of event ids persisted in the gate state file, and `NOW` the set of ids in
the current signal.

| Condition | Resulting state | Notes |
|---|---|---|
| `SEEN` is empty | `BASELINE` | First run. Initialize `SEEN = NOW`. Do not act. |
| `NOW \ SEEN` is non-empty | `OPEN` | At least one genuinely new event. Act. |
| `NOW \ SEEN` is empty | `CLOSED` | Nothing new. Do not act. |
| signal fetch/parse failed | `ERROR` | Fail closed. Report honestly. Do not act. |

## Invariants (the design rules that matter)

1. **The gate is read-only.** It never writes the state file. Separation of "decide" from "record".
2. **State advances only after a *successful* action.** The acting agent writes state after the
   action succeeds — so a failed production run cannot consume the signal and lock the gate.
3. **Monotonic membership.** Seen ids **accumulate**; a rolling upstream window must never replace
   the set. Otherwise a window shift (an item dropping out) looks like a brand-new event.
4. **Fail-closed.** Any unreachable/unparsable/ambiguous signal → `ERROR`, never `OPEN`.
5. **Freshness, not just difference.** Membership alone is not enough: a "new" id should also be
   *younger* than the newest id ever seen. Comparing sets alone turns every upstream window
   movement (takedown, unlisting, duplicate removal) into a false trigger.
6. **Honest reporting.** The gate prints what it measured, so a decision can be reconstructed
   without re-running it.

## Why four states and not two

A naive gate has "new / not-new". That conflates three different situations that need different
handling:

- *first ever run* (must **not** act — nothing to compare against),
- *nothing new* (must **not** act — steady state),
- *signal broken* (must **not** act, but must **tell you**, loudly and honestly).

Collapsing `BASELINE` and `ERROR` into "not new" produces the two classic bugs:

- a **stalled system** (nobody notices the feed died),
- a **repeating false positive** (a window shift is read as "new event" every day).

## Reference implementation

`gate/release_gate.py` is a dependency-free implementation of the above. See its `--help`.

```bash
# XML signal (e.g. an RSS/Atom-style feed)
python gate/release_gate.py --source feed.xml --state state.json --mode xml

# plain list of ids, one per line
python gate/release_gate.py --source ids.txt --state state.json --mode lines
```

Exit code is always `0` — the gate *reports* state; it does not crash the pipeline. The consumer
branches on the emitted state.
