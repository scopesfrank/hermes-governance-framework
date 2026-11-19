# Anonymized Compliance Check — EU AI Act Article 50

**Scope:** a content-generation pipeline that produces and publishes AI-generated image,
voice and video material. All channel names, account IDs, asset IDs and dates are fictional or
generalized.

**Classification:** limited-risk *deployer* case → relevant obligations are **Art. 50(4) and
50(5)** transparency duties (applicable since 2 August 2026). Not an Annex III high-risk case.

**Verification approach:** each obligation is checked against an observable, reproducible
artifact (platform flag, description field, length limits). A duty that could not be checked is
recorded as `ERROR`, never as "met".

---

## Findings

### F-1 · Machine-readable AI marking — `CLOSED` ✅

- **Obligation:** content must carry a machine-readable indication of synthetic origin.
- **Evidence:** the platform's per-item "synthetic / altered" flag is set on every published item.
- **Method:** checked per item against the published metadata.
- **Result:** met for all items in scope.

### F-2 · Human-readable AI notice — `CLOSED` ✅

- **Obligation:** a perceivable natural-language disclosure.
- **Evidence:** each description carries the notice
  *"created with the support of artificial intelligence (image and sound)"*.
- **Method:** string presence verified in the description of every item.
- **Result:** met for all items in scope.

### F-3 · Metadata limits — `CLOSED` ✅

- **Obligation:** platform limits on title and description length.
- **Method:** lengths measured programmatically across all items.
- **Result:** title ≤ 95 / 100, description ≤ 5000 — all within limits.

### K1 · Disclosure not perceivable at first exposure — `OPEN` ⚠️

- **Obligation:** Art. 50(5) — the disclosure must be made **in a clear and distinguishable
  manner, at the latest at the time of the first interaction or exposure**, and be
  **accessible without special aids**.
- **Observation:** in the platform's autoplay presentation, the description field (which holds the
  F-2 notice) is **collapsed and not shown**. During the first exposure — playback starting from
  an autoplay/feed context — the notice is therefore not perceivable without the user taking an
  extra action (opening the description).
- **Gap:** "the notice exists in the description" ≠ "the notice reaches the user at first
  exposure". The obligation targets *perceivability at exposure*, not the presence of a text field.
- **Candidate remediation (not yet applied):** an on-video overlay or a pinned comment rendering
  the disclosure in-frame at the start of playback, so it is perceivable without opening the
  description.
- **Status:** **OPEN — deliberately unresolved.** Recorded rather than closed, because the
  obligation is genuinely not yet met for the autoplay exposure path.

### F-4 · Content extraction availability — `BASELINE` ℹ️

- Some source items could not be re-extracted in the check window (temporary extraction issues).
  Those items are recorded as `BASELINE` (no verified measurement yet) rather than assumed compliant.

---

## Interpretation

A report that shows only green checks is not a compliance report; it is marketing. This check
keeps **K1 open** and shows the reasoning, because the value of a governance gate is precisely
that it refuses to certify what it cannot back with evidence. The open item is the deliverable.

## How the gate binds this

- The pre-publication gate refuses to publish while an `OPEN` finding is **unreviewed**.
- `ERROR` (couldn't check) is treated as **not met**, never as met.
- Final public release remains a **human** decision.
