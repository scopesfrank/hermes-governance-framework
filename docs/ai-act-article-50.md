# EU AI Act — Article 50, mapped to gates

> Engineering interpretation for governance design. **Not legal advice.** Validate against the
> official regulation text and qualified counsel.

Article 50 of the EU AI Act sets **transparency obligations**. For a system that *generates or
manipulates* content, the two practically relevant duties are:

- **Art. 50(4)** — deployers of AI systems that generate or manipulate image, audio or video
  content constituting a deep fake must disclose that the content is artificially generated or
  manipulated.
- **Art. 50(5)** — where content is generated or manipulated and published to inform the public,
  the disclosure must be made **in a clear and distinguishable manner, at the latest at the time
  of the first interaction or exposure**, and be **accessible** without special aids.

(Clause numbering follows the widely used reading of the final text; confirm the exact wording
against the current official text.)

## Risk classification — where a content pipeline lands

A text/image/video generation pipeline that publishes disclosure-bearing content is a
**limited-risk** case. It is *not* high-risk; the binding duties are the Art. 50 transparency
ones (applicable from 2 August 2026), not the Annex III high-risk regime.

**Standard currently met** (example, anonymized — see `examples/compliance-check-art50.md`):

| Duty | Mechanism | Status |
|---|---|---|
| Machine-readable AI marking | Platform's per-item synthetic-content flag | met |
| Human-readable notice | Description note "created with the support of AI (image and sound)" | met |
| Audience / title / description constraints | length limits verified programmatically | met |

## The open gap class this framework is built to surface

Art. 50(5) requires the notice to be perceivable **at the time of first exposure** and
**without special aids**. A description note is **not** perceivable in an autoplay context where
the description is collapsed by the platform UI. That is a genuine gap between "we wrote the
notice" and "the notice reaches the user at first exposure".

This is exactly the kind of finding a governance gate should record as an **OPEN** item rather
than paper over — see finding **K1** in `examples/compliance-check-art50.md`.

## Mapping to gate states

| Finding state | Gate analog |
|---|---|
| Obligation verified met | `CLOSED` (nothing to do) |
| Obligation not yet met, remediation known | `OPEN` (action required, e.g. add an overlay/pin) |
| Extraction/verification failed (couldn't check) | `ERROR` (fail-closed — do **not** claim compliance) |
| No baseline measurement yet | `BASELINE` (record the initial state before claiming anything) |

The critical rule: **an unverifiable obligation is never reported as met.** "We could not check"
is `ERROR`, not a green check.

## Practical control points

1. **Pre-publication gate** — refuse to publish if a mandatory disclosure artifact is missing or an
   `OPEN` finding is unresolved and unreviewed.
2. **Evidence artifact** — a per-item record of exactly which disclosures were applied, so the
   claim is reproducible.
3. **Human approval** — final public release stays a human decision; the gate only authorizes.
