# Severity rubric

Every finding is scored on two analyst-assigned dimensions, each 1–5, and
the severity is derived from the product. The dimensions are judgements
against this rubric; the *evidence* for each finding (measurements, log
lines, source citations) is in the finding's evidence fields and is
independently rerunnable.

## Impact (1–5)
- 1 — Informational: no security or operational effect; planning context only.
- 2 — Minor cost or friction: measurable overhead, no security property affected.
- 3 — A security property is weakened, or an assumed migration property does
  not hold; an operator acting on the assumption would be misled.
- 4 — A key, secret, or authentication decision can be compromised if the
  condition is met.
- 5 — Immediate compromise of confidentiality, integrity, or availability.

## Likelihood / exposure (1–5)
- 1 — Requires an unusual configuration or an attacker capability not
  present in normal deployments.
- 2 — Requires a specific misconfiguration or a weak component (e.g. a weak
  random-bit generator) that is uncommon in maintained systems.
- 3 — Arises in ordinary deployment or migration planning.
- 4 — Arises by default for a common migration path.
- 5 — Present in every deployment of the affected component.

## Severity bands (score = impact × likelihood)
- 20–25 Critical
- 15–19 High
- 8–14  Medium
- 4–7   Low
- 1–3   Info

## Method note
Severity is an analyst judgement under this rubric, not a measured value.
Where a finding rests on a measurement, the measured numbers are quoted in
the finding's evidence and can be re-derived by running the pack. Findings
whose evidence is a standards text (not a measurement) say so explicitly.
