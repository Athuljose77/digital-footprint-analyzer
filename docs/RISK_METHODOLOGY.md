# Exposure methodology — `exposure-v1`

This document describes how the Digital Footprint Analyzer turns one finished
scan into the exposure score, band, confidence, and counts that appear on the
Assessment page, the dashboard, exported reports, and scan history. The single
implementation is `app/core/risk/` (`models.py`, `scoring.py`,
`explanations.py`); there is no second scoring path anywhere in the
application.

## What the score is

- A 0–100 index summarising the **distinct, deduplicated issues** a scan
  actually detected, weighted by severity and evidence confidence.
- **Deterministic**: the same findings and the same recorded coverage always
  produce the same score, points, band, and confidence.
- **Gated by honesty**: when the scan cannot support a number, the score is
  `None`, the band is `Indeterminate`, and `unavailable_reason` says why. A
  number is never invented to fill the space.

The score is a prioritisation aid, not a measurement of absolute risk. A score
of 0 means "nothing was detected by the modules that ran", never "nothing
exists".

## How a scan becomes a score

The pipeline lives in `app/core/risk/scoring.py::build_risk_summary` and runs
in this order:

1. **Coverage first.** Every scan records per-module coverage (see
   `app/core/scan_coverage.py`). Only modules that provided usable coverage
   can contribute findings to the score; modules that failed, were
   unavailable, or were skipped are reported as gaps instead.
2. **Scan findings are separated from exposure findings.** Findings whose
   type is a coverage/limitation record (`Scan Limitation`, `Scan Coverage`,
   `Scan Warnings`, `Unavailable Sources`) describe the scan, not the user.
   They are counted separately and never raise the score.
3. **Duplicate issues are collapsed by identity key.** The key is
   `uuid5(NAMESPACE_URL, "identity::" + (rule_id or finding_type).lower() +
   "::" + title.lower())`, so the same issue reported by several modules is
   one issue. Merging keeps the highest severity, the strongest verification,
   every contributing module in `sources`, and all evidence underneath — no
   provenance is discarded by deduplication.
4. **Each distinct issue contributes severity points scaled by confidence.**
5. **One rule may contribute at most 3 issues** (`MAX_ISSUES_PER_RULE`), so a
   single noisy source cannot dominate the score. Issues beyond the cap stay
   listed as components with `counted=false`.
6. **Points map onto the index through a saturating curve** and the band is
   read off the index.
7. **If the score cannot be supported, it is withheld** with a stated reason.

## Severity weights and confidence factors

| Severity | Base points |
|---|---|
| Critical | 25 |
| High | 15 |
| Medium | 8 |
| Low | 3 |
| Info | 1 |

| Confidence | Factor | Typical source |
|---|---|---|
| `high` | 1.0 | Observed directly on this machine, or verified |
| `medium` | 0.7 | Reported by a provider with supporting detail |
| `low` | 0.5 | Unconfirmed lead |
| anything else / missing | 0.5 | Conservative default |

An issue's contribution is `severity_weight × confidence_factor`, rounded to
two decimals. Confidence is assigned when findings are normalised
(`app/core/findings_processor.py`) from the finding's verification status, so
"a provider merely told us this" can never score like "we read this off your
disk".

## The curve and the bands

```
points = sum(contributions of counted issues)
score  = round(100 × (1 − e^(−points / 35)))
band   = read from the table below
```

| Points | Index | Band |
|---|---|---|
| 1 | 3 | Low |
| 3 | 8 | Low |
| 8 | 20 | Low |
| 15 | 35 | Moderate |
| 25 | 51 | Elevated |
| 40 | 68 | Elevated |
| 60 | 82 | High |
| 100 | 94 | High |

Bands by index: **0** None detected · **1–24** Low · **25–50** Moderate ·
**51–75** Elevated · **76–100** High. The curve saturates, so the index
approaches but never reaches 100; ordering is preserved, so a worse scan
always scores at least as high as a milder one.

## When the score is withheld

A score requires **both** of:

- scan status `COMPLETED` or `PARTIAL`, and
- at least one exposure-capable module (`system`, `browser`, `file_metadata`,
  `email`, `username`) with a coverage state of `completed` or `limited`.

Otherwise `score=None`, `band="Indeterminate"`, and the reason is one of:

- *The scan produced no module results to assess.*
- *The scan finished with status {status}; an exposure score requires a
  completed or partially completed scan.*
- *No module completed with usable coverage, so there is nothing to score.
  Absence of findings here does not mean absence of exposure.*

## Coverage vocabulary

Canonical states (`app/core/scan_coverage.py`):

| State | Meaning |
|---|---|
| `completed` | The module ran and produced usable results |
| `limited` | The module ran but saw only part of its area |
| `failed` | The module ran but errored |
| `unavailable` | The module cannot run on this platform/configuration |
| `skipped` | The module was not requested for this scan |
| `unknown` | The module's outcome could not be determined |

`completed`/`limited` are evidence states; the rest are uncovered states. The
dashboard's full-scan summary maps `unavailable` back to a "limited" wording
for display compatibility, but scoring, history, and comparison always use the
canonical state.

## Counts

`RiskSummary.counts` carries: `distinct_issues`, `confirmed`, `potential`,
`inconclusive`, `coverage_findings`, `uncovered_modules`,
`collection_failures`, `unsupported_checks`. Confirmed means the issue is
backed by direct observation, a provider verification, or an HTTP-verified
profile; potential means the provider reported it but nothing was verified
locally.

## Confidence in the assessment itself

Separate from per-issue confidence:

- **low** — one or more modules did not provide coverage (a failed or
  unavailable module, or two or more uncovered modules);
- **medium** — exactly one module is uncovered, or part of the scan
  completed with limitations;
- **high** — every attempted module completed.

If any issues are unverified, the reason list adds "*N finding(s) are
reported but unverified*".

## Comparison rules across scans

`app/core/history/compare.py` classifies each distinct issue as `new`,
`unchanged`, `modified`, `resolved`, or `not_rechecked`:

- **resolved** is claimed only when the module that owns the finding
  completed in the newer scan. If the owning module did not run, the issue is
  `not_rechecked`, never silently resolved. When the newer scan recorded no
  coverage at all, the resolution confidence is `low`.
- **Score deltas** are only shown when the methodology version *and* the
  coverage key match — comparing scores produced under different coverage
  would compare different measurements.

## Standing limits

These are true of every scan, whatever it found, and are stated in the
Assessment page and in every exported report:

1. Only the modules listed under coverage ran. Anything they cannot see was
   not assessed.
2. Not detecting a finding is not evidence that the exposure does not exist.
3. Findings that a provider merely reported are leads until you verify them.

## Marking an action complete is not verification

The Actions centre records *your* mark, not a technical re-check. A completed
action reads "Marked complete by you; this is your own mark, not a technical
verification. Re-run the scan to check whether it is still detected." An
action that disappeared from the latest scan is shown as "Completed by you and
no longer detected in the latest scan (your mark, not a technical
verification)." — never as resolved exposure.

## Versioning

The methodology version is `exposure-v1`. Any change to weights, caps, bands,
or gating rules bumps it; scan history only compares scores that share a
version. When the version changes, this document and the constants in
`app/core/risk/` must change together.

## Determinism and tests

Scoring is pure over (findings, coverage) and is covered by
`app/tests/test_risk_scoring.py`, with history/comparison behaviour in
`app/tests/test_scan_history.py` and `app/tests/test_scan_comparison.py`.
