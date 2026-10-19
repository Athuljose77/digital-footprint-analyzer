# Report schema — `dfa-report-v1`

One report bundle feeds all three export formats. The bundle is built by
`app/core/reporting/builder.py::build_report_bundle` from the **same**
`RiskSummary` the dashboard displays, and rendered by `json_export.py`,
`csv_export.py`, and `pdf_export.py`. There is no second scoring path, so a
number in a PDF cannot disagree with the number on screen.

## Formats

| Format | Renderer | Notes |
|---|---|---|
| `.json` | `render_json` | Complete machine-readable bundle (every field below) |
| `.csv` | `render_csv` + `encode_csv` | One uniform table; four row kinds via `record_type`; written as UTF-8 with BOM (`utf-8-sig`) and CRLF line endings so spreadsheet apps open it correctly |
| `.pdf` | `render_pdf` | Rendered locally with `QPdfWriter` + `QTextDocument` (no new dependencies); requires a running Qt GUI application, otherwise export fails with a clear message |

The `.json` file additionally carries `title` (the same human title the PDF
and CSV assessment row use).

## Bundle fields

```
schema_version   "dfa-report-v1"
generated_at     ISO-8601 UTC
application      "Digital Footprint Analyzer"
title            e.g. "Full Scan report — some@example.com"
is_empty         true when the scan recorded no findings
empty_reason     plain-language explanation when is_empty is true
notes            provenance + sanitization + standing methodology limits
assessment       { ...below... }
coverage[]       name, key, state, note
findings[]       identity_key, title, description, finding_type, category,
                 severity, status, module, sources[], verification,
                 confidence, why_it_matters, evidence[]
actions[]        action_key, title, priority, module, why_it_matters,
                 steps[], docs[{label,url}], verification, confidence,
                 verify_first, user_state, present_in_latest_scan, note
```

### `assessment`

| Field | Meaning |
|---|---|
| `scan_type`, `status`, `target_label` | What ran, how it ended, and what it ran against (sanitized) |
| `started_at`, `finished_at` | Real wall-clock bounds recorded by the scan controller |
| `score` | 0–100, or `null` when the score is withheld |
| `band` | `None detected` / `Low` / `Moderate` / `Elevated` / `High`, or `Indeterminate` |
| `score_available` | Whether the score could be supported at all |
| `unavailable_reason` | Why the score is `null` (empty when a score exists) |
| `points` | Raw weighted points before the curve |
| `confidence`, `confidence_reasons[]` | Confidence in the assessment itself |
| `severity_breakdown` | Distinct issues per severity |
| `counts` | The counters described in `docs/RISK_METHODOLOGY.md` |
| `factors[]` | Stated reasons the score is what it is (`name`, `detail`) |
| `caveats[]` | Scan-specific honesty notes (gaps, unverified findings, withheld score) |
| `methodology_version` | `exposure-v1` |
| `coverage_key` | Hash of the coverage rows; score comparison across scans requires a match |

## CSV layout

One table, fixed columns, one row per fact:

```
record_type, title, severity, status, module, verification, confidence,
priority, user_state, detail, evidence, score, band, methodology,
coverage_key, note
```

`record_type` is one of `assessment`, `finding`, `coverage`,
`recommendation`:

- **assessment** — one row: `title` is the report title, `detail` the
  severity breakdown, `note` the caveats, plus score/band/methodology/
  coverage_key/confidence.
- **finding** — one row per finding; `evidence` joins entries with
  `" | "`; `note` carries the finding type.
- **coverage** — one row per module: `status` is the coverage state,
  `module` the module key, `note` the limitation text.
- **recommendation** — one row per action: `priority`, `user_state`,
  `detail` = why it matters, `evidence` = the steps, `note` = the note plus
  the documentation URLs. `severity` holds the action's verification label.

Cells beginning with `=`, `+`, `-`, `@`, tab, or carriage return are prefixed
with `'` so a spreadsheet cannot interpret scan data as a formula
(CSV-injection defence).

## PDF contents

The PDF is generated locally from the bundle: title, assessment (score, band,
confidence, breakdown), coverage, top findings with severity/verification,
recommended actions, the standing methodology limits, and the notes. It
contains the same textual data as the JSON, formatted for reading; it is not
interactive.

## Empty and partial scans

- A scan with **no findings** still produces a complete report. `is_empty` is
  `true` and `empty_reason` states which case applies:
  - no findings and no module coverage;
  - no findings and no module completed with usable coverage, so nothing
    could be assessed;
  - no findings in the modules that ran ("that is not evidence that no
    exposure exists").
- A **partial** scan keeps `status` in the assessment, lists every uncovered
  module under `coverage`, and either withholds the score with
  `unavailable_reason` or shows it with the coverage caveats — exactly as the
  Assessment page shows them.
- Every report includes the three standing methodology limits and the note
  that a 0 means "nothing detected".

## Provenance, sanitization, and secrets

Every report carries these notes:

> Generated locally on this device from a single scan. No data was sent
> anywhere to produce this report.

> Evidence is shortened and sensitive values (credentials, tokens, full file
> paths, email local parts) are masked. Re-run the scan for the raw values.

All text passes `app/core/history/sanitize.py` before inclusion, so reports do
not leak credentials, tokens, full local paths, or other people's email
addresses. See `docs/PRIVACY.md` for the full rules.

## Destination handling and failures

`export_report(bundle, path, fmt)` is the only write path:

- The path is validated first: an empty destination, a directory, a missing
  parent folder, or an unwritable folder raises `ReportExportError` with a
  user-facing message; the extension is corrected to match the format.
- JSON and CSV are rendered **completely in memory** before the file is
  opened, so a rendering failure cannot leave a half-written file behind. PDF
  renders through a scratch file first.
- After writing, an empty file is treated as a failure.
- OS errors surface as `Could not write the report to '<path>': <reason>`.

The caller (Assessment page export) shows the message and never a traceback.

## Compatibility contract

`schema_version` is `dfa-report-v1`. Consumers should treat unknown fields as
additive and must not recompute scores from raw findings — the score,
methodology version, and coverage key in `assessment` are authoritative. A
change to the meaning of any documented field bumps the schema version.
