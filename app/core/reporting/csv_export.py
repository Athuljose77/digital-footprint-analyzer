"""CSV report export.

One table with a uniform set of columns holds four kinds of row, identified by
``record_type``: the assessment, one row per finding, one row per module
coverage entry, and one row per recommended action. A spreadsheet can pivot
that without any format-specific handling.

Two details matter for correctness:

* The file is written as ``utf-8-sig`` so Excel opens it with the right
  encoding instead of mangling non-ASCII text.
* Cells beginning with ``=``, ``+``, ``-``, or ``@`` are prefixed so a
  spreadsheet cannot interpret scan data as a formula.
"""

import csv
import io
from typing import Dict, List

from app.core.reporting.models import ReportBundle

COLUMNS = [
    "record_type",
    "title",
    "severity",
    "status",
    "module",
    "verification",
    "confidence",
    "priority",
    "user_state",
    "detail",
    "evidence",
    "score",
    "band",
    "methodology",
    "coverage_key",
    "note",
]

RECORD_TYPES = ("assessment", "finding", "coverage", "recommendation")

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_EVIDENCE_SEPARATOR = " | "


def _cell(value) -> str:
    """Render one cell and defuse spreadsheet formula injection."""
    if value is None:
        return ""
    text = str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def _blank_row() -> Dict[str, str]:
    return {column: "" for column in COLUMNS}


def _assessment_row(bundle: ReportBundle) -> Dict[str, str]:
    row = _blank_row()
    assessment = bundle.assessment
    row["record_type"] = "assessment"
    row["title"] = bundle.title
    row["status"] = assessment.status
    row["detail"] = "; ".join(
        f"{key}: {value}" for key, value in assessment.severity_breakdown.items()
        if value)
    row["score"] = "" if assessment.score is None else str(assessment.score)
    row["band"] = assessment.band
    row["methodology"] = assessment.methodology_version
    row["coverage_key"] = assessment.coverage_key
    row["confidence"] = assessment.confidence
    row["note"] = " / ".join(assessment.caveats)
    return row


def _finding_row(finding) -> Dict[str, str]:
    row = _blank_row()
    row["record_type"] = "finding"
    row["title"] = finding.title
    row["severity"] = finding.severity
    row["status"] = finding.status
    row["module"] = finding.module
    row["verification"] = finding.verification
    row["confidence"] = finding.confidence
    row["detail"] = finding.description or finding.why_it_matters
    row["evidence"] = _EVIDENCE_SEPARATOR.join(finding.evidence)
    row["note"] = finding.finding_type
    return row


def _coverage_row(coverage) -> Dict[str, str]:
    row = _blank_row()
    row["record_type"] = "coverage"
    row["title"] = coverage.name
    row["status"] = coverage.state
    row["module"] = coverage.key
    row["note"] = coverage.note
    return row


def _recommendation_row(action) -> Dict[str, str]:
    row = _blank_row()
    row["record_type"] = "recommendation"
    row["title"] = action.title
    row["severity"] = action.verification
    row["confidence"] = action.confidence
    row["priority"] = action.priority
    row["user_state"] = action.user_state
    row["module"] = action.module
    row["detail"] = action.why_it_matters
    row["evidence"] = _EVIDENCE_SEPARATOR.join(action.steps)
    links = " ".join(doc.get("url", "") for doc in action.docs)
    row["note"] = " ".join(part for part in (action.note, links) if part)
    return row


def build_rows(bundle: ReportBundle) -> List[Dict[str, str]]:
    """Flat rows for the whole report, in reading order."""
    rows: List[Dict[str, str]] = [_assessment_row(bundle)]
    rows.extend(_finding_row(finding) for finding in bundle.findings)
    rows.extend(_coverage_row(coverage) for coverage in bundle.coverage)
    rows.extend(_recommendation_row(action) for action in bundle.actions)
    return rows


def render_csv(bundle: ReportBundle) -> str:
    """Serialize a bundle to CSV text (without the BOM; see write_csv)."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS, lineterminator="\r\n",
                            extrasaction="ignore")
    writer.writeheader()
    for row in build_rows(bundle):
        writer.writerow({column: _cell(row.get(column, "")) for column in COLUMNS})
    return buffer.getvalue()


def encode_csv(text: str) -> bytes:
    """Bytes to write to disk: UTF-8 with BOM so spreadsheets agree on it."""
    return ("\ufeff" + text).encode("utf-8")
