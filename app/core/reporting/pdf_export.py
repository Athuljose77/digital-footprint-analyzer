"""PDF report export.

Rendered with Qt's own printing stack (``QPdfWriter`` + ``QTextDocument``),
which the desktop app already ships, so this adds no dependency and no
external process. Every value is HTML-escaped and was sanitized when the
bundle was built.
"""

import html
from pathlib import Path
from typing import List

from app.core.reporting.errors import ReportExportError
from app.core.reporting.models import ReportBundle

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")

_STATE_LABELS = {
    "completed": "Completed",
    "limited": "Completed with limitations",
    "failed": "Failed — not covered",
    "unavailable": "Unavailable — not covered",
    "skipped": "Skipped — not covered",
    "unknown": "Unknown",
}


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=False)


def _score_block(bundle: ReportBundle) -> str:
    assessment = bundle.assessment
    if assessment.score is None:
        return (
            "<p><b>Exposure score: not available</b><br>"
            f"{_esc(assessment.unavailable_reason)}</p>"
        )
    return (
        f"<p><b>Exposure score: {_esc(assessment.score)} / 100"
        f" &nbsp;·&nbsp; {_esc(assessment.band)}</b><br>"
        f"Raw points: {_esc(round(assessment.points, 2))} &nbsp;·&nbsp; "
        f"confidence: {_esc(assessment.confidence)}<br>"
        f"Methodology: {_esc(assessment.methodology_version)}</p>"
    )


def _metadata_table(bundle: ReportBundle) -> str:
    assessment = bundle.assessment
    rows = [
        ("Scan", assessment.scan_type or "—"),
        ("Target", assessment.target_label or "local device"),
        ("Status", assessment.status or "—"),
        ("Started", assessment.started_at or "—"),
        ("Finished", assessment.finished_at or "—"),
        ("Report generated", bundle.generated_at or "—"),
    ]
    body = "".join(
        f"<tr><td style='padding-right:12px;color:#555'>{_esc(label)}</td>"
        f"<td>{_esc(value)}</td></tr>"
        for label, value in rows
    )
    return f"<table cellspacing='0' cellpadding='2'>{body}</table>"


def _counts_table(bundle: ReportBundle) -> str:
    counts = bundle.assessment.counts
    if not counts:
        return ""
    labels = [
        ("distinct_issues", "Distinct issues"),
        ("confirmed", "Confirmed"),
        ("potential", "Reported, unverified"),
        ("inconclusive", "Inconclusive"),
        ("coverage_findings", "Coverage notes"),
        ("collection_failures", "Modules that failed"),
        ("unsupported_checks", "Checks unsupported here"),
    ]
    cells = "".join(
        f"<tr><td style='padding-right:12px;color:#555'>{_esc(label)}</td>"
        f"<td>{_esc(counts.get(key, 0))}</td></tr>"
        for key, label in labels
    )
    return f"<h2>Findings summary</h2><table cellspacing='0' cellpadding='2'>{cells}</table>"


def _severity_table(bundle: ReportBundle) -> str:
    breakdown = bundle.assessment.severity_breakdown
    if not breakdown:
        return ""
    cells = "".join(
        f"<td style='padding-right:14px'><b>{_esc(severity)}</b>: "
        f"{_esc(breakdown.get(severity, 0))}</td>"
        for severity in SEVERITY_ORDER if severity in breakdown
    )
    return f"<p>{cells}</p>"


def _coverage_table(bundle: ReportBundle) -> str:
    if not bundle.coverage:
        return ""
    rows = "".join(
        "<tr>"
        f"<td style='padding-right:12px'>{_esc(row.name)}</td>"
        f"<td style='padding-right:12px'>{_esc(_STATE_LABELS.get(row.state, row.state))}</td>"
        f"<td style='color:#555'>{_esc(row.note)}</td>"
        "</tr>"
        for row in bundle.coverage
    )
    return (
        "<h2>Module coverage</h2>"
        "<p style='color:#555'>A module that did not complete cannot clear a "
        "finding, and its findings are unknown rather than absent.</p>"
        f"<table cellspacing='0' cellpadding='3'>{rows}</table>"
    )


def _findings_block(bundle: ReportBundle) -> str:
    if not bundle.findings:
        reason = bundle.empty_reason or "No findings were recorded for this scan."
        return f"<h2>Findings</h2><p>None recorded. {_esc(reason)}</p>"

    parts: List[str] = ["<h2>Findings</h2>"]
    ordered = sorted(
        bundle.findings,
        key=lambda f: SEVERITY_ORDER.index(f.severity)
        if f.severity in SEVERITY_ORDER else len(SEVERITY_ORDER),
    )

    for finding in ordered:
        meta = " · ".join(part for part in (
            finding.module,
            finding.finding_type,
            finding.verification,
            f"confidence: {finding.confidence}",
            finding.status,
        ) if part)
        evidence = ""
        if finding.evidence:
            items = "".join(f"<li>{_esc(item)}</li>" for item in finding.evidence)
            evidence = f"<ul style='margin-top:2px'>{items}</ul>"
        explanation = ""
        if finding.why_it_matters:
            explanation = (f"<p style='margin:4px 0'><i>Why it matters:</i> "
                           f"{_esc(finding.why_it_matters)}</p>")
        description = ""
        if finding.description:
            description = f"<p style='margin:4px 0'>{_esc(finding.description)}</p>"

        parts.append(
            "<div style='margin-bottom:10px'>"
            f"<p style='margin:0'><b>[{_esc(finding.severity)}] "
            f"{_esc(finding.title)}</b></p>"
            f"<p style='margin:0;color:#555'>{_esc(meta)}</p>"
            f"{description}{explanation}{evidence}"
            "</div>"
        )
    return "".join(parts)


def _actions_block(bundle: ReportBundle) -> str:
    if not bundle.actions:
        return ""
    parts: List[str] = [
        "<h2>Recommended actions</h2>",
        "<p style='color:#555'>Marking an action complete is your own record; "
        "it is not a technical verification that the issue is gone.</p>",
    ]
    for action in bundle.actions:
        steps = "".join(f"<li>{_esc(step)}</li>" for step in action.steps)
        docs = "".join(
            f"<li>{_esc(doc.get('label', ''))} — {_esc(doc.get('url', ''))}</li>"
            for doc in action.docs
        )
        flags = []
        if action.verify_first:
            flags.append("check the evidence before acting")
        if not action.present_in_latest_scan:
            flags.append("no longer detected in the latest scan")
        if action.user_state and action.user_state != "pending":
            flags.append(f"marked {action.user_state} by you")
        flag_text = f"<p style='margin:0;color:#555'>({_esc('; '.join(flags))})</p>" if flags else ""

        parts.append(
            "<div style='margin-bottom:10px'>"
            f"<p style='margin:0'><b>{_esc(action.priority)} — "
            f"{_esc(action.title)}</b></p>"
            f"{flag_text}"
            f"<p style='margin:4px 0'>{_esc(action.why_it_matters)}</p>"
            f"<ol style='margin-top:2px'>{steps}</ol>"
            f"<ul>{docs}</ul>"
            "</div>"
        )
    return "".join(parts)


def _caveats_block(bundle: ReportBundle) -> str:
    parts: List[str] = []
    if bundle.assessment.caveats:
        items = "".join(f"<li>{_esc(c)}</li>" for c in bundle.assessment.caveats)
        parts.append("<h2>What this assessment does not cover</h2>"
                     f"<ul>{items}</ul>")
    if bundle.assessment.factors:
        rows = "".join(
            "<tr>"
            f"<td style='padding-right:12px;color:#555'>{_esc(factor.get('name', ''))}</td>"
            f"<td>{_esc(factor.get('detail', ''))}</td>"
            "</tr>"
            for factor in bundle.assessment.factors
        )
        parts.append("<h2>How this score was calculated</h2>"
                     f"<table cellspacing='0' cellpadding='3'>{rows}</table>")
    return "".join(parts)


def build_html(bundle: ReportBundle) -> str:
    """HTML source for the PDF. Also used for text-based verification."""
    notes = "".join(f"<li>{_esc(note)}</li>" for note in bundle.notes)
    return (
        "<html><body style='font-family:Helvetica,Arial,sans-serif;font-size:10pt'>"
        f"<h1 style='margin-bottom:2px'>{_esc(bundle.title)}</h1>"
        f"<p style='color:#555;margin-top:0'>{_esc(bundle.application)} · "
        f"report schema {_esc(bundle.schema_version)}</p>"
        "<h2>Assessment</h2>"
        f"{_metadata_table(bundle)}"
        f"{_score_block(bundle)}"
        f"{_severity_table(bundle)}"
        f"{_counts_table(bundle)}"
        f"{_caveats_block(bundle)}"
        f"{_coverage_table(bundle)}"
        f"{_findings_block(bundle)}"
        f"{_actions_block(bundle)}"
        "<h2>About this report</h2>"
        f"<ul>{notes}</ul>"
        "</body></html>"
    )


def render_pdf(bundle: ReportBundle, path: Path) -> Path:
    """Write the report as a PDF and return the path written.

    Qt renders text through the running application's font stack, so this
    requires an initialised ``QGuiApplication``. Without one Qt aborts the
    process, so the situation is detected and reported as an error instead.
    """
    from PySide6.QtGui import QFont, QGuiApplication, QPageLayout, QPageSize, QPdfWriter, QTextDocument
    from PySide6.QtCore import QMarginsF

    if QGuiApplication.instance() is None:
        raise ReportExportError(
            "PDF export needs the running application (Qt is not initialised). "
            "Export as JSON or CSV instead.")

    destination = Path(path)
    writer = QPdfWriter(str(destination))
    writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    writer.setPageMargins(QMarginsF(15, 15, 15, 15), QPageLayout.Unit.Millimeter)
    writer.setResolution(300)
    writer.setTitle(bundle.title)
    writer.setCreator(bundle.application)

    document = QTextDocument()
    document.setDefaultFont(QFont("Helvetica", 10))
    document.setHtml(build_html(bundle))

    # QTextDocument::print returns nothing; failures surface as an empty or
    # missing file, which the exporter checks after we return.
    document.print_(writer)

    # The PDF is flushed when the writer is destroyed, so drop both references
    # now instead of relying on scope exit.
    document.setParent(None)
    del document
    del writer

    return destination
