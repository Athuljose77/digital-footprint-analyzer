"""Assessment page: the exposure score and everything behind it.

Read-only. Every number shown comes from the RiskSummary produced by
app/core/risk, which is the same object the dashboard, the report exporters,
and scan history use.
"""

import datetime as _datetime
import re
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QTextBrowser,
    QVBoxLayout,
)

from app.core.remediation import ActionBoard, RemediationPlan
from app.core.reporting import (
    FORMAT_CSV,
    FORMAT_JSON,
    FORMAT_PDF,
    ReportExportError,
    build_report_bundle,
    export_report,
)
from app.core.risk.explanations import methodology_limits
from app.core.risk.models import RiskSummary
from app.ui import theme
from app.ui.pages.base import (
    FIELD_TEMPLATE,
    ThemedPage,
    badge_html,
    escape,
    severity_color,
)

EMPTY_TITLE = "No assessment yet"
EMPTY_BODY = ("Run a scan from Home or My Footprint. The assessment is built "
              "from the findings and the module coverage of the most recent "
              "scan, and nothing is stored outside this device.")

_STATE_COLORS = {
    "completed": "ok_text",
    "limited": "warn_text",
    "failed": "err_text",
    "unavailable": "warn_text",
    "skipped": "muted",
    "unknown": "muted",
}


class AssessmentPage(ThemedPage):
    """Displays the unified exposure assessment for the current scan."""

    def __init__(self, window=None, parent=None):
        super().__init__(window, parent)

        self.result = None
        self.risk: RiskSummary | None = None
        self.target = None
        self.last_export_path = None

        self.add_header(
            "Exposure Assessment",
            "One explainable score for the most recent scan, derived from its "
            "findings and the modules that actually ran.")

        score_card = self.add_card("assessment_score_card")
        self._layout.addWidget(score_card)
        score_box = QVBoxLayout(score_card)
        score_box.setContentsMargins(16, 14, 16, 14)
        score_box.setSpacing(6)

        top_row = QHBoxLayout()
        top_row.setSpacing(14)

        self.score_label = QLabel("—")
        self.score_label.setTextFormat(Qt.RichText)
        top_row.addWidget(self.score_label)

        verdict = QVBoxLayout()
        verdict.setSpacing(2)
        self.band_label = QLabel()
        self.band_label.setTextFormat(Qt.RichText)
        self.band_label.setWordWrap(True)
        verdict.addWidget(self.band_label)
        self.confidence_label = QLabel()
        self.confidence_label.setTextFormat(Qt.RichText)
        self.confidence_label.setWordWrap(True)
        verdict.addWidget(self.confidence_label)
        top_row.addLayout(verdict, stretch=1)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.pdf_btn = self.button("Export PDF")
        self.json_btn = self.button("Export JSON", primary=False)
        self.csv_btn = self.button("Export CSV", primary=False)
        self.actions_btn = self.button("Open action centre", primary=False)
        for button in (self.pdf_btn, self.json_btn, self.csv_btn,
                       self.actions_btn):
            buttons.addWidget(button)
        top_row.addLayout(buttons)
        score_box.addLayout(top_row)

        self.coverage_label = QLabel()
        self.coverage_label.setWordWrap(True)
        self.coverage_label.setTextFormat(Qt.RichText)
        score_box.addWidget(self.coverage_label)

        self.export_status = self.note("")
        score_box.addWidget(self.export_status)

        self.body = QTextBrowser()
        self.body.setOpenExternalLinks(False)
        self.body.setReadOnly(True)
        self.body.setStyleSheet("border: none; background: transparent;")
        self._layout.addWidget(self.body, stretch=1)

        self.pdf_btn.clicked.connect(lambda: self.export_with_dialog(FORMAT_PDF))
        self.json_btn.clicked.connect(lambda: self.export_with_dialog(FORMAT_JSON))
        self.csv_btn.clicked.connect(lambda: self.export_with_dialog(FORMAT_CSV))
        self.actions_btn.clicked.connect(self._open_actions)

        self.clear()

    # -- data -----------------------------------------------------------

    def clear(self):
        self.result = None
        self.risk = None
        self.target = None
        self._set_export_enabled(False)
        self.score_label.setText(
            f"<div style='font-size: 30px; font-weight: bold; "
            f"color: {theme.R('muted')};'>—</div>")
        self.band_label.setText(
            f"<b style='font-size: 15px;'>{escape(EMPTY_TITLE)}</b>")
        self.confidence_label.setText(
            f"<span style='color: {theme.R('muted')};'>{escape(EMPTY_BODY)}</span>")
        self.coverage_label.setText("")
        self.export_status.setText("")
        self.body.setHtml(
            f"<p style='color:{theme.R('muted')};'>No scan data yet.</p>")

    def set_assessment(self, result, risk: RiskSummary, target=None,
                       plan: RemediationPlan | None = None,
                       board: ActionBoard | None = None):
        """Show the assessment for one finished scan."""
        self.result = result
        self.risk = risk
        self.target = target
        self.plan = plan
        self.board = board
        self._set_export_enabled(True)
        self.export_status.setText("")
        self.refresh_theme()

    def refresh_theme(self):
        if self.risk is None:
            self.clear()
            return
        self.score_label.setText(self._score_html())
        self.band_label.setText(self._band_html())
        self.confidence_label.setText(self._confidence_html())
        self.coverage_label.setText(self._coverage_html())
        self.body.setHtml(self._body_html())

    # -- rendering ------------------------------------------------------

    def _require_risk(self) -> RiskSummary:
        """The risk summary these renderers need.

        They are only reached once an assessment is loaded, but raising a
        clear error beats dereferencing None if that ever stops being true.
        """
        if self.risk is None:
            raise RuntimeError("No assessment is loaded yet.")
        return self.risk

    def _score_html(self):
        risk = self._require_risk()
        if risk.score is None:
            color = theme.R("muted")
            return (f"<div style='font-size: 30px; font-weight: bold; "
                    f"color: {color};'>No score</div>")
        color = self._band_color(risk.score)
        return (f"<div style='font-size: 34px; font-weight: bold; color: {color};'>"
                f"{risk.score}<span style='font-size: 16px;'>/100</span></div>")

    def _band_html(self):
        risk = self._require_risk()
        color = self._band_color(risk.score) if risk.score is not None \
            else theme.R("muted")
        band = escape(risk.band)
        detail = (f"{risk.points:g} raw points · methodology "
                  f"{escape(risk.methodology_version)}")
        extra = ""
        if not risk.score_available and risk.unavailable_reason:
            extra = (f"<br><span style='color: {theme.R('muted')}; font-size: 11px;'>"
                     f"{escape(risk.unavailable_reason)}</span>")
        return (f"<b style='font-size: 16px; color: {color};'>{band}</b>"
                f"<br><span style='color: {theme.R('muted')}; font-size: 11px;'>"
                f"{escape(detail)}</span>{extra}")

    def _confidence_html(self):
        risk = self._require_risk()
        reasons = "; ".join(risk.confidence_reasons) or "no stated reasons"
        return (f"<span style='font-size: 12px;'>Assessment confidence: "
                f"<b>{escape(risk.confidence)}</b> "
                f"<span style='color: {theme.R('muted')};'>({escape(reasons)})</span>"
                "</span>")

    def _coverage_html(self):
        risk = self._require_risk()
        if not risk.modules:
            return (f"<span style='color: {theme.R('muted')};'>"
                    "No module coverage was recorded for this scan.</span>")
        done = [m for m in risk.modules
                if m.state in ("completed", "limited")]
        gaps = [m.name for m in risk.modules
                if m.state not in ("completed", "limited")]
        text = (f"Coverage: <b>{len(done)} of {len(risk.modules)}</b> module(s) "
                "produced usable results.")
        if gaps:
            text += (f" <span style='color: {theme.R('warn_text')};'>Not covered: "
                     f"{escape(', '.join(gaps))}.</span>")
        return text

    def _band_color(self, score):
        if score is None:
            return theme.R("muted")
        if score >= 76:
            return theme.R("sev_critical")
        if score >= 51:
            return theme.R("sev_high")
        if score >= 25:
            return theme.R("sev_medium")
        if score >= 1:
            return theme.R("sev_low")
        return theme.R("ok_text")

    def _body_html(self):
        risk = self._require_risk()
        muted = theme.R("muted")
        parts = []

        breakdown = " &nbsp; ".join(
            f"<b>{escape(name)}</b>: {count}"
            for name, count in (risk.severity_breakdown or {}).items())
        parts.append(
            f"<h3 style='margin-bottom:4px;'>Distinct issues by severity</h3>"
            f"<p style='margin-top:0;'>{breakdown or 'None'}</p>")

        counts = risk.counts
        rows = [
            ("Distinct issues", counts.get("distinct_issues", 0)),
            ("Confirmed by direct evidence", counts.get("confirmed", 0)),
            ("Reported but unverified", counts.get("potential", 0)),
            ("Inconclusive", counts.get("inconclusive", 0)),
            ("Coverage notes", counts.get("coverage_findings", 0)),
            ("Modules that failed", counts.get("collection_failures", 0)),
            ("Checks unsupported on this platform",
             counts.get("unsupported_checks", 0)),
        ]
        parts.append(
            "<h3 style='margin-bottom:4px;'>Counts</h3>"
            "<table cellspacing='0' cellpadding='3'>"
            + "".join(
                f"<tr><td style='color:{muted};padding-right:12px;'>{escape(label)}</td>"
                f"<td>{escape(value)}</td></tr>" for label, value in rows)
            + "</table>")

        if risk.factors:
            parts.append(
                "<h3 style='margin-bottom:4px;'>How this score was calculated</h3>"
                "<table cellspacing='0' cellpadding='3'>"
                + "".join(
                    f"<tr><td style='color:{muted};padding-right:12px;'>"
                    f"{escape(factor.name)}</td><td>{escape(factor.detail)}</td></tr>"
                    for factor in risk.factors)
                + "</table>")

        if risk.caveats or methodology_limits():
            items = "".join(f"<li>{escape(caveat)}</li>"
                            for caveat in risk.caveats)
            standing = "".join(
                f"<li style='color:{muted};'>{escape(limit)}</li>"
                for limit in methodology_limits())
            parts.append(
                "<h3 style='margin-bottom:4px;'>What this assessment does not cover</h3>"
                f"<ul style='margin-top:0;'>{items}{standing}</ul>")

        if risk.modules:
            parts.append(
                "<h3 style='margin-bottom:4px;'>Module coverage</h3>"
                "<table cellspacing='0' cellpadding='3'>"
                + "".join(
                    f"<tr><td style='padding-right:12px;'>{escape(module.name)}</td>"
                    f"<td style='padding-right:12px;color:"
                    f"{theme.R(_STATE_COLORS.get(module.state, 'muted'))};'>"
                    f"{escape(module.state)}</td>"
                    f"<td style='color:{muted};'>{escape(module.note)}</td></tr>"
                    for module in risk.modules)
                + "</table>")

        if risk.top_findings:
            parts.append("<h3 style='margin-bottom:4px;'>Top issues by weight</h3>")
            for component in risk.top_findings:
                parts.append(
                    "<div style='margin-bottom:8px;'>"
                    f"<p style='margin:0;'>{badge_html(escape(component.severity), severity_color(component.severity))} "
                    f"<b>{escape(component.title)}</b> "
                    f"<span style='color:{muted};'>· {escape(component.module)} · "
                    f"{escape(component.verification)} · weight "
                    f"{component.contribution:g}</span></p>"
                    f"<p style='margin:2px 0 0 0; color:{muted}; font-size: 11px;'>"
                    f"{escape(component.why_it_matters)}</p></div>")
        else:
            parts.append(
                "<h3 style='margin-bottom:4px;'>Top issues by weight</h3>"
                f"<p style='color:{muted};'>No issues contributed to this score.</p>")

        return "".join(parts)

    # -- export ---------------------------------------------------------

    def _set_export_enabled(self, enabled):
        for button in (self.pdf_btn, self.json_btn, self.csv_btn):
            button.setEnabled(bool(enabled))

    def suggested_name(self, fmt):
        stamp = _datetime.datetime.now().strftime("%Y%m%d-%H%M")
        scan_type = (getattr(self.result, "scan_type", "") or "scan")
        slug = re.sub(r"[^a-z0-9]+", "-", scan_type.lower()).strip("-") or "scan"
        extension = {FORMAT_PDF: "pdf", FORMAT_JSON: "json", FORMAT_CSV: "csv"}[fmt]
        return f"footprint-{slug}-{stamp}.{extension}"

    def export(self, fmt, path):
        """Write the report. Returns the path or raises ReportExportError."""
        if self.result is None:
            raise ReportExportError("There is no scan to report on yet.")
        bundle = build_report_bundle(
            self.result, risk_summary=self.risk,
            plan=getattr(self, "plan", None), board=getattr(self, "board", None),
            target=self.target)
        written = export_report(bundle, path, fmt)
        self.last_export_path = written
        return written

    def export_with_dialog(self, fmt):
        if self.result is None:
            QMessageBox.information(
                self, "Nothing to export",
                "Run a scan first — there is no assessment to export yet.")
            return None

        start = str(Path.home() / self.suggested_name(fmt))
        filters = {
            FORMAT_PDF: "PDF report (*.pdf)",
            FORMAT_JSON: "JSON data (*.json)",
            FORMAT_CSV: "CSV spreadsheet (*.csv)",
        }[fmt]
        path, _ = QFileDialog.getSaveFileName(
            self, "Save report", start, filters)
        if not path:
            self.export_status.setText("Export cancelled.")
            return None
        try:
            written = self.export(fmt, path)
        except ReportExportError as error:
            self.export_status.setText(f"Export failed: {error}")
            QMessageBox.warning(self, "Export failed", str(error))
            return None
        except Exception as error:  # unexpected: never crash the window
            self.export_status.setText(f"Export failed: {error}")
            QMessageBox.warning(self, "Export failed", str(error))
            return None

        self.export_status.setText(f"Report saved to {written}")
        QMessageBox.information(self, "Report saved",
                                f"Report written to:\n{written}")
        return written

    def _open_actions(self):
        if self.window is not None and hasattr(self.window, "show_page"):
            self.window.show_page("actions")
