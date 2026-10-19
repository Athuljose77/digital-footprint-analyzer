"""Evidence explorer: search, filter, sort, and inspect every finding.

The explorer works on the current scan's findings, or on any stored scan's
findings from the history page. It never re-derives severities or scores: it
shows the finding's own provenance fields, which the findings normalizer set
when the scan ran.
"""

from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
)

from app.core.risk.explanations import why_it_matters
from app.ui import theme
from app.ui.pages.base import (
    FIELD_TEMPLATE,
    TABLE_TEMPLATE,
    ThemedPage,
    badge_html,
    escape,
    severity_color,
)

SEVERITY_FILTERS = ("All severities", "Critical", "High", "Medium", "Low", "Info")
VERIFICATION_FILTERS = (
    "All verification",
    "direct-observation",
    "provider-verified",
    "provider-reported",
    "unconfirmed",
    "not-applicable",
    "unknown",
)
CONFIDENCE_FILTERS = ("All confidence", "high", "medium", "low")
SORTS = ("Severity", "Module", "Confidence", "Title")

_SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2, "unknown": 3}

COLUMNS = ("Severity", "Finding", "Module", "Verification", "Confidence",
           "Evidence")


class EvidencePage(ThemedPage):
    """Searchable, filterable table of findings with a detail pane."""

    def __init__(self, window=None, parent=None):
        super().__init__(window, parent)

        self._findings: List[object] = []
        self._source_label = ""
        self._rows: List[object] = []

        self.add_header(
            "Evidence Explorer",
            "Every finding from the selected scan, with where it came from and "
            "how strongly it is supported.")

        controls = QHBoxLayout()
        controls.setSpacing(8)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search titles, modules, evidence…")
        self.search.setClearButtonEnabled(True)
        controls.addWidget(self.search, stretch=2)

        self.severity_filter = QComboBox()
        self.severity_filter.addItems(SEVERITY_FILTERS)
        controls.addWidget(self.severity_filter)

        self.module_filter = QComboBox()
        self.module_filter.addItems(["All modules"])
        controls.addWidget(self.module_filter)

        self.verification_filter = QComboBox()
        self.verification_filter.addItems(VERIFICATION_FILTERS)
        controls.addWidget(self.verification_filter)

        self.confidence_filter = QComboBox()
        self.confidence_filter.addItems(CONFIDENCE_FILTERS)
        controls.addWidget(self.confidence_filter)

        self.sort_combo = QComboBox()
        self.sort_combo.addItems(SORTS)
        controls.addWidget(self.sort_combo)

        self._layout.addLayout(controls)
        for widget in (self.search, self.severity_filter, self.module_filter,
                       self.verification_filter, self.confidence_filter,
                       self.sort_combo):
            self.themed(widget, FIELD_TEMPLATE)

        self.count_label = QLabel()
        self.themed(self.count_label, "color: {muted}; font-size: 11px;")
        self._layout.addWidget(self.count_label)

        splitter = QSplitter(Qt.Horizontal)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(False)
        self.themed(self.table, TABLE_TEMPLATE)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        splitter.addWidget(self.table)

        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(False)
        self.detail.setReadOnly(True)
        self.detail.setMinimumWidth(320)
        self.detail.setStyleSheet("border: none; background: transparent;")
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        self._layout.addWidget(splitter, stretch=1)

        self.search.textChanged.connect(self._apply_filters)
        for combo in (self.severity_filter, self.module_filter,
                      self.verification_filter, self.confidence_filter,
                      self.sort_combo):
            combo.currentIndexChanged.connect(self._apply_filters)
        self.table.itemSelectionChanged.connect(self._show_selected)

        self.clear()

    # -- data -----------------------------------------------------------

    def clear(self):
        self._findings = []
        self._source_label = ""
        self._populate_module_filter([])
        self._apply_filters()

    def show_result(self, result, source_label="Current scan"):
        """Show every finding from a scan result."""
        self._findings = list(getattr(result, "findings", None) or [])
        self._source_label = source_label
        self._populate_module_filter(self._findings)
        self._apply_filters()

    def show_findings(self, findings, source_label="Selected scan"):
        """Show an explicit list of findings (used for stored scans)."""
        self._findings = list(findings or [])
        self._source_label = source_label
        self._populate_module_filter(self._findings)
        self._apply_filters()

    def refresh_theme(self):
        self._apply_filters()

    # -- filtering ------------------------------------------------------

    def _populate_module_filter(self, findings):
        modules = sorted({self._module_of(f) for f in findings if self._module_of(f)})
        self.module_filter.blockSignals(True)
        current = self.module_filter.currentText()
        self.module_filter.clear()
        self.module_filter.addItem("All modules")
        self.module_filter.addItems(modules)
        index = self.module_filter.findText(current)
        self.module_filter.setCurrentIndex(index if index >= 0 else 0)
        self.module_filter.blockSignals(False)

    @staticmethod
    def _module_of(finding):
        return str(getattr(finding, "source_module", "") or "").strip() or "unknown"

    def _matches(self, finding):
        query = self.search.text().strip().lower()
        if query:
            haystack = " ".join(str(part) for part in (
                getattr(finding, "title", ""),
                getattr(finding, "description", ""),
                getattr(finding, "finding_type", ""),
                getattr(finding, "category", ""),
                self._module_of(finding),
                " ".join(str(s) for s in (getattr(finding, "sources", None) or [])),
                " ".join(str(e) for e in (getattr(finding, "evidence", None) or [])),
            )).lower()
            if query not in haystack:
                return False

        severity = self.severity_filter.currentText()
        if severity != SEVERITY_FILTERS[0]:
            if str(getattr(finding, "severity", "")).strip().capitalize() != severity:
                return False

        module = self.module_filter.currentText()
        if module != "All modules" and self._module_of(finding) != module:
            return False

        verification = self.verification_filter.currentText()
        if verification != VERIFICATION_FILTERS[0]:
            if str(getattr(finding, "verification", "") or "unknown") != verification:
                return False

        confidence = self.confidence_filter.currentText()
        if confidence != CONFIDENCE_FILTERS[0]:
            if str(getattr(finding, "confidence", "") or "unknown") != confidence:
                return False
        return True

    def _sorted(self, findings):
        mode = self.sort_combo.currentText()
        if mode == "Module":
            return sorted(findings, key=lambda f: (self._module_of(f),
                                                   _severity_rank(f)))
        if mode == "Confidence":
            return sorted(findings, key=lambda f: (
                _CONFIDENCE_RANK.get(str(getattr(f, "confidence", "") or "unknown"), 3),
                _severity_rank(f)))
        if mode == "Title":
            return sorted(findings, key=lambda f: str(getattr(f, "title", "")).lower())
        return sorted(findings, key=_severity_rank)

    def _apply_filters(self):
        matched = [f for f in self._findings if self._matches(f)]
        self._rows = self._sorted(matched)
        self._fill_table()
        self._update_count(len(matched))

    def _update_count(self, matched):
        total = len(self._findings)
        if not total:
            self.count_label.setText(
                "No scan data yet — run a scan or open a stored scan from History.")
            return
        source = f" from {self._source_label}" if self._source_label else ""
        if matched == total:
            self.count_label.setText(f"Showing all {total} finding(s){source}.")
        else:
            self.count_label.setText(
                f"Showing {matched} of {total} finding(s){source}.")
        if not matched:
            self.count_label.setText(
                f"No findings match these filters ({total} in {self._source_label or 'this scan'}).")

    # -- table ----------------------------------------------------------

    def _fill_table(self):
        self.table.setRowCount(0)
        if not self._rows:
            self.detail.setHtml(self._empty_html())
            return

        self.table.setRowCount(len(self._rows))
        for row, finding in enumerate(self._rows):
            values = (
                str(getattr(finding, "severity", "") or "Info"),
                str(getattr(finding, "title", "") or ""),
                self._module_of(finding),
                str(getattr(finding, "verification", "") or "unknown"),
                str(getattr(finding, "confidence", "") or "unknown"),
                str(len(getattr(finding, "evidence", None) or [])),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column in (0, 4, 5):
                    item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, column, item)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.selectRow(0)

    def _empty_html(self):
        muted = theme.R("muted")
        if not self._findings:
            return (f"<p style='color:{muted};'>No findings to show. Run a scan, "
                    "or open a stored scan from the History page.</p>")
        return (f"<p style='color:{muted};'>No findings match the current "
                "filters. Clear a filter or the search box to see the rest.</p>")

    def _show_selected(self):
        rows = self.table.selectionModel().selectedRows() if \
            self.table.selectionModel() else []
        if not rows:
            self.detail.setHtml(self._empty_html())
            return
        index = rows[0].row()
        if index >= len(self._rows):
            return
        self.detail.setHtml(self._detail_html(self._rows[index]))

    def _detail_html(self, finding):
        muted = theme.R("muted")
        severity = str(getattr(finding, "severity", "") or "Info")
        module = self._module_of(finding)
        verification = str(getattr(finding, "verification", "") or "unknown")
        confidence = str(getattr(finding, "confidence", "") or "unknown")
        sources = [str(s) for s in (getattr(finding, "sources", None) or [])]

        meta = [
            ("Module", module),
            ("Type", str(getattr(finding, "finding_type", "") or "—")),
            ("Category", str(getattr(finding, "category", "") or "—")),
            ("Verification", verification),
            ("Confidence", confidence),
            ("Status", str(getattr(finding, "status", "") or "—")),
            ("Reported by", ", ".join(sources) or module),
        ]
        parts = [
            f"<p style='margin-bottom:2px;'>"
            f"{badge_html(escape(severity), severity_color(severity))} "
            f"<b style='font-size: 13px;'>{escape(getattr(finding, 'title', ''))}</b></p>",
            f"<p style='color:{muted}; margin-top:2px;'>"
            f"{escape(getattr(finding, 'description', ''))}</p>",
            "<table cellspacing='0' cellpadding='2'>" + "".join(
                f"<tr><td style='color:{muted}; padding-right:10px;'>{escape(label)}</td>"
                f"<td>{escape(value)}</td></tr>" for label, value in meta)
            + "</table>",
        ]

        why = str(getattr(finding, "why_it_matters", "") or "") or why_it_matters(finding)
        if why:
            parts.append(f"<p style='margin-top:8px;'><i>Why it matters:</i> "
                         f"{escape(why)}</p>")

        evidence = list(getattr(finding, "evidence", None) or [])
        if evidence:
            parts.append("<p style='margin-bottom:2px;'><b>Evidence</b></p><ul style='margin-top:0;'>"
                         + "".join(f"<li>{escape(self._render_item(item))}</li>"
                                   for item in evidence[:25])
                         + "</ul>")
            if len(evidence) > 25:
                parts.append(f"<p style='color:{muted};'>… and {len(evidence) - 25} "
                             "more item(s).</p>")
        else:
            parts.append(f"<p style='color:{muted};'>No evidence items were recorded "
                         "for this finding.</p>")

        limitations = str(getattr(finding, "limitations", "") or "")
        if limitations:
            parts.append(f"<p style='color:{muted};'><b>Limitations:</b> "
                         f"{escape(limitations)}</p>")

        identity = str(getattr(finding, "identity_key", "") or "")
        if identity:
            parts.append(f"<p style='color:{muted}; font-size: 10px;'>"
                         f"Identity key {escape(identity[:18])}… — stable across "
                         "scans, used to match this finding in comparisons.</p>")
        return "".join(parts)

    @staticmethod
    def _render_item(item):
        if isinstance(item, dict):
            return "; ".join(f"{key}: {value}" for key, value in item.items())
        return str(item)

    # -- testing helpers ------------------------------------------------

    def visible_findings(self) -> List[object]:
        """Findings currently shown, after filters and sorting."""
        return list(self._rows)

    def visible_titles(self):
        return [str(getattr(f, "title", "")) for f in self._rows]

    def detail_text(self):
        return self.detail.toPlainText()

    def selected_title(self) -> Optional[str]:
        rows = self.table.selectionModel().selectedRows() if \
            self.table.selectionModel() else []
        if not rows:
            return None
        return str(getattr(self._rows[rows[0].row()], "title", ""))


def _severity_rank(finding):
    return _SEVERITY_RANK.get(str(getattr(finding, "severity", "")).strip().capitalize(), 5)
