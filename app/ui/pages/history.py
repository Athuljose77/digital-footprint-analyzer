"""Scan history: stored scans, deletion, and comparison.

Everything on this page is local. The store is injectable so tests never touch
real user data, and the page always states where the database lives.
"""

from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
)

from app.core.history import (
    HistoryStoreError,
    ScanComparison,
    ScanHistoryStore,
    change_label,
    compare_scans,
    default_db_path,
)
from app.core.history.compare import MODIFIED, NEW, NOT_RECHECKED, RESOLVED
from app.ui import theme
from app.ui.pages.base import (
    TABLE_TEMPLATE,
    ThemedPage,
    badge_html,
    escape,
    severity_color,
)

COLUMNS = ("When", "Scan", "Target", "Score", "Band", "Status", "Findings")

_CHANGE_COLORS = {
    NEW: "sev_high",
    MODIFIED: "sev_medium",
    RESOLVED: "ok_text",
    NOT_RECHECKED: "warn_text",
}


class HistoryPage(ThemedPage):
    """Stored scans with an honest two-scan comparison."""

    def __init__(self, window=None, store: Optional[ScanHistoryStore] = None,
                 parent=None):
        super().__init__(window, parent)

        self.store = store if store is not None else self._open_default_store()
        self.records: List[object] = []
        self.last_comparison: Optional[ScanComparison] = None
        self.error = ""
        self.storage_problem = ""

        self.add_header(
            "Scan History",
            "Every completed scan is stored on this device so you can see what "
            "changed. Nothing is uploaded, and you can delete any entry or "
            "clear the whole history.")

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.compare_btn = self.button("Compare two scans")
        self.refresh_btn = self.button("Refresh", primary=False)
        self.open_btn = self.button("Open in Evidence", primary=False)
        self.delete_btn = self.button("Delete selected", primary=False)
        self.clear_btn = self.button("Clear all history", primary=False)
        for button in (self.compare_btn, self.refresh_btn, self.open_btn,
                       self.delete_btn, self.clear_btn):
            controls.addWidget(button)
        controls.addStretch(1)
        self._layout.addLayout(controls)

        self.count_label = QLabel()
        self.count_label.setWordWrap(True)
        self.themed(self.count_label, "color: {muted}; font-size: 11px;")
        self._layout.addWidget(self.count_label)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.themed(self.table, TABLE_TEMPLATE)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setMinimumHeight(200)
        self._layout.addWidget(self.table)

        comparison_card = self.add_card("history_comparison_card")
        comparison_box = QVBoxLayout(comparison_card)
        comparison_box.setContentsMargins(14, 12, 14, 12)
        comparison_box.setSpacing(6)
        heading = QLabel("<b>Comparison</b>")
        heading.setStyleSheet("font-size: 13px;")
        comparison_box.addWidget(heading)
        self.comparison_view = QTextBrowser()
        self.comparison_view.setReadOnly(True)
        self.comparison_view.setOpenExternalLinks(False)
        self.comparison_view.setStyleSheet("border: none; background: transparent;")
        self.comparison_view.setMinimumHeight(160)
        comparison_box.addWidget(self.comparison_view)
        self._layout.addWidget(comparison_card, stretch=1)

        self.storage_note = self.note(f"History file: {default_db_path()}")
        self._layout.addWidget(self.storage_note)

        self.compare_btn.clicked.connect(self.compare_selected)
        self.refresh_btn.clicked.connect(self.refresh)
        self.delete_btn.clicked.connect(lambda: self.delete_selected(confirm=True))
        self.clear_btn.clicked.connect(lambda: self.clear_all(confirm=True))
        self.open_btn.clicked.connect(self.open_in_evidence)
        self.table.itemSelectionChanged.connect(self._update_buttons)

        self.refresh()

    # -- data -----------------------------------------------------------

    @staticmethod
    def _open_default_store():
        """Open the on-device store, tolerating a storage failure.

        A machine where the data directory cannot be created must still show
        the page and say so, rather than refusing to start.
        """
        try:
            return ScanHistoryStore()
        except HistoryStoreError:
            return None

    def set_store(self, store: ScanHistoryStore):
        self.store = store
        if store is not None:
            self.storage_note.setText(f"History file: {store.db_path}")
        self.refresh()

    def refresh(self):
        """Reload the stored scans from disk."""
        if self.store is None:
            self.records = []
            self.error = self.storage_problem or "History storage is unavailable."
        else:
            try:
                self.records = self.store.list_scans()
                self.error = ""
            except HistoryStoreError as error:
                self.records = []
                self.error = str(error)
        self._fill_table()
        self._update_buttons()
        if not self.last_comparison:
            self.comparison_view.setHtml(self._placeholder_html())

    def report_storage_problem(self, message: str):
        """Surface a write failure from the window without losing it."""
        self.storage_problem = str(message)
        self._fill_table()

    @property
    def effective_error(self) -> str:
        return getattr(self, "error", "") or getattr(self, "storage_problem", "")

    def refresh_theme(self):
        self._fill_table()
        if self.last_comparison:
            self.show_comparison(self.last_comparison)
        else:
            self.comparison_view.setHtml(self._placeholder_html())

    # -- table ----------------------------------------------------------

    def _fill_table(self):
        self.table.setRowCount(0)
        if self.effective_error:
            self.count_label.setText(
                f"History problem: {self.effective_error}")
            return

        total = len(self.records)
        if not total:
            self.count_label.setText(
                "No scans stored yet. Completed scans appear here.")
            return

        self.count_label.setText(
            f"{total} stored scan(s). Select two rows to compare them, or one "
            "to open its findings in the evidence explorer.")

        self.table.setRowCount(total)
        for row, record in enumerate(self.records):
            score = "—" if record.score is None else str(record.score)
            values = (
                _pretty_time(record.finished_at),
                record.scan_type or "—",
                record.target_label or "local device",
                score,
                record.band or ("Not scored" if record.score is None else "—"),
                record.status or "—",
                str(len(record.findings)),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column in (3, 4, 5, 6):
                    item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, column, item)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)

    def selected_records(self) -> List[object]:
        rows = sorted({index.row() for index in
                       self.table.selectionModel().selectedRows()}) \
            if self.table.selectionModel() else []
        return [self.records[row] for row in rows if row < len(self.records)]

    def _update_buttons(self):
        selected = len(self.selected_records())
        has_records = bool(self.records) and not self.effective_error
        self.compare_btn.setEnabled(selected == 2)
        self.delete_btn.setEnabled(selected >= 1)
        self.open_btn.setEnabled(selected == 1)
        self.clear_btn.setEnabled(has_records)

    # -- actions --------------------------------------------------------

    def compare_selected(self, confirm: bool = True):
        """Compare exactly two selected scans, older first."""
        records = self.selected_records()
        if len(records) != 2:
            self.comparison_view.setHtml(
                f"<p style='color:{theme.R('muted')};'>Select exactly two "
                "stored scans (Ctrl-click) to compare them.</p>")
            return None

        older, newer = sorted(records, key=lambda r: (r.finished_at, r.id))
        comparison = compare_scans(older, newer)
        self.last_comparison = comparison
        self.show_comparison(comparison)
        return comparison

    def show_comparison(self, comparison: ScanComparison):
        self.comparison_view.setHtml(self._comparison_html(comparison))

    def delete_selected(self, confirm: bool = True) -> int:
        records = self.selected_records()
        if not records:
            return 0
        if self.store is None:
            self.count_label.setText("History storage is unavailable.")
            return 0
        if confirm:
            answer = QMessageBox.question(
                self, "Delete scans",
                f"Delete {len(records)} stored scan(s)? This cannot be undone.")
            if answer != QMessageBox.Yes:
                return 0
        deleted = 0
        try:
            for record in records:
                if self.store.delete_scan(record.id):
                    deleted += 1
        except HistoryStoreError as error:
            self.count_label.setText(f"Could not delete: {error}")
            return deleted
        self.last_comparison = None
        self.refresh()
        self.count_label.setText(
            f"Deleted {deleted} stored scan(s). "
            f"{len(self.records)} remaining.")
        return deleted

    def clear_all(self, confirm: bool = True) -> int:
        if self.store is None:
            self.count_label.setText("History storage is unavailable.")
            return 0
        if confirm:
            answer = QMessageBox.question(
                self, "Clear history",
                "Delete every stored scan on this device? This cannot be undone.")
            if answer != QMessageBox.Yes:
                return 0
        try:
            removed = self.store.clear()
        except HistoryStoreError as error:
            self.count_label.setText(f"Could not clear history: {error}")
            return 0
        self.last_comparison = None
        self.refresh()
        self.count_label.setText(f"Cleared {removed} stored scan(s).")
        return removed

    def open_in_evidence(self) -> bool:
        records = self.selected_records()
        if len(records) != 1:
            return False
        record = records[0]
        if self.window is not None and hasattr(self.window, "show_stored_findings"):
            self.window.show_stored_findings(record)
            return True
        return False

    # -- rendering ------------------------------------------------------

    def _placeholder_html(self):
        return (f"<p style='color:{theme.R('muted')};'>No comparison yet. "
                "Select two scans and choose “Compare two scans”.</p>")

    def _comparison_html(self, comparison: ScanComparison):
        muted = theme.R("muted")
        parts = [f"<p style='margin-top:0;'><b>{escape(comparison.headline)}</b></p>"]
        parts.append(
            f"<p style='color:{muted}; margin-top:0;'>{escape(comparison.score_note)}"
            f"</p>")

        if comparison.score_delta is not None:
            delta = comparison.score_delta
            color = theme.R("sev_high") if delta > 0 else \
                (theme.R("ok_text") if delta < 0 else muted)
            parts.append(
                f"<p>Exposure score: {escape(comparison.score_before)} → "
                f"{escape(comparison.score_after)} "
                f"<b style='color:{color};'>({'+' if delta > 0 else ''}{delta})</b></p>")

        counts = comparison.counts
        chips = []
        for kind in (NEW, MODIFIED, RESOLVED, NOT_RECHECKED, "unchanged"):
            if counts.get(kind):
                chips.append(badge_html(
                    f"{counts[kind]} {change_label(kind).lower()}",
                    theme.R(_CHANGE_COLORS.get(kind, "muted"))))
        if chips:
            parts.append("<p>" + " ".join(chips) + "</p>")

        parts.append(f"<p style='color:{muted};'>{escape(comparison.resolved_note)}"
                     "</p>")

        if comparison.coverage_changes:
            parts.append("<p style='margin-bottom:2px;'><b>Coverage changes</b></p>"
                         "<ul style='margin-top:0;'>"
                         + "".join(
                             f"<li>{escape(change.name)}: "
                             f"{escape(change.before)} → <b>{escape(change.after)}</b></li>"
                             for change in comparison.coverage_changes)
                         + "</ul>")

        interesting = [c for c in comparison.changes
                       if c.change in (NEW, MODIFIED, RESOLVED, NOT_RECHECKED)]
        if interesting:
            parts.append("<p style='margin-bottom:2px;'><b>Findings</b></p>")
            for change in interesting[:60]:
                color = theme.R(_CHANGE_COLORS.get(change.change, "muted"))
                severity = change.severity_after or change.severity_before or "—"
                detail = ""
                if change.severity_before and change.severity_after and \
                        change.severity_before != change.severity_after:
                    detail = (f" <span style='color:{muted};'>({escape(change.severity_before)}"
                              f" → {escape(change.severity_after)})</span>")
                parts.append(
                    f"<p style='margin:2px 0;'>{badge_html(escape(change_label(change.change)), color)} "
                    f"{badge_html(escape(str(severity)), severity_color(severity))} "
                    f"{escape(change.title)}{detail} "
                    f"<span style='color:{muted};'>· {escape(change.module)}</span>"
                    f"{f'<br><span style=\"color:{muted};font-size:11px;\">{escape(change.note)}</span>' if change.note else ''}</p>")
            if len(interesting) > 60:
                parts.append(f"<p style='color:{muted};'>… and "
                             f"{len(interesting) - 60} more change(s).</p>")
        return "".join(parts)

    # -- testing helpers ------------------------------------------------

    def row_values(self):
        values = []
        for row in range(self.table.rowCount()):
            values.append([self.table.item(row, column).text()
                           for column in range(len(COLUMNS))])
        return values

    def count_text(self) -> str:
        return self.count_label.text()

    def comparison_text(self) -> str:
        return self.comparison_view.toPlainText()

    def select_rows(self, *rows):
        """Select several rows at once (Qt clears the selection per call)."""
        from PySide6.QtCore import QItemSelectionModel

        self.table.clearSelection()
        model = self.table.selectionModel()
        flags = (QItemSelectionModel.Select | QItemSelectionModel.Rows)
        for row in rows:
            model.select(self.table.model().index(row, 0), flags)
        self._update_buttons()


def _pretty_time(value: str) -> str:
    """Render a stored ISO timestamp as something readable."""
    text = str(value or "")
    if not text:
        return "—"
    try:
        from datetime import datetime

        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.strftime("%d %b %Y, %H:%M")
    except ValueError:
        return text
