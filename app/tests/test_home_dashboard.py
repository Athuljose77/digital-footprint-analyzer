"""Dashboard tests for the Home overview redesign.

Covers scan cards, overview rendering, checklist navigation, session
history bounds, and the history dialog. Presentation-only; scan
semantics untouched.
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from PySide6.QtWidgets import QApplication

import app.ui.main_window as main_window_module
from app.ui.main_window import MainWindow
from app.models.common import Finding, FootprintData, ScanResult
from app.services.system_service import DEFAULT_PROCESS_COLLECTOR_MODE

app = QApplication.instance()
if app is None:
    app = QApplication([])


def _finding(title, severity="Info", category="Observation"):
    return Finding(
        finding_id=f"finding-{title}",
        finding_type="Test Type",
        title=title,
        description=f"Description for {title}",
        evidence=[title],
        severity=severity,
        status="Informational",
        category=category,
    )


def _footprint(category, subcategory, value):
    return FootprintData(
        category=category,
        subcategory=subcategory,
        source="Test Source",
        data_type="String",
        value=value,
        sensitivity="Low",
    )


def _result(scan_type="System", status="COMPLETED", findings=(), footprint=()):
    categories = {"System": "System Footprint", "Browser": "Browser Footprint",
                  "File & Metadata": "File & Metadata Footprint",
                  "Full Scan": "Unified Footprint"}.get(scan_type, "Test")
    return ScanResult(
        scan_id=f"{scan_type}-dash-1",
        analysis_mode="My Footprint",
        scan_type=scan_type,
        scan_category=categories,
        status=status,
        message="done",
        footprint_data=list(footprint),
        findings=list(findings),
    )


class TestHomeDashboard(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    def test_default_landing_page_is_home_dashboard(self):
        self.assertEqual(self.window.pages.currentIndex(), 0)
        self.assertEqual(self.window.sidebar.currentRow(), 0)

    def test_sidebar_branding(self):
        self.assertIn("Digital Footprint", self.window.sidebar_logo.text())
        self.assertIn("Analyzer", self.window.sidebar_logo.text())
        self.assertIn("privacy", self.window.sidebar_tagline.text().lower())
        self.assertEqual(self.window.sidebar.count(), 4)

    def test_hero_reference_accents(self):
        emblem = self.window.hero_emblem.pixmap()
        self.assertIsNotNone(emblem)
        self.assertFalse(emblem.isNull())
        self.assertIn("ANALYZE", self.window.hero_tagline.text())
        self.assertIn("STAY IN CONTROL", self.window.hero_tagline.text())

    def test_scan_cards_single_frame_and_visible_action(self):
        from PySide6.QtWidgets import QFrame
        for key, btn in self.window.home_cards.items():
            card = self.window.home_card_frames[key]
            self.assertIsInstance(card, QFrame)
            self.assertEqual(card.frameShape(), QFrame.NoFrame)
            self.assertGreaterEqual(btn.width(), 32)
            self.assertIn("2dd4bf", btn.styleSheet())

    def test_stat_mini_cards_have_borders(self):
        # Qt re-serializes cell borders per-side, so assert the normalized form.
        self.window.on_scan_complete(_result())
        html = self.window.dashboard_overview.toHtml()
        self.assertIn("Total Findings", html)
        self.assertIn("border-top-style:solid", html)

    def test_checklist_rows_are_panels(self):
        from PySide6.QtWidgets import QFrame
        panels = [w for w in self.window.findChildren(QFrame)
                  if w.styleSheet() and "border-radius: 6px" in w.styleSheet()]
        self.assertGreaterEqual(len(panels), 3)

    def test_empty_state_before_any_scan(self):
        html = self.window.dashboard_overview.toHtml()
        self.assertIn("Run a scan", html)
        self.assertEqual(self.window.recent_scans_table.rowCount(), 0)
        self.assertEqual(self.window._scan_history, [])

    def test_four_scan_cards_present(self):
        self.assertEqual(
            set(self.window.home_cards),
            {"system", "browser", "file", "full"},
        )
        for btn in self.window.home_cards.values():
            self.assertTrue(btn.isEnabled())

    def test_system_card_starts_scan(self):
        with patch.object(main_window_module, "ScanWorker") as mock_worker_cls:
            self.window.home_cards["system"].click()
        # Scan type and target are the contract; the call also forwards the
        # saved process-collector preference.
        self.assertEqual(mock_worker_cls.call_count, 1)
        args, kwargs = mock_worker_cls.call_args
        self.assertEqual(args[0], "System")
        self.assertEqual(args[1], "")
        self.assertEqual(kwargs["options"]["process_mode"],
                         DEFAULT_PROCESS_COLLECTOR_MODE)
        self.assertEqual(self.window.pages.currentIndex(), 1)
        self.assertEqual(self.window.my_footprint_tabs.currentIndex(), 0)

    def test_browser_card_starts_scan(self):
        with patch.object(main_window_module, "ScanWorker") as mock_worker_cls:
            self.window.home_cards["browser"].click()
        self.assertEqual(mock_worker_cls.call_count, 1)
        args, _ = mock_worker_cls.call_args
        self.assertEqual(args[0], "Browser")

    def test_file_card_navigates_without_starting(self):
        with patch.object(main_window_module, "ScanWorker") as mock_worker_cls:
            self.window.home_cards["file"].click()
        mock_worker_cls.assert_not_called()
        self.assertEqual(self.window.pages.currentIndex(), 1)
        self.assertEqual(self.window.my_footprint_tabs.currentIndex(), 2)

    def test_full_card_starts_full_scan(self):
        with patch.object(main_window_module, "ScanWorker") as mock_worker_cls:
            self.window.home_cards["full"].click()
        mock_worker_cls.assert_called_once_with("Full Scan", "")
        self.assertEqual(self.window.my_footprint_tabs.currentIndex(), 3)

    def test_busy_worker_blocks_card_scan(self):
        from unittest.mock import MagicMock
        busy = MagicMock()
        busy.isRunning.return_value = True
        self.window.worker = busy
        with patch.object(main_window_module, "ScanWorker") as mock_worker_cls:
            self.window.home_cards["system"].click()
        mock_worker_cls.assert_not_called()

    def test_completed_scan_updates_overview(self):
        result = _result(
            findings=[_finding("F1", severity="High", category="Concern"),
                      _finding("F2")],
            footprint=[_footprint("System", "Operating System", "OS")],
        )
        self.window.on_scan_complete(result)
        html = self.window.dashboard_overview.toHtml()
        self.assertIn("Total Findings", html)
        self.assertIn("COMPLETED", html)
        self.assertIn("High", html)

    def test_individual_scan_module_row(self):
        self.window.on_scan_complete(_result())
        html = self.window.dashboard_overview.toHtml()
        self.assertIn("System", html)
        self.assertIn("1 / 1", html)

    def test_full_scan_module_rows(self):
        result = ScanResult(
            scan_id="full-dash", analysis_mode="Full Footprint Analysis",
            scan_type="Full Scan", scan_category="Unified Footprint",
            status="PARTIAL",
            message="partial. browser footprint unavailable. File scan skipped — no file selected.",
            footprint_data=[_footprint("System", "Operating System", "OS")],
            findings=[Finding(
                finding_id="lim-1", finding_type="Scan Limitation",
                title="Module Limitation: Browser", description="unavailable",
                evidence=["unavailable"], severity="Info", status="Limitation",
                category="Observation")],
        )
        self.window.on_scan_complete(result)
        html = self.window.dashboard_overview.toHtml()
        self.assertIn("PARTIAL", html)
        self.assertIn("Skipped", html)

    def test_history_bounded_and_ordered(self):
        for _ in range(25):
            self.window.on_scan_complete(_result())
        self.assertEqual(len(self.window._scan_history), 20)
        self.assertEqual(self.window.recent_scans_table.rowCount(), 5)
        times = [self.window._scan_history[i]["time"] for i in range(20)]
        self.assertTrue(all(isinstance(t, str) for t in times))

    def test_history_dialog_lists_session(self):
        self.window.on_scan_complete(_result())
        self.window.on_scan_complete(_result(scan_type="Browser"))
        dialog = self.window._build_history_dialog()
        try:
            tables = dialog.findChildren(main_window_module.QTableWidget)
            self.assertEqual(len(tables), 1)
            self.assertEqual(tables[0].rowCount(), 2)
            self.assertEqual(tables[0].item(0, 1).text(), "Browser")
        finally:
            dialog.close()

    def test_checklist_navigates(self):
        self.window._goto_my_footprint_tab(1)
        self.assertEqual(self.window.pages.currentIndex(), 1)
        self.assertEqual(self.window.my_footprint_tabs.currentIndex(), 1)

    def test_sidebar_items_have_icons(self):
        for row in range(self.window.sidebar.count()):
            self.assertFalse(self.window.sidebar.item(row).icon().isNull())

    def test_sidebar_emblem_is_icon(self):
        pixmap = self.window.sidebar_emblem.pixmap()
        self.assertIsNotNone(pixmap)
        self.assertFalse(pixmap.isNull())

    def test_overview_scan_selector_switches_summary(self):
        self.window.on_scan_complete(_result(
            findings=[_finding("F1", severity="High", category="Concern")]))
        self.window.on_scan_complete(_result(scan_type="Browser"))
        combo = self.window.overview_scan_combo
        self.assertEqual(combo.count(), 3)  # "Last Scan" + 2 entries, newest first
        combo.setCurrentIndex(1)
        html = self.window.dashboard_overview.toHtml()
        self.assertIn("Browser:", html)
        combo.setCurrentIndex(2)
        html = self.window.dashboard_overview.toHtml()
        self.assertIn("System:", html)
        combo.setCurrentIndex(0)
        html = self.window.dashboard_overview.toHtml()
        self.assertIn("Browser:", html)  # latest is still the Browser scan

    def test_history_entry_stores_summary_data(self):
        self.window.on_scan_complete(_result(
            findings=[_finding("F1", severity="High", category="Concern")]))
        entry = self.window._scan_history[0]
        self.assertEqual(entry["severity_counts"]["High"], 1)
        self.assertEqual(entry["module_rows"][0]["name"], "System")

    def test_small_window_smoke(self):
        self.window.resize(640, 480)
        self.window.on_scan_complete(_result(
            findings=[_finding("F1", severity="Critical", category="Concern")],
            footprint=[_footprint("System", "Operating System", "OS")],
        ))
        html = self.window.dashboard_overview.toHtml()
        self.assertIn("Total Findings", html)
        self.assertIn("Critical", html)


if __name__ == "__main__":
    unittest.main()
