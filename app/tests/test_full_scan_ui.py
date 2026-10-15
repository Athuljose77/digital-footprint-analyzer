"""Phase D UI regression tests for Full Scan integration.

Verifies the Full Scan tab, worker wiring, dedicated result views,
progress reporting, busy-worker protection, and control restoration
without starting real scan threads.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from PySide6.QtWidgets import QApplication

import app.ui.main_window as main_window_module
from app.ui.main_window import MainWindow
from app.models.common import Finding, FootprintData, ScanResult

app = QApplication.instance()
if app is None:
    app = QApplication([])


def _finding(title, severity="Info", status="Informational"):
    return Finding(
        finding_id=f"finding-{title}",
        finding_type="Test Type",
        title=title,
        description=f"Description for {title}",
        evidence=[title],
        severity=severity,
        status=status,
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


def _full_result(status="COMPLETED", message="Full scan done.", findings=(), footprint=()):
    return ScanResult(
        scan_id="full-scan-1",
        analysis_mode="Full Footprint Analysis",
        scan_type="Full Scan",
        scan_category="Unified Footprint",
        status=status,
        message=message,
        footprint_data=list(footprint),
        findings=list(findings),
    )


class TestFullScanUI(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    def _tab_texts(self):
        return [
            self.window.my_footprint_tabs.tabText(i)
            for i in range(self.window.my_footprint_tabs.count())
        ]

    # 1. Full Scan action is available.
    def test_full_scan_tab_available(self):
        self.assertIn("Full Scan", self._tab_texts())
        self.assertEqual(self.window.full_scan_btn.text(), "Run Full Scan")
        self.assertEqual(self.window.full_scan_file_label.text(), "No file selected")
        self.assertIsNone(self.window.full_scan_file_path)
        self.assertFalse(self.window.full_scan_clear_btn.isEnabled())

    # 2/3. Worker created with selected path, or empty when none selected.
    def test_start_full_scan_without_file(self):
        with patch.object(main_window_module, "ScanWorker") as mock_worker_cls:
            self.window.start_full_scan()
        mock_worker_cls.assert_called_once_with("Full Scan", "")
        worker = mock_worker_cls.return_value
        worker.start.assert_called_once_with()
        worker.progress_changed.connect.assert_called_once_with(
            self.window.on_full_scan_progress
        )
        self.assertFalse(self.window.full_scan_btn.isEnabled())
        self.assertIn("Starting Full Scan", self.window.full_scan_status_label.text())

    def test_start_full_scan_with_selected_file(self):
        self.window.full_scan_file_path = "/tmp/explicit-file.png"
        with patch.object(main_window_module, "ScanWorker") as mock_worker_cls:
            self.window.start_full_scan()
        mock_worker_cls.assert_called_once_with("Full Scan", "/tmp/explicit-file.png")

    def test_selecting_file_does_not_start_scan(self):
        with (
            patch.object(
                main_window_module.QFileDialog, "getOpenFileName",
                return_value=("/tmp/chosen.png", "All Files (*)"),
            ),
            patch.object(main_window_module, "ScanWorker") as mock_worker_cls,
        ):
            self.window.select_full_scan_file()
        mock_worker_cls.assert_not_called()
        self.assertEqual(self.window.full_scan_file_path, "/tmp/chosen.png")
        self.assertEqual(self.window.full_scan_file_label.text(), "chosen.png")
        self.assertTrue(self.window.full_scan_clear_btn.isEnabled())

    def test_cancelled_selection_keeps_state(self):
        with (
            patch.object(
                main_window_module.QFileDialog, "getOpenFileName",
                return_value=("", ""),
            ),
            patch.object(main_window_module, "ScanWorker") as mock_worker_cls,
        ):
            self.window.select_full_scan_file()
        mock_worker_cls.assert_not_called()
        self.assertIsNone(self.window.full_scan_file_path)
        self.assertEqual(self.window.full_scan_file_label.text(), "No file selected")

    def test_clear_file_resets_state(self):
        self.window.full_scan_file_path = "/tmp/chosen.png"
        self.window.full_scan_clear_btn.setEnabled(True)
        self.window.clear_full_scan_file()
        self.assertIsNone(self.window.full_scan_file_path)
        self.assertEqual(self.window.full_scan_file_label.text(), "No file selected")
        self.assertFalse(self.window.full_scan_clear_btn.isEnabled())

    # 4/5. Dedicated view populated; individual views untouched.
    def test_full_scan_results_in_dedicated_view(self):
        for area in (
            self.window.sys_results_area,
            self.window.browser_results_area,
            self.window.file_results_area,
            self.window.results_area,
        ):
            area.setHtml("SENTINEL-INDIVIDUAL")
        result = _full_result(
            findings=[_finding("Full Scan finding", "High")],
            footprint=[_footprint("System", "Operating System", "FullOS")],
        )
        with patch.object(main_window_module, "ScanWorker"):
            self.window.start_full_scan()
        self.window.on_scan_complete(result)

        findings_html = self.window.full_scan_findings_area.toHtml()
        evidence_html = self.window.full_scan_results_area.toHtml()
        self.assertIn("Full Scan finding", findings_html)
        self.assertIn("FullOS", evidence_html)
        self.assertEqual(self.window.full_scan_sub_tabs.tabText(0), "Findings (1)")
        self.assertEqual(self.window.full_scan_sub_tabs.tabText(1), "Collected Evidence (1)")
        for area in (
            self.window.sys_results_area,
            self.window.browser_results_area,
            self.window.file_results_area,
            self.window.results_area,
        ):
            self.assertIn("SENTINEL-INDIVIDUAL", area.toHtml())

    # 6. Progress reaches the Full Scan status label.
    def test_progress_reaches_status_label(self):
        self.window.worker = MagicMock()
        self.window.worker.scan_type = "Full Scan"
        self.window.on_full_scan_progress("Starting Browser scan...")
        self.assertEqual(
            self.window.full_scan_status_label.text(), "Starting Browser scan..."
        )

    def test_progress_ignored_for_individual_scans(self):
        self.window.worker = MagicMock()
        self.window.worker.scan_type = "System"
        self.window.full_scan_status_label.setText("untouched")
        self.window.on_full_scan_progress("Starting Browser scan...")
        self.assertEqual(self.window.full_scan_status_label.text(), "untouched")

    # 7. Busy-worker protection.
    def test_busy_worker_blocks_full_scan(self):
        busy = MagicMock()
        busy.isRunning.return_value = True
        self.window.worker = busy
        with patch.object(main_window_module, "ScanWorker") as mock_worker_cls:
            self.window.start_full_scan()
        mock_worker_cls.assert_not_called()
        self.assertIs(self.window.worker, busy)

    # 8. Controls restored after success and error.
    def test_controls_restored_after_success(self):
        self.window.full_scan_file_path = "/tmp/explicit-file.png"
        with patch.object(main_window_module, "ScanWorker"):
            self.window.start_full_scan()
        self.assertFalse(self.window.full_scan_btn.isEnabled())
        self.window.on_scan_complete(_full_result())
        self.assertTrue(self.window.full_scan_btn.isEnabled())
        self.assertTrue(self.window.full_scan_select_btn.isEnabled())
        self.assertTrue(self.window.full_scan_clear_btn.isEnabled())
        self.assertIn("COMPLETED", self.window.full_scan_status_label.text())

    def test_controls_restored_after_error(self):
        with patch.object(main_window_module, "ScanWorker"):
            self.window.start_full_scan()
        self.window.on_scan_error("full scan boom")
        self.assertTrue(self.window.full_scan_btn.isEnabled())
        self.assertTrue(self.window.full_scan_select_btn.isEnabled())
        self.assertIn("full scan boom", self.window.full_scan_status_label.text())

    # 9. PARTIAL and ERROR statuses rendered.
    def test_partial_status_rendered(self):
        result = _full_result(
            status="PARTIAL",
            message="partial results",
            findings=[_finding("Module Limitation: Browser", "Info", "Limitation")],
        )
        self.window.on_scan_complete(result)
        self.assertIn("PARTIAL", self.window.full_scan_status_label.text())
        self.assertIn(
            "Module Limitation: Browser", self.window.full_scan_findings_area.toHtml()
        )

    def test_error_status_rendered(self):
        result = _full_result(status="ERROR", message="everything failed")
        self.window.on_scan_complete(result)
        self.assertIn("ERROR", self.window.full_scan_status_label.text())
        self.assertIn(
            "No findings were generated",
            self.window.full_scan_findings_area.toHtml(),
        )

    # 10. Skipped file explained without fabricated findings.
    def test_skipped_file_explained(self):
        result = _full_result(
            message="Scan completed successfully. File scan skipped — no file selected.",
            footprint=[_footprint("System", "Operating System", "OnlyOS")],
            findings=[],
        )
        self.window.on_scan_complete(result)
        evidence_html = self.window.full_scan_results_area.toHtml()
        self.assertIn("skipped because no file was selected", evidence_html)
        findings_html = self.window.full_scan_findings_area.toHtml()
        self.assertIn("No findings were generated", findings_html)
        self.assertNotIn("Exposed in", findings_html)

    def test_browser_limitation_visible(self):
        result = _full_result(
            status="PARTIAL",
            message="browser footprint unavailable on this platform",
            findings=[
                Finding(
                    finding_id="lim-browser",
                    finding_type="Scan Limitation",
                    title="Module Limitation: Browser",
                    description="The browser scan encountered an issue: unavailable",
                    evidence=["unavailable"],
                    severity="Info",
                    status="Limitation",
                )
            ],
            footprint=[
                _footprint("Browser", "Scan Coverage", "Unavailable: nothing found")
            ],
        )
        self.window.on_scan_complete(result)
        findings_html = self.window.full_scan_findings_area.toHtml()
        self.assertIn("Module Limitation: Browser", findings_html)
        self.assertIn("Unavailable: nothing found",
                      self.window.full_scan_results_area.toHtml())

    # 11. Public Lookup flows unchanged.
    def test_public_lookup_flow_unchanged(self):
        self.window.target_input.setText("someuser")
        self.window.scan_type_combo.setCurrentText("Username")
        with patch.object(main_window_module, "ScanWorker") as mock_worker_cls:
            self.window.start_scan()
        mock_worker_cls.assert_called_once_with("Username", "someuser")
        # Full Scan views untouched by Public Lookup completion.
        self.window.full_scan_findings_area.setHtml("SENTINEL-FULL-FINDINGS")
        self.window.full_scan_results_area.setHtml("SENTINEL-FULL-EVIDENCE")
        public_result = ScanResult(
            scan_id="user-1",
            analysis_mode="Public Footprint Lookup",
            scan_type="Username",
            scan_category="Public Presence",
            status="COMPLETED",
            message="Found 1 profiles.",
            footprint_data=[
                FootprintData(category="Public Presence", subcategory="Social Profile",
                              source="GitHub", data_type="URL",
                              value="https://github.com/test", sensitivity="Low")
            ],
            findings=[
                Finding(finding_id="2", finding_type="Public Presence",
                        title="Possible username matches",
                        description="Profiles found",
                        evidence=["https://github.com/test"],
                        severity="Info", status="Informational")
            ],
        )
        self.window.on_scan_complete(public_result)
        self.assertIn("SENTINEL-FULL-FINDINGS",
                      self.window.full_scan_findings_area.toHtml())
        self.assertIn("SENTINEL-FULL-EVIDENCE",
                      self.window.full_scan_results_area.toHtml())
        self.assertIn("Possible username matches",
                      self.window.public_findings_area.toHtml())


if __name__ == "__main__":
    unittest.main()
