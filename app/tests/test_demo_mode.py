"""Demo-mode behavior: synthetic data must stay out of persisted history."""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from PySide6.QtWidgets import QApplication

from app.core import demo
from app.core.history import ScanHistoryStore
from app.core.remediation.store import ActionStateStore
from app.models.common import Finding, FootprintData, ScanResult
from app.ui.main_window import MainWindow

app = QApplication.instance()
if app is None:
    app = QApplication([])


def _real_result():
    return ScanResult(
        scan_id="real-scan",
        analysis_mode="System Footprint Analysis",
        scan_type="System",
        scan_category="System Footprint",
        status="COMPLETED",
        message="Real scan for the demo-mode test.",
        footprint_data=[
            FootprintData(
                category="System",
                subcategory="Operating System",
                source="Test",
                data_type="String",
                value="TestOS",
                sensitivity="Low",
            )
        ],
        findings=[
            Finding(
                finding_id="real-finding",
                finding_type="Observation",
                title="Real finding",
                description="A real (test) finding.",
                evidence=["test"],
                severity="Info",
                status="Informational",
            )
        ],
    )


def _full_result():
    return ScanResult(
        scan_id="real-full",
        analysis_mode="Full Footprint Analysis",
        scan_type="Full Scan",
        scan_category="Unified Footprint",
        status="COMPLETED",
        message="Real full scan for the demo-mode test.",
        footprint_data=[
            FootprintData(
                category="System",
                subcategory="Operating System",
                source="Test",
                data_type="String",
                value="TestOS",
                sensitivity="Low",
            )
        ],
        findings=[
            Finding(
                finding_id="real-full-finding",
                finding_type="Observation",
                title="Real full-scan finding",
                description="A real (test) finding.",
                evidence=["test"],
                severity="Low",
                status="Informational",
            )
        ],
        module_coverage=[
            {"name": "System", "key": "system", "state": "completed",
             "note": "Completed"},
            {"name": "Browser", "key": "browser", "state": "completed",
             "note": "Completed"},
            {"name": "File", "key": "file_metadata", "state": "skipped",
             "note": "No file selected"},
        ],
    )


class DemoModeTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dfa-demo-test-")
        self.window = MainWindow()
        self.history = ScanHistoryStore(os.path.join(self.tmp, "history.db"))
        self.actions = ActionStateStore(os.path.join(self.tmp, "actions.db"))
        self.window.history_store = self.history
        self.window.action_store = self.actions
        self.window.history_page.set_store(self.history)

    def tearDown(self):
        self.window.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_demo_payload_is_clearly_synthetic(self):
        result = demo.build_demo_result()
        self.assertEqual(result.scan_id, demo.DEMO_SCAN_ID)
        self.assertIn("synthetic", (result.message or "").lower())
        self.assertTrue(result.findings)
        rendered = str(result.model_dump()).lower()
        self.assertNotIn("/home/", rendered)
        self.assertNotIn("c:\\\\users", rendered)

    def test_explore_button_loads_assessment_without_history(self):
        self.assertTrue(self.window.home_demo_btn.isVisible() or
                        not self.window.home_demo_btn.isHidden())
        self.window.home_demo_btn.click()

        self.assertTrue(self.window.demo_mode)
        self.assertFalse(self.window.demo_banner.isHidden())
        self.assertIn("Demo", self.window.windowTitle())
        self.assertEqual(self.window.pages.currentIndex(), 4)
        self.assertEqual(self.window.latest_result.scan_id, demo.DEMO_SCAN_ID)
        self.assertEqual(self.window.assessment_page.result.scan_id,
                         demo.DEMO_SCAN_ID)
        self.assertEqual(self.history.count(), 0)
        self.assertEqual(self.window._scan_history[0]["scan_type"], "Demo scan")
        self.assertEqual(self.actions.count(), 0)
        self.window.on_action_state_changed("demo-key", "completed")
        self.assertEqual(self.actions.count(), 0)
        self.assertIn("not saved", self.window.action_page.privacy_note.text())

    def test_exit_demo_clears_synthetic_view(self):
        self.window.load_demo_scan()
        self.window._exit_demo()

        self.assertFalse(self.window.demo_mode)
        self.assertTrue(self.window.demo_banner.isHidden())
        self.assertEqual(self.window.windowTitle(), "Digital Footprint Analyzer")
        self.assertIsNone(self.window.latest_result)
        self.assertIsNone(self.window.assessment_page.result)
        self.assertIsNone(self.window.action_page.board)
        self.assertEqual(self.history.count(), 0)
        self.assertEqual(self.window._scan_history, [])
        self.assertEqual(self.window.pages.currentIndex(), 0)

    def test_exit_demo_restores_the_previous_real_result(self):
        real = _real_result()
        self.window.on_scan_complete(real)
        self.assertEqual(self.history.count(), 1)

        self.window.load_demo_scan()
        self.assertEqual(self.window.latest_result.scan_id, demo.DEMO_SCAN_ID)

        self.window._exit_demo()
        self.assertEqual(self.window.latest_result.scan_id, "real-scan")
        self.assertEqual(self.window.assessment_page.result.scan_id, "real-scan")
        self.assertEqual(self.history.count(), 1)
        self.assertEqual(self.window._scan_history[0]["scan_type"], "System")

    def test_exit_demo_restores_previous_full_scan_view(self):
        self.window.on_scan_complete(_full_result())
        before = self.window.full_scan_findings_area.toPlainText()
        self.assertIn("Real full-scan finding", before)

        self.window.load_demo_scan()
        self.assertIn("Demo address appears",
                      self.window.full_scan_findings_area.toPlainText())

        self.window._exit_demo()
        self.assertEqual(self.window._last_results["full"].scan_id, "real-full")
        self.assertIn("Real full-scan finding",
                      self.window.full_scan_findings_area.toPlainText())

    def test_real_scan_after_demo_does_not_persist_demo_finding(self):
        self.window.load_demo_scan()
        self.window.on_scan_complete(_real_result())

        self.assertFalse(self.window.demo_mode)
        self.assertTrue(self.window.demo_banner.isHidden())
        self.assertEqual(self.history.count(), 1)
        records = self.history.list_scans()
        self.assertEqual(records[0].scan_id, "real-scan")
        self.assertNotIn("Demo address appears",
                         str(records[0].findings))

    def test_demo_mode_does_not_duplicate_on_repeated_entry(self):
        self.window.load_demo_scan()
        self.window.load_demo_scan()
        self.assertEqual(len(self.window._scan_history), 1)


if __name__ == "__main__":
    unittest.main()
