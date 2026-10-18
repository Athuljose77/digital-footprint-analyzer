"""Tests for Dark/Light mode theming, text selection readability, and Settings page options."""
import os
import sys
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from PySide6.QtWidgets import QApplication

from app.ui.main_window import (
    MainWindow,
    get_theme_palette,
    format_evidence_record_html,
    format_finding_evidence_html,
)
from app.models.common import Finding, FootprintData, ScanResult

app = QApplication.instance()
if app is None:
    app = QApplication([])


def _finding(title, severity="Info", status="Informational", evidence=None,
             finding_type="Test Type", category="Observation"):
    return Finding(
        finding_id=f"finding-{title}",
        finding_type=finding_type,
        title=title,
        description=f"Description for {title}",
        evidence=list(evidence) if evidence is not None else [title],
        severity=severity,
        status=status,
        category=category,
    )


def _footprint(category, subcategory, value, source="test"):
    return FootprintData(
        category=category,
        subcategory=subcategory,
        value=value,
        source=source,
        data_type="String",
        sensitivity="Low",
    )


class TestThemePalette(unittest.TestCase):
    def test_light_palette_values(self):
        p = get_theme_palette(False)
        self.assertFalse(p["is_dark"])
        self.assertEqual(p["box_bg"], "#f8f9fa")
        self.assertEqual(p["text_primary"], "#0f172a")
        self.assertEqual(p["card_border"], "#e1e4e8")

    def test_dark_palette_values(self):
        p = get_theme_palette(True)
        self.assertTrue(p["is_dark"])
        self.assertEqual(p["box_bg"], "#1e293b")
        self.assertEqual(p["text_primary"], "#f8fafc")
        self.assertEqual(p["card_border"], "#334155")
        self.assertEqual(p["selection_bg"], "#2563eb")
        self.assertEqual(p["selection_text"], "#ffffff")


class TestMainWindowTheming(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    def test_theme_mode_switching(self):
        self.window.set_theme_mode("dark")
        self.assertEqual(self.window.current_theme, "dark")
        self.assertTrue(self.window.is_dark_mode)
        p_dark = self.window.get_palette()
        self.assertTrue(p_dark["is_dark"])

        self.window.set_theme_mode("light")
        self.assertEqual(self.window.current_theme, "light")
        self.assertFalse(self.window.is_dark_mode)
        p_light = self.window.get_palette()
        self.assertFalse(p_light["is_dark"])

    def test_high_contrast_selection_stylesheet(self):
        # Verify both dark and light QSS enforce high-contrast selection colors
        self.window.high_contrast = True
        dark_qss = self.window._get_dark_qss()
        self.assertIn("selection-background-color: #2563eb", dark_qss)
        self.assertIn("selection-color: #ffffff", dark_qss)

        light_qss = self.window._get_light_qss()
        self.assertIn("selection-background-color: #2563eb", light_qss)
        self.assertIn("selection-color: #ffffff", light_qss)

    def test_dark_mode_findings_html(self):
        self.window.set_theme_mode("dark")
        finding = _finding("Insecure Service", severity="High", category="Concern")
        html = self.window.format_findings_html([finding], evidence_count=1, scan_status="COMPLETED")

        # In dark mode, summary and card backgrounds should use dark slate styling
        self.assertIn("#1e293b", html)
        self.assertIn("Insecure Service", html)
        self.assertIn("HIGH", html)

    def test_dark_mode_evidence_html(self):
        self.window.set_theme_mode("dark")
        fp = [
            _footprint("System", "Running Processes", "chrome.exe — PID: 1234"),
            _footprint("System", "Installed Applications", "Python 3.12"),
        ]
        html = self.window.format_system_evidence_html(fp)
        # Verify box styling in dark mode uses dark slate background #1e293b
        self.assertIn("#1e293b", html)
        self.assertIn("Running Processes", html)
        self.assertIn("chrome.exe", html)

    def test_dark_mode_browser_evidence_html(self):
        self.window.set_theme_mode("dark")
        fp = [_footprint("Browser", "Detected Browser", "Google Chrome")]
        html = self.window.format_browser_evidence_html(fp)
        self.assertIn("#1e293b", html)
        self.assertIn("Detected Browsers", html)

    def test_dark_mode_file_evidence_html(self):
        self.window.set_theme_mode("dark")
        fp = [_footprint("File & Metadata", "File Information", "photo.jpg (1.2 MB)")]
        html = self.window.format_file_evidence_html(fp)
        self.assertIn("#1e293b", html)
        self.assertIn("photo.jpg", html)

    def test_dark_mode_full_scan_evidence_html(self):
        self.window.set_theme_mode("dark")
        result = ScanResult(
            scan_id="full-test",
            analysis_mode="Full Footprint Analysis",
            scan_type="Full Scan",
            scan_category="Unified Footprint",
            status="COMPLETED",
            message="Done",
            footprint_data=[_footprint("System", "Running Processes", "proc.exe")],
            findings=[_finding("Test finding")],
        )
        html = self.window.format_full_scan_evidence_html(result)
        self.assertIn("#1e293b", html)
        self.assertIn("proc.exe", html)


class TestSettingsPageControls(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    def test_settings_theme_radio_buttons(self):
        self.window.theme_dark_rb.setChecked(True)
        self.assertEqual(self.window.current_theme, "dark")
        self.assertTrue(self.window.is_dark_mode)

        self.window.theme_light_rb.setChecked(True)
        self.assertEqual(self.window.current_theme, "light")
        self.assertFalse(self.window.is_dark_mode)

    def test_settings_contrast_toggle(self):
        self.window.contrast_checkbox.setChecked(False)
        self.assertFalse(self.window.high_contrast)
        self.window.contrast_checkbox.setChecked(True)
        self.assertTrue(self.window.high_contrast)

    def test_settings_font_scale_combo(self):
        self.window.font_scale_combo.setCurrentIndex(0)  # 12px
        self.assertEqual(self.window.font_scale, 12)
        self.window.font_scale_combo.setCurrentIndex(2)  # 14px
        self.assertEqual(self.window.font_scale, 14)

    def test_settings_clear_cached_results(self):
        dummy_result = ScanResult(
            scan_id="dummy",
            analysis_mode="Test",
            scan_type="System",
            scan_category="System",
            status="COMPLETED",
            message="Done",
            footprint_data=[_footprint("System", "OS", "Windows")],
            findings=[_finding("F1")],
        )
        self.window.on_scan_complete(dummy_result)
        self.assertIn("sys", self.window._last_results)

        self.window.clear_all_cached_results()
        self.assertEqual(len(self.window._last_results), 0)
        self.assertEqual(self.window.sys_findings_area.toPlainText().strip(), "")
        self.assertEqual(self.window.sys_results_area.toPlainText().strip(), "")

    def test_settings_reset_to_defaults(self):
        self.window.set_theme_mode("dark")
        self.window.font_scale = 16
        self.window.reset_settings_to_defaults()
        self.assertEqual(self.window.current_theme, "system")
        self.assertEqual(self.window.font_scale, 13)
        self.assertTrue(self.window.high_contrast)
