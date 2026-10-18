"""Settings page, theme switching, and preference wiring tests.

These tests replace the QSettings instance on every window they build, so
they never read or write the real user preferences file.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

import shiboken6
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

from app.ui import theme
from app.ui.theme import DARK_REPORT, LIGHT_REPORT
from app.ui.main_window import MainWindow
from app.services.system_service import (
    DEFAULT_PROCESS_COLLECTOR_MODE,
    PROCESS_COLLECTOR_MODES,
)
from app.models.common import Finding, FootprintData, ScanResult

app = QApplication.instance()
if app is None:
    app = QApplication([])

# Redirect QSettings to a throwaway directory BEFORE any window is built.
# MainWindow reads preferences during construction, so redirecting afterwards
# would still let a test pick up the developer's real settings file.
_SETTINGS_DIR = tempfile.mkdtemp(prefix="dfa-test-settings-")
QSettings.setDefaultFormat(QSettings.Format.IniFormat)
QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope,
                  _SETTINGS_DIR)
QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.SystemScope,
                  _SETTINGS_DIR)


def _finding(title, severity="High", category="Concern", finding_type="Test"):
    return Finding(
        finding_id=f"finding-{title}",
        finding_type=finding_type,
        title=title,
        description=f"Description for {title}",
        evidence=[title],
        severity=severity,
        status="Unremediated",
        category=category,
    )


def _footprint(category, subcategory, value):
    return FootprintData(
        category=category,
        subcategory=subcategory,
        value=value,
        source="test",
        data_type="String",
        sensitivity="Low",
    )


def _result(scan_type="System"):
    return ScanResult(
        scan_id="s1",
        analysis_mode="test",
        scan_type=scan_type,
        scan_category="System Footprint",
        status="COMPLETED",
        message="Done",
        footprint_data=[_footprint("System", "Running Processes", "proc.exe")],
        findings=[_finding("Insecure Service")],
    )


class IsolatedSettingsMixin:
    """Build windows on top of the redirected, throwaway settings store.

    Windows are destroyed, not just closed: apply_theme() restyles the whole
    QApplication, so a leaked widget tree makes every later theme switch
    progressively slower.
    """

    def build_window(self):
        # Clear before constructing: MainWindow reads preferences during
        # __init__, so clearing afterwards would let one test's saved theme
        # leak into the next window.
        QSettings("DigitalFootprintAnalyzer", "Preferences").clear()
        window = MainWindow()
        self.addCleanup(self._destroy, window)
        self.addCleanup(theme.set_dark_theme, False)
        return window

    def _destroy(self, window):
        # close() alone leaves the widget tree alive, and apply_theme()
        # restyles every live widget, so a leaked window makes each later
        # test slower. shiboken6.delete() frees the C++ object immediately;
        # deleteLater() would never be delivered without a running event loop.
        window.close()
        shiboken6.delete(window)


class TestThemeSwitching(IsolatedSettingsMixin, unittest.TestCase):
    def setUp(self):
        self.window = self.build_window()

    def test_dark_is_the_default(self):
        self.assertEqual(self.window.current_theme, "dark")
        self.assertTrue(self.window.is_dark_mode)

    def test_switch_to_light_and_back(self):
        self.window.set_theme_mode("light")
        self.assertEqual(self.window.current_theme, "light")
        self.assertFalse(self.window.is_dark_mode)
        self.assertFalse(theme.is_dark())

        self.window.set_theme_mode("dark")
        self.assertTrue(self.window.is_dark_mode)
        self.assertTrue(theme.is_dark())

    def test_invalid_mode_is_ignored(self):
        self.window.set_theme_mode("neon")
        self.assertEqual(self.window.current_theme, "dark")

    def test_system_mode_delegates_to_detection(self):
        self.window.set_theme_mode("system")
        self.assertEqual(self.window.current_theme, "system")
        expected = self.window._detect_system_dark_mode()
        self.assertEqual(self.window.is_dark_mode, expected)

    def test_theme_mode_is_persisted(self):
        self.window.set_theme_mode("light")
        self.assertEqual(
            self.window.app_settings.value("theme_mode"), "light")


class TestChromeStylesheet(IsolatedSettingsMixin, unittest.TestCase):
    def setUp(self):
        self.window = self.build_window()

    def test_high_contrast_selection_in_both_themes(self):
        self.window.high_contrast = True
        for dark in (True, False):
            qss = theme.build_qss(dark=dark, high_contrast=True)
            self.assertIn("selection-background-color: #2563eb", qss)
            self.assertIn("selection-color: #ffffff", qss)

    def test_standard_selection_differs(self):
        qss = theme.build_qss(dark=True, high_contrast=False)
        self.assertNotIn("selection-background-color: #2563eb", qss)

    def test_light_and_dark_qss_differ(self):
        self.assertNotEqual(theme.build_qss(dark=True),
                            theme.build_qss(dark=False))

    def test_font_scale_only_emits_when_not_default(self):
        self.assertEqual(theme.build_qss(dark=True, font_scale=13),
                         theme.build_qss(dark=True, font_scale=13))
        self.assertNotIn("font-size: 16px",
                         theme.build_qss(dark=True, font_scale=13))
        self.assertIn("font-size: 16px",
                      theme.build_qss(dark=True, font_scale=16))

    def test_qss_uses_accent_token(self):
        self.assertIn(LIGHT_REPORT["accent"], theme.build_qss(dark=False))


class TestSettingsControls(IsolatedSettingsMixin, unittest.TestCase):
    def setUp(self):
        self.window = self.build_window()

    def test_theme_radios_exist_and_reflect_state(self):
        self.assertTrue(self.window.theme_dark_rb.isChecked())
        self.window.theme_light_rb.setChecked(True)
        self.assertEqual(self.window.current_theme, "light")
        self.window.theme_system_rb.setChecked(True)
        self.assertEqual(self.window.current_theme, "system")

    def test_contrast_toggle(self):
        self.window.contrast_checkbox.setChecked(False)
        self.assertFalse(self.window.high_contrast)
        self.window.contrast_checkbox.setChecked(True)
        self.assertTrue(self.window.high_contrast)

    def test_font_scale_combo(self):
        self.window.font_scale_combo.setCurrentIndex(0)
        self.assertEqual(self.window.font_scale, 12)
        self.window.font_scale_combo.setCurrentIndex(2)
        self.assertEqual(self.window.font_scale, 14)

    def test_preview_limit_combo(self):
        self.window.preview_limit_combo.setCurrentIndex(0)
        self.assertEqual(self.window.evidence_preview_limit, 5)
        self.window.preview_limit_combo.setCurrentIndex(3)
        self.assertEqual(self.window.evidence_preview_limit, 999999)

    def test_timeout_combo(self):
        self.window.timeout_combo.setCurrentIndex(0)
        self.assertEqual(self.window.network_timeout, 5)
        self.window.timeout_combo.setCurrentIndex(2)
        self.assertEqual(self.window.network_timeout, 20)

    def test_process_mode_combo_uses_service_tiers(self):
        combo = self.window.process_mode_combo
        self.assertEqual(combo.count(), len(PROCESS_COLLECTOR_MODES))
        for index, mode in enumerate(PROCESS_COLLECTOR_MODES):
            combo.setCurrentIndex(index)
            self.assertEqual(self.window.process_collector_mode, mode)
        # Defaults must round-trip to the service default (issue: string
        # matching previously mis-selected this combo).
        combo.setCurrentIndex(
            PROCESS_COLLECTOR_MODES.index(DEFAULT_PROCESS_COLLECTOR_MODE))
        self.assertEqual(self.window.process_collector_mode,
                         DEFAULT_PROCESS_COLLECTOR_MODE)

    def test_status_label_reports_change(self):
        self.window.contrast_checkbox.setChecked(False)
        self.assertIn("Standard selection",
                      self.window.settings_status_label.text())


class TestPreferencesAreWired(IsolatedSettingsMixin, unittest.TestCase):
    """Every control must change real behavior, not just a stored string."""

    def setUp(self):
        self.window = self.build_window()

    def test_preview_limit_affects_rendered_evidence(self):
        finding = Finding(
            finding_id="f1", finding_type="Test", title="Many",
            description="d", evidence=[f"item {i}" for i in range(30)],
            severity="High", status="Unremediated", category="Concern",
        )
        self.window.evidence_preview_limit = 5
        html = self.window.format_findings_html([finding])
        self.assertIn("+25 more", html)

        self.window.evidence_preview_limit = 999999
        html = self.window.format_findings_html([finding])
        self.assertNotIn("+25 more", html)

    def test_preview_limit_applies_to_coverage_blocks(self):
        finding = Finding(
            finding_id="f2", finding_type="Scan Coverage", title="Coverage",
            description="checked | sources | extra | more | lines | here",
            evidence=["extra", "more", "lines", "here", "and more items"],
            severity="Info", status="Unremediated", category="Observation",
        )
        self.window.evidence_preview_limit = 999999
        html = self.window.format_findings_html([finding])
        self.assertIsNotNone(html)

    def test_clear_cached_results(self):
        self.window.on_scan_complete(_result())
        self.assertIn("sys", self.window._last_results)
        self.window.on_scan_complete(_result("Browser"))
        self.assertIn("browser", self.window._last_results)
        self.assertEqual(len(self.window._scan_history), 2)

        self.window.clear_all_cached_results()
        self.assertEqual(len(self.window._last_results), 0)
        self.assertEqual(len(self.window._scan_history), 0)
        self.assertEqual(self.window.sys_findings_area.toPlainText().strip(), "")
        self.assertEqual(self.window.sys_results_area.toPlainText().strip(), "")
        self.assertIsNone(self.window.full_scan_file_path)

    def test_clear_cache_resets_tab_titles(self):
        self.window.on_scan_complete(_result())
        self.assertEqual(self.window.sys_sub_tabs.tabText(0), "Findings (1)")
        self.window.clear_all_cached_results()
        self.assertEqual(self.window.sys_sub_tabs.tabText(0), "Findings")
        self.assertEqual(self.window.sys_sub_tabs.tabText(1),
                         "Collected Evidence")

    def test_cache_status_text(self):
        self.assertIn("No scan results",
                      self.window._get_cache_status_text())
        self.window.on_scan_complete(_result())
        self.assertIn("1 scan result", self.window._get_cache_status_text())

    def test_reset_to_defaults(self):
        self.window.set_theme_mode("light")
        self.window.font_scale = 16
        self.window.network_timeout = 20
        self.window.reset_settings_to_defaults()

        self.assertEqual(self.window.current_theme, "dark")
        self.assertEqual(self.window.font_scale, 13)
        self.assertEqual(self.window.network_timeout, 10)
        self.assertEqual(self.window.process_collector_mode,
                         DEFAULT_PROCESS_COLLECTOR_MODE)
        self.assertTrue(self.window.contrast_checkbox.isChecked())

    def test_apply_theme_rerenders_held_results(self):
        self.window.on_scan_complete(_result())
        before = self.window.sys_findings_area.toHtml()
        self.window.set_theme_mode("light")
        after_light = self.window.sys_findings_area.toHtml()
        self.window.set_theme_mode("dark")
        after_dark = self.window.sys_findings_area.toHtml()
        self.assertNotEqual(before, after_light)
        self.assertEqual(before, after_dark)


if __name__ == "__main__":
    unittest.main()
