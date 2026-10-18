"""Theme tests: light defaults plus systematic dark-mode rendering checks.

Every report formatter is rendered with dark mode enabled and asserted
to contain no light-only color literals, so no hardcoded light color can
survive unnoticed. Content assertions stay theme-independent.
"""
import os
import sys
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from PySide6.QtWidgets import QApplication

from app.ui import theme
from app.ui.theme import DARK_REPORT, LIGHT_REPORT, R
from app.ui.main_window import MainWindow
from app.models.common import Finding, FootprintData, ScanResult

app = QApplication.instance()
if app is None:
    app = QApplication([])

# Light literals whose dark replacements differ and which never legitimately
# appear in dark output (values shared by both maps are excluded).
LIGHT_ONLY_HEXES = {
    light for key, light in LIGHT_REPORT.items()
    if DARK_REPORT[key] != light
} - set(DARK_REPORT.values())


def _finding(title, severity="High", category="Concern", finding_type="Test Type",
             evidence=None, status="Unremediated"):
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


def _coverage_finding():
    return Finding(
        finding_id="cov-1",
        finding_type="Scan Coverage",
        title="Browser Footprint Scan Coverage",
        description="Browsers searched: A, B | Browsers detected: A",
        evidence={"searched": ["A", "B"], "detected": ["A"]},
        severity="Info",
        status="Informational",
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


def _rich_footprint():
    return [
        _footprint("System", "Operating System", "TestOS"),
        _footprint("System", "Installed Applications", "pkg-a — version 1.0"),
        _footprint("System", "Running Processes", "PID 1: init | User: root"),
        _footprint("System", "Startup Applications", "Name: App | Scope: user"),
        _footprint("Browser", "Detected Browser", "Brave — version 1.0 | Profiles: Default"),
        _footprint("Browser", "Extension",
                   "Ext (v1) | ID: abc | Browser: Brave | Profile: Default | does things"),
        _footprint("Browser", "Scan Coverage", "Unavailable: nothing here"),
        _footprint("File & Metadata", "File Information", "photo.jpg"),
        _footprint("File & Metadata", "Potentially Sensitive", "GPS: 1, 2"),
        _footprint("File & Metadata", "Embedded Metadata", "Make: Canon"),
    ]


def _rich_result():
    return ScanResult(
        scan_id="theme-1",
        analysis_mode="Full Footprint Analysis",
        scan_type="Full Scan",
        scan_category="Unified Footprint",
        status="PARTIAL",
        message="partial. File scan skipped — no file selected.",
        footprint_data=_rich_footprint(),
        findings=[_finding("Big", evidence=[f"entry-{i}" for i in range(12)]),
                  _coverage_finding()],
    )


class TestThemeMaps(unittest.TestCase):
    def test_light_is_default(self):
        # The module default is light. Another test may have constructed a
        # MainWindow, which applies the saved user preference, so this checks
        # the declared default rather than whatever ran before it.
        self.assertFalse(theme.DEFAULT_DARK)
        # Read the light map directly: R() follows whichever theme is
        # currently active, which an earlier test may legitimately have set.
        self.assertEqual(LIGHT_REPORT["panel_bg"], "#f8f9fa")
        self.assertEqual(LIGHT_REPORT["text"], "#24292e")

    def test_maps_cover_same_keys(self):
        self.assertEqual(set(LIGHT_REPORT), set(DARK_REPORT))

    def test_blocklist_nonempty(self):
        self.assertTrue(len(LIGHT_ONLY_HEXES) > 10)


class TestDarkRendering(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()
        theme.set_dark_theme(True)
        self.addCleanup(theme.set_dark_theme, False)

    def tearDown(self):
        self.window.close()

    def assertNoLightHexes(self, html):
        lowered = html.lower()
        for hx in LIGHT_ONLY_HEXES:
            self.assertNotIn(hx, lowered, f"light literal {hx} leaked into dark output")

    def test_findings_with_coverage(self):
        html = self.window.format_findings_html(
            [_finding("Big", evidence=["a", "b"]), _coverage_finding()],
            evidence_count=10, scan_status="PARTIAL",
        )
        self.assertNoLightHexes(html)
        self.assertIn(DARK_REPORT["panel_bg"], html)
        self.assertIn("Big", html)
        self.assertIn("COVERAGE &amp; LIMITATIONS", html)

    def test_findings_empty_error(self):
        html = self.window.format_findings_html([], evidence_count=0, scan_status="ERROR")
        self.assertNoLightHexes(html)
        self.assertIn("did not complete", html)

    def test_system_evidence(self):
        html = self.window.format_system_evidence_html(
            _rich_footprint(), view_key="sys")
        self.assertNoLightHexes(html)
        self.assertIn("pkg-a", html)

    def test_browser_evidence(self):
        html = self.window.format_browser_evidence_html(
            _rich_footprint(), view_key="browser")
        self.assertNoLightHexes(html)
        self.assertIn("Ext (v1)", html)

    def test_file_evidence(self):
        html = self.window.format_file_evidence_html(
            _rich_footprint(), view_key="file")
        self.assertNoLightHexes(html)
        self.assertIn("photo.jpg", html)

    def test_full_scan_evidence(self):
        html = self.window.format_full_scan_evidence_html(_rich_result())
        self.assertNoLightHexes(html)
        self.assertIn("FULL SCAN EVIDENCE", html)

    def test_public_evidence(self):
        html = self.window.format_public_evidence_html(
            _rich_footprint(), [_finding("F")])
        self.assertNoLightHexes(html)
        self.assertIn("pkg-a", html)

    def test_dashboard_overview(self):
        self.window.on_scan_complete(_rich_result())
        html = self.window.dashboard_overview.toHtml()
        self.assertIn("Total Findings", html)

    def test_dark_window_construction(self):
        dark_window = MainWindow()
        try:
            self.assertIn(DARK_REPORT["panel_bg_alt"],
                          dark_window.home_card_frames["system"].styleSheet())
        finally:
            dark_window.close()


class TestApplyDarkTheme(unittest.TestCase):
    def test_apply_and_restore(self):
        old_palette = app.palette()
        old_sheet = app.styleSheet()
        try:
            from PySide6.QtGui import QPalette
            theme.apply_dark_theme(app)
            self.assertTrue(theme.is_dark())
            self.assertEqual(
                app.palette().color(QPalette.ColorRole.Window).name(), "#0d1319")
            self.assertIn("#2dd4bf", app.styleSheet())
        finally:
            theme.set_dark_theme(False)
            app.setPalette(old_palette)
            app.setStyleSheet(old_sheet)
        self.assertFalse(theme.is_dark())


if __name__ == "__main__":
    unittest.main()
