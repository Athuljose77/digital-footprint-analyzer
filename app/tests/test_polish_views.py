"""Phase F.1 tests for evidence polish across footprint views.

Covers structured evidence records, group collapse, per-extension detail
expansion, per-tab search/group filtering, coverage evidence dedupe, and
the compact wrapping summary. Presentation-only; scan semantics untouched.
"""
import os
import sys
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from PySide6.QtCore import QUrl
from PySide6.QtWidgets import QApplication

from app.ui.main_window import (
    MainWindow,
    filter_footprint,
    format_evidence_record_html,
    parse_evidence_record,
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


def _footprint(category, subcategory, value, source="Test Source"):
    return FootprintData(
        category=category,
        subcategory=subcategory,
        source=source,
        data_type="String",
        value=value,
        sensitivity="Low",
    )


def _sys_result(findings=(), footprint=(), status="COMPLETED"):
    return ScanResult(
        scan_id="sys-polish-1",
        analysis_mode="My Footprint",
        scan_type="System",
        scan_category="System Footprint",
        status=status,
        message="done",
        footprint_data=list(footprint),
        findings=list(findings),
    )


class TestParseEvidenceRecord(unittest.TestCase):
    def test_extension(self):
        headline, visible, hidden = parse_evidence_record(
            "Extension",
            "uBlock Origin (v1.2) | ID: abc123 | Browser: Brave | Profile: Default | Blocks ads",
        )
        self.assertIn("uBlock Origin (v1.2)", headline)
        self.assertIn("Brave", headline)
        self.assertIn("Default", headline)
        self.assertTrue(any("Blocks ads" in v for v in visible))
        self.assertTrue(any("abc123" in h for h in hidden))

    def test_extension_missing_fields(self):
        headline, visible, hidden = parse_evidence_record("Extension", "LonelyExt")
        self.assertEqual(headline, "LonelyExt")
        self.assertEqual(visible, [])
        self.assertEqual(hidden, [])

    def test_startup(self):
        headline, visible, hidden = parse_evidence_record(
            "Startup Applications", "Name: Discord | Scope: user | Path: /usr/bin/discord"
        )
        self.assertEqual(headline, "Discord")
        self.assertIn("Scope: user", visible)
        self.assertEqual(hidden, [])

    def test_process(self):
        headline, visible, hidden = parse_evidence_record(
            "Running Processes", "PID 1: systemd | User: root | Status: running"
        )
        self.assertEqual(headline, "PID 1: systemd")
        self.assertIn("User: root", visible)

    def test_installed_app(self):
        headline, visible, hidden = parse_evidence_record(
            "Installed Applications", "Firefox — version 128"
        )
        self.assertEqual(headline, "Firefox — version 128")
        self.assertEqual(visible, [])
        self.assertEqual(hidden, [])

    def test_browser(self):
        headline, visible, hidden = parse_evidence_record(
            "Detected Browser", "Brave — version 1.0 | Profiles: Default | Extensions: 2"
        )
        self.assertEqual(headline, "Brave — version 1.0")
        self.assertIn("Profiles: Default", visible)

    def test_fallback_preserves_raw(self):
        headline, visible, hidden = parse_evidence_record("Weird", "some | raw")
        self.assertEqual(headline, "some | raw")
        self.assertEqual(visible, [])
        self.assertEqual(hidden, [])


class TestFilterSubcategories(unittest.TestCase):
    def setUp(self):
        self.records = [
            _footprint("System", "Installed Applications", "pkg-a"),
            _footprint("System", "Running Processes", "PID 1"),
            _footprint("System", "Startup Applications", "Name: X"),
            _footprint("System", "Operating System", "Linux"),
        ]

    def test_subcategory_limit(self):
        matched = filter_footprint(self.records, subcategories={"Running Processes"})
        self.assertEqual([r.value for r in matched], ["PID 1"])

    def test_exclude_subcategories(self):
        matched = filter_footprint(
            self.records,
            exclude_subcategories={"Installed Applications", "Running Processes",
                                   "Startup Applications"},
        )
        self.assertEqual([r.value for r in matched], ["Linux"])

    def test_query_combines_with_subcategories(self):
        matched = filter_footprint(
            self.records, query="pkg",
            subcategories={"Installed Applications", "Running Processes"},
        )
        self.assertEqual([r.value for r in matched], ["pkg-a"])

    def test_defaults_unchanged(self):
        self.assertEqual(len(filter_footprint(self.records)), 4)
        self.assertEqual(len(filter_footprint(self.records, module="System")), 4)


class TestStructuredEvidenceViews(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    def test_startup_headline_first(self):
        result = _sys_result(
            findings=[_finding("F")],
            footprint=[_footprint("System", "Startup Applications",
                                   "Name: Discord | Scope: user | Path: /usr/bin/discord")],
        )
        self.window.on_scan_complete(result)
        html = self.window.sys_results_area.toHtml()
        self.assertIn("Discord", html)
        self.assertIn("Scope: user", html)
        self.assertIn("Startup Applications (1 detected)", html)

    def test_extension_details_expand(self):
        result = ScanResult(
            scan_id="b-1", analysis_mode="My Footprint", scan_type="Browser",
            scan_category="Browser Footprint", status="COMPLETED", message="done",
            footprint_data=[_footprint(
                "Browser", "Extension",
                "uBlock Origin (v1.2) | ID: abc123 | Browser: Brave | Profile: Default | Blocks ads and trackers",
            )],
            findings=[_finding("F")],
        )
        self.window.on_scan_complete(result)
        collapsed = self.window.browser_results_area.toHtml()
        self.assertIn("uBlock Origin (v1.2)", collapsed)
        self.assertIn("Details", collapsed)
        self.assertNotIn("abc123", collapsed)

        self.window._on_evidence_anchor("browser", QUrl("#evd-browser-extensions:0-show"))
        expanded = self.window.browser_results_area.toHtml()
        self.assertIn("abc123", expanded)
        self.assertIn("Hide details", expanded)

        self.window._on_evidence_anchor("browser", QUrl("#evd-browser-extensions:0-hide"))
        recollapsed = self.window.browser_results_area.toHtml()
        self.assertNotIn("abc123", recollapsed)

    def test_group_collapse_round_trip(self):
        footprint = [_footprint("System", "Installed Applications", f"pkg-{i}")
                     for i in range(12)]
        result = _sys_result(findings=[_finding("F")], footprint=footprint)
        self.window.on_scan_complete(result)
        html = self.window.sys_results_area.toHtml()
        self.assertIn("Collapse", html)
        self.assertIn("pkg-0", html)

        self.window._on_evidence_anchor("sys", QUrl("#evd-sys-g-installed_apps"))
        collapsed_html = self.window.sys_results_area.toHtml()
        self.assertNotIn("pkg-0", collapsed_html)
        self.assertIn("records hidden", collapsed_html)

        self.window._on_evidence_anchor("sys", QUrl("#evd-sys-g-installed_apps"))
        restored = self.window.sys_results_area.toHtml()
        self.assertIn("pkg-0", restored)

    def test_small_groups_have_no_collapse_link(self):
        result = _sys_result(
            findings=[_finding("F")],
            footprint=[_footprint("System", "Installed Applications", "pkg-a")],
        )
        self.window.on_scan_complete(result)
        html = self.window.sys_results_area.toHtml()
        self.assertNotIn("Collapse", html)
        self.assertIn("pkg-a", html)

    def test_bad_evidence_anchors_ignored(self):
        result = _sys_result(
            findings=[_finding("F")],
            footprint=[_footprint("System", "Installed Applications", "pkg-a")],
        )
        self.window.on_scan_complete(result)
        before = self.window.sys_results_area.toHtml()
        for bad in ("#nope", "#evd-sys-g-", "#evd-sys-x", "#evd-sys-apps:z-show",
                    "#evd-sys-apps:0-maybe", ""):
            self.window._on_evidence_anchor("sys", QUrl(bad))
        self.window._on_evidence_anchor("unknown", QUrl("#evd-unknown-g-x"))
        self.assertEqual(self.window.sys_results_area.toHtml(), before)

    def test_per_tab_search_filter(self):
        footprint = [
            _footprint("System", "Installed Applications", "firefox-pkg"),
            _footprint("System", "Running Processes", "PID 1: systemd"),
        ]
        result = _sys_result(findings=[_finding("F")], footprint=footprint)
        self.window.on_scan_complete(result)
        self.window.sys_evidence_search.setText("firefox")
        self.window._render_view_evidence("sys")
        html = self.window.sys_results_area.toHtml()
        self.assertIn("firefox-pkg", html)
        self.assertNotIn("systemd", html)
        plain = self.window.sys_results_area.toPlainText()
        self.assertIn("Filter matched 1 of 2 records.", plain)
        # Underlying result untouched.
        self.assertEqual(len(result.footprint_data), 2)

    def test_per_tab_group_filter(self):
        footprint = [
            _footprint("System", "Installed Applications", "pkg-a"),
            _footprint("System", "Running Processes", "PID 1"),
        ]
        result = _sys_result(findings=[_finding("F")], footprint=footprint)
        self.window.on_scan_complete(result)
        self.window.sys_evidence_group.setCurrentText("Running Processes")
        self.window._render_view_evidence("sys")
        html = self.window.sys_results_area.toHtml()
        self.assertIn("PID 1", html)
        self.assertNotIn("pkg-a", html)

    def test_file_group_filter(self):
        footprint = [
            _footprint("File & Metadata", "File Information", "photo.jpg"),
            _footprint("File & Metadata", "Embedded Metadata", "Make: Canon"),
        ]
        result = ScanResult(
            scan_id="f-1", analysis_mode="My Footprint", scan_type="File & Metadata",
            scan_category="File & Metadata Footprint", status="COMPLETED",
            message="done", footprint_data=footprint, findings=[_finding("F")],
        )
        self.window.on_scan_complete(result)
        self.window.file_evidence_group.setCurrentText("Extracted metadata")
        self.window._render_view_evidence("file")
        html = self.window.file_results_area.toHtml()
        self.assertIn("Make: Canon", html)
        self.assertNotIn("photo.jpg", html)

    def test_no_match_note(self):
        result = _sys_result(
            findings=[_finding("F")],
            footprint=[_footprint("System", "Operating System", "Linux")],
        )
        self.window.on_scan_complete(result)
        self.window.sys_evidence_search.setText("zzz-nope")
        self.window._render_view_evidence("sys")
        self.assertIn("No records match",
                      self.window.sys_results_area.toHtml())


class TestCoverageDedupe(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    def _coverage_result(self, findings):
        return ScanResult(
            scan_id="cov-1", analysis_mode="My Footprint", scan_type="Browser",
            scan_category="Browser Footprint", status="COMPLETED", message="done",
            footprint_data=[], findings=findings,
        )

    def test_unavailable_sources_not_duplicated(self):
        paths = [f"/usr/bin/tool-{i}" for i in range(3)]
        finding = Finding(
            finding_id="unav-1", finding_type="Unavailable Sources",
            title="Sources That Could Not Be Checked",
            description=" | ".join(paths),
            evidence=list(paths), severity="Info", status="Informational",
        )
        self.window.on_scan_complete(self._coverage_result([finding]))
        html = self.window.browser_findings_area.toHtml()
        for path in paths:
            self.assertEqual(html.count(path), 1)

    def test_long_path_list_previewed_with_expand(self):
        paths = [f"/usr/bin/tool-{i}" for i in range(20)]
        finding = Finding(
            finding_id="unav-2", finding_type="Unavailable Sources",
            title="Sources That Could Not Be Checked",
            description=" | ".join(paths),
            evidence=list(paths), severity="Info", status="Informational",
        )
        self.window.on_scan_complete(self._coverage_result([finding]))
        html = self.window.browser_findings_area.toHtml()
        self.assertIn("Show all", html)
        self.assertNotIn(paths[-1], html)

        self.window._on_findings_anchor("browser", QUrl("#ev-0-show"))
        expanded = self.window.browser_findings_area.toHtml()
        self.assertIn(paths[-1], expanded)

    def test_warnings_keep_evidence_box(self):
        finding = Finding(
            finding_id="warn-1", finding_type="Scan Warnings",
            title="Non-Fatal Scan Warnings",
            description="2 warning(s) encountered during scan",
            evidence=["locked profile A", "locked profile B"],
            severity="Low", status="Informational",
        )
        self.window.on_scan_complete(self._coverage_result([finding]))
        html = self.window.browser_findings_area.toHtml()
        self.assertIn("locked profile A", html)
        self.assertIn("2 warning(s) encountered during scan", html)


class TestSummaryLayout(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    def test_summary_wraps_without_table(self):
        html = self.window.format_findings_html(
            [_finding("F")], evidence_count=1, scan_status="COMPLETED"
        )
        self.assertIn("SCAN SUMMARY:", html)
        self.assertIn("Total Findings:", html)
        self.assertIn(">1<", html)

    def test_full_scan_no_duplicate_module_labels(self):
        result = ScanResult(
            scan_id="full-1", analysis_mode="Full Footprint Analysis",
            scan_type="Full Scan", scan_category="Unified Footprint",
            status="COMPLETED", message="done",
            footprint_data=[
                _footprint("System", "Operating System", "Linux"),
                _footprint("Browser", "Detected Browser", "Brave"),
            ],
            findings=[_finding("F")],
        )
        self.window.on_scan_complete(result)
        html = self.window.full_scan_results_area.toHtml()
        self.assertIn("FULL SCAN EVIDENCE", html)
        self.assertEqual(html.count("System Footprint:"), 1)


class TestSmallWindowSmoke(unittest.TestCase):
    def test_small_window_renders_large_result(self):
        window = MainWindow()
        try:
            window.resize(640, 480)
            footprint = (
                [_footprint("System", "Installed Applications", f"pkg-{i}")
                 for i in range(200)]
                + [_footprint("Browser", "Extension",
                               f"Ext {i} (v1) | ID: id-{i} | Browser: B | Profile: P | desc {i}")
                   for i in range(50)]
            )
            result = ScanResult(
                scan_id="big-1", analysis_mode="Full Footprint Analysis",
                scan_type="Full Scan", scan_category="Unified Footprint",
                status="PARTIAL", message="partial",
                footprint_data=footprint,
                findings=[_finding("Big finding",
                                   evidence=[f"entry-{i}" for i in range(30)])],
            )
            window.on_scan_complete(result)
            self.assertIn("Big finding", window.full_scan_findings_area.toHtml())
            self.assertIn("pkg-0", window.full_scan_results_area.toHtml())
            self.assertTrue(window.full_scan_btn.isEnabled())
        finally:
            window.close()


class TestRecordTypography(unittest.TestCase):
    def test_headline_splits_name_from_version(self):
        html = format_evidence_record_html("Installed Applications", "pkg-a — version 2.4", "rpm")
        self.assertIn("<b>pkg-a</b>", html)
        self.assertIn("version 2.4", html)
        self.assertNotIn("<b>pkg-a — version 2.4</b>", html)

    def test_headline_without_separator_stays_bold(self):
        html = format_evidence_record_html(
            "Extension", "uBlock Origin (v1.2) | ID: abc | Browser: B | Profile: P | ads",
            "src", view_key="browser", record_key="extensions:0")
        self.assertIn("<b>uBlock Origin (v1.2) · B / P</b>", html)

    def test_path_details_monospace_prose_proportional(self):
        html = format_evidence_record_html(
            "Startup Applications", "Name: Agent | Scope: user | Path: /usr/bin/agent",
            "XDG")
        self.assertIn("font-family: monospace", html)
        self.assertIn("/usr/bin/agent", html)

    def test_severity_chips_have_spacing(self):
        window = MainWindow()
        try:
            html = window.format_findings_html([], evidence_count=0, scan_status="COMPLETED")
            self.assertIn("&nbsp;&nbsp;", html)
            self.assertIn("Critical", html)
        finally:
            window.close()


if __name__ == "__main__":
    unittest.main()
