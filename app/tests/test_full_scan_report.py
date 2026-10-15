"""Phase F tests for the Full Scan report redesign.

Covers the display summary adapter, finding-card rendering and subtitles,
evidence flattening, expand/collapse, evidence search/filter, browser
coverage presentation, and empty/partial/failed/skipped states.
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
    flatten_evidence_value,
    summarize_full_scan,
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


def _limitation(title, description="limited"):
    return Finding(
        finding_id=f"lim-{title}",
        finding_type="Scan Limitation",
        title=title,
        description=description,
        evidence=[description],
        severity="Info",
        status="Limitation",
        category="Observation",
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


def _full_result(status="COMPLETED", message="done.", findings=(), footprint=()):
    return ScanResult(
        scan_id="full-report-1",
        analysis_mode="Full Footprint Analysis",
        scan_type="Full Scan",
        scan_category="Unified Footprint",
        status=status,
        message=message,
        footprint_data=list(footprint),
        findings=list(findings),
    )


class TestFlattenEvidenceValue(unittest.TestCase):
    def test_nested_list_joined(self):
        self.assertEqual(flatten_evidence_value(["a", "b"]), "a; b")

    def test_dict_rendered_as_pairs(self):
        self.assertEqual(
            flatten_evidence_value({"searched": ["a", "b"], "n": 1}),
            "searched: a; b; n: 1",
        )

    def test_no_python_reprs(self):
        text = flatten_evidence_value({"searched": ["Chrome", "Edge"]})
        self.assertNotIn("['Chrome'", text)
        self.assertIn("Chrome; Edge", text)

    def test_none_and_empty(self):
        self.assertEqual(flatten_evidence_value(None), "")
        self.assertEqual(flatten_evidence_value({}), "")
        self.assertEqual(flatten_evidence_value([]), "")


class TestSummarizeFullScan(unittest.TestCase):
    def test_all_completed(self):
        result = _full_result(
            findings=[_finding("F1", severity="High", category="Concern")],
            footprint=[
                _footprint("System", "Operating System", "OS"),
                _footprint("Browser", "Detected Browser", "B"),
            ],
        )
        summary = summarize_full_scan(result)
        self.assertEqual(summary["status"], "COMPLETED")
        self.assertIn("all modules", summary["status_guidance"].lower())
        self.assertEqual(summary["total_findings"], 1)
        self.assertEqual(summary["severity_counts"]["High"], 1)
        self.assertEqual(summary["evidence_records"], 2)
        states = {m["name"]: m["state"] for m in summary["modules"]}
        self.assertEqual(states["System"], "completed")
        self.assertEqual(states["Browser"], "completed")

    def test_browser_unavailable_and_file_skipped(self):
        result = _full_result(
            status="PARTIAL",
            message=("Scan completed with partial results. browser footprint "
                     "unavailable on this platform. File scan skipped — no file selected."),
            findings=[_limitation("Module Limitation: Browser", "unavailable")],
            footprint=[_footprint("System", "Operating System", "OS")],
        )
        summary = summarize_full_scan(result)
        self.assertEqual(summary["status"], "PARTIAL")
        states = {m["name"]: (m["state"], m["note"]) for m in summary["modules"]}
        self.assertEqual(states["Browser"][0], "limited")
        self.assertIn("navailable", states["Browser"][1])
        self.assertEqual(states["File"][0], "skipped")
        self.assertEqual(states["System"][0], "completed")

    def test_failed_module_marked_limited(self):
        result = _full_result(
            status="PARTIAL",
            findings=[_limitation("Module Limitation: System", "boom")],
        )
        states = {m["name"]: m["state"] for m in summarize_full_scan(result)["modules"]}
        self.assertEqual(states["System"], "limited")

    def test_never_invents_modules_or_counts(self):
        summary = summarize_full_scan(_full_result())
        self.assertEqual(len(summary["modules"]), 3)
        self.assertEqual(summary["total_findings"], 0)
        self.assertEqual(summary["evidence_records"], 0)


class TestFindingCards(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    def test_severity_and_category_guidance(self):
        html = self.window.format_findings_html(
            [_finding("Bad thing", severity="High", category="Concern")]
        )
        self.assertIn("HIGH", html)  # raw badge kept
        self.assertIn("worth reviewing", html)
        self.assertIn("Potential concern", html)
        html2 = self.window.format_findings_html([_finding("Note")])
        self.assertIn("Informational observation", html2)

    def test_severity_chips_cover_all_tiers(self):
        html = self.window.format_findings_html(
            [_finding("H", severity="High")], scan_status="COMPLETED"
        )
        for sev in ("Critical", "High", "Medium", "Low", "Info"):
            self.assertIn(sev, html)

    def test_coverage_section_separated_with_disclaimers(self):
        findings = [
            _finding("Real concern", severity="Medium", category="Concern"),
            Finding(
                finding_id="cov-1",
                finding_type="Scan Coverage",
                title="Browser Footprint Scan Coverage",
                description="Browsers searched: A, B | Browsers detected: A",
                evidence={"searched": ["A", "B"], "detected": ["A"],
                          "not_detected": ["C"], "unsupported": ["IE"]},
                severity="Info",
                status="Informational",
            ),
            Finding(
                finding_id="unav-1",
                finding_type="Unavailable Sources",
                title="Sources That Could Not Be Checked",
                description="/home/u/.config/a | /home/u/.config/b",
                evidence=["/home/u/.config/a", "/home/u/.config/b"],
                severity="Info",
                status="Informational",
            ),
        ]
        html = self.window.format_findings_html(findings, scan_status="PARTIAL")
        self.assertIn("COVERAGE &amp; LIMITATIONS", html)
        self.assertIn("not proof", html)
        self.assertIn("not the same as a failed scan", html)
        self.assertIn("never", html)
        # Coverage title leaves the regular card flow but stays visible.
        self.assertIn("Browser Footprint Scan Coverage", html)
        # No raw Python reprs from the evidence dict.
        self.assertNotIn("['A', 'B']", html)
        self.assertIn("searched: A; B", html)
        # Long path list renders as bullets, not one joined line.
        self.assertNotIn("/home/u/.config/a | /home/u/.config/b", html)

    def test_error_empty_state_explains_failure(self):
        html = self.window.format_findings_html([], scan_status="ERROR")
        self.assertIn("did not complete", html)
        self.assertIn("No findings were generated", html)

    def test_expand_collapse_round_trip(self):
        entries = [f"entry-{i}" for i in range(15)]
        result = _full_result(
            findings=[_finding("Big", evidence=entries)],
            footprint=[_footprint("System", "Operating System", "OS")],
        )
        self.window.on_scan_complete(result)
        collapsed = self.window.full_scan_findings_area.toHtml()
        self.assertIn("Show all", collapsed)
        self.assertNotIn("entry-14", collapsed)

        self.window._on_findings_anchor("full", QUrl("#ev-0-show"))
        expanded = self.window.full_scan_findings_area.toHtml()
        self.assertIn("entry-14", expanded)
        self.assertIn("Show less", expanded)

        self.window._on_findings_anchor("full", QUrl("#ev-0-hide"))
        recollapsed = self.window.full_scan_findings_area.toHtml()
        self.assertNotIn("entry-14", recollapsed)
        self.assertIn("Show all", recollapsed)

    def test_bad_anchors_ignored(self):
        result = _full_result(findings=[_finding("F", evidence=["x"])])
        self.window.on_scan_complete(result)
        before = self.window.full_scan_findings_area.toHtml()
        for bad in ("#nope", "#ev-x-show", "#ev-0-maybe", "#ev-99-show", ""):
            self.window._on_findings_anchor("full", QUrl(bad))
        self.window._on_findings_anchor("unknown-view", QUrl("#ev-0-show"))
        self.assertEqual(self.window.full_scan_findings_area.toHtml(), before)


class TestEvidenceFilter(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()
        self.records = [
            _footprint("System", "Operating System", "Ubuntu 24.04"),
            _footprint("System", "Running Processes", "PID 1: systemd"),
            _footprint("Browser", "Detected Browser", "Firefox"),
            _footprint("Browser", "Extension", "uBlock Origin"),
        ]

    def tearDown(self):
        self.window.close()

    def test_filter_by_query(self):
        matched = filter_footprint(self.records, query="firefox")
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0].value, "Firefox")

    def test_filter_case_insensitive_source(self):
        matched = filter_footprint(self.records, query="test source")
        self.assertEqual(len(matched), 4)

    def test_filter_by_module(self):
        matched = filter_footprint(self.records, module="Browser")
        self.assertEqual(len(matched), 2)
        self.assertTrue(all(r.category == "Browser" for r in matched))

    def test_filter_no_match(self):
        self.assertEqual(filter_footprint(self.records, query="zzz-nope"), [])

    def test_ui_filter_narrows_rendered_evidence(self):
        result = _full_result(
            findings=[_finding("F")],
            footprint=self.records,
        )
        self.window.on_scan_complete(result)
        self.window.full_evidence_search.setText("firefox")
        self.window._render_full_scan_evidence()
        html = self.window.full_scan_results_area.toHtml()
        self.assertIn("Firefox", html)
        self.assertNotIn("systemd", html)
        plain = self.window.full_scan_results_area.toPlainText()
        self.assertIn("Filter matched 1 of 4 records.", plain)

    def test_ui_module_filter(self):
        result = _full_result(findings=[_finding("F")], footprint=self.records)
        self.window.on_scan_complete(result)
        self.window.full_evidence_module.setCurrentText("System")
        self.window._render_full_scan_evidence()
        html = self.window.full_scan_results_area.toHtml()
        self.assertIn("Ubuntu", html)
        self.assertNotIn("Firefox", html)

    def test_ui_no_match_note(self):
        result = _full_result(findings=[_finding("F")], footprint=self.records)
        self.window.on_scan_complete(result)
        self.window.full_evidence_search.setText("zzz-nope")
        self.window._render_full_scan_evidence()
        html = self.window.full_scan_results_area.toHtml()
        self.assertIn("No records match", html)


class TestLargeEvidenceCollections(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    def test_thousands_of_records_render_grouped(self):
        footprint = (
            [_footprint("System", "Installed Applications", f"pkg-{i}") for i in range(3000)]
            + [_footprint("System", "Running Processes", f"PID {i}") for i in range(1000)]
            + [_footprint("Browser", "Extension", f"ext-{i}") for i in range(500)]
        )
        result = _full_result(
            findings=[_finding("F")],
            footprint=footprint,
        )
        self.window.on_scan_complete(result)
        html = self.window.full_scan_results_area.toHtml()
        self.assertIn("Installed Applications (3000 detected)", html)
        self.assertIn("Running Processes (1000 detected)", html)
        self.assertIn("Installed Extensions (500)", html)
        self.assertEqual(self.window.full_scan_sub_tabs.tabText(1), "Collected Evidence (4500)")

    def test_large_filter_completes(self):
        footprint = [_footprint("System", "Installed Applications", f"pkg-{i}") for i in range(5000)]
        matched = filter_footprint(footprint, query="pkg-4999")
        self.assertEqual(len(matched), 1)


class TestReportStates(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    def test_partial_summary_shows_guidance_and_modules(self):
        result = _full_result(
            status="PARTIAL",
            message="partial. browser footprint unavailable. File scan skipped — no file selected.",
            findings=[_limitation("Module Limitation: Browser", "unavailable")],
            footprint=[_footprint("System", "Operating System", "OS")],
        )
        self.window.on_scan_complete(result)
        html = self.window.full_scan_findings_area.toHtml()
        self.assertIn("Finished with gaps", html)
        self.assertIn("Browser", html)
        self.assertIn("Skipped", html)

    def test_individual_views_unaffected(self):
        result = ScanResult(
            scan_id="sys-1",
            analysis_mode="My Footprint",
            scan_type="System",
            scan_category="System Footprint",
            status="COMPLETED",
            message="done",
            footprint_data=[_footprint("System", "Operating System", "OS")],
            findings=[_finding("Sys finding", evidence=["a", "b"])],
        )
        self.window.on_scan_complete(result)
        self.assertIn("Sys finding", self.window.sys_findings_area.toHtml())
        self.assertIn("Finished", self.window.sys_findings_area.toHtml())


if __name__ == "__main__":
    unittest.main()
