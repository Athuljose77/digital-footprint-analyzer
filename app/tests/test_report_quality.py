"""Phase E tests for Full Scan report quality and evidence readability.

Covers findings-card evidence formatting, the evidence-counting rule,
summary accuracy, and limitation handling using the offscreen Qt setup.
"""
import os
import sys
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from PySide6.QtWidgets import QApplication

from app.ui.main_window import (
    FINDING_EVIDENCE_PREVIEW_LIMIT,
    MainWindow,
    collect_finding_evidence_items,
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


def _footprint(category, subcategory, value):
    return FootprintData(
        category=category,
        subcategory=subcategory,
        source="Test Source",
        data_type="String",
        value=value,
        sensitivity="Low",
    )


class TestFindingEvidenceHelpers(unittest.TestCase):
    def test_list_entries_kept_separate(self):
        items = collect_finding_evidence_items(["alpha", "beta", "gamma"])
        self.assertEqual(items, ["alpha", "beta", "gamma"])

    def test_none_and_blank_entries_dropped(self):
        items = collect_finding_evidence_items(["alpha", None, "   ", "", "beta"])
        self.assertEqual(items, ["alpha", "beta"])

    def test_none_evidence_is_empty(self):
        self.assertEqual(collect_finding_evidence_items(None), [])

    def test_empty_list_is_empty(self):
        self.assertEqual(collect_finding_evidence_items([]), [])

    def test_string_evidence_is_single_entry(self):
        self.assertEqual(collect_finding_evidence_items("just one"), ["just one"])

    def test_blank_string_is_empty(self):
        self.assertEqual(collect_finding_evidence_items("   "), [])

    def test_dict_evidence_renders_pairs(self):
        items = collect_finding_evidence_items({"a": 1, "b": 2})
        self.assertEqual(items, ["a: 1", "b: 2"])

    def test_empty_dict_is_empty(self):
        self.assertEqual(collect_finding_evidence_items({}), [])

    def test_non_string_entries_stringified(self):
        items = collect_finding_evidence_items([123, True])
        self.assertEqual(items, ["123", "True"])


class TestFindingsCardEvidenceRendering(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    def test_multiple_entries_render_separately(self):
        html = format_finding_evidence_html(["alpha", "beta", "gamma"])
        # Each entry on its own bullet line, not one joined string.
        self.assertEqual(html.count("•"), 3)
        self.assertNotIn("alpha, beta, gamma", html)
        self.assertIn("alpha", html)
        self.assertIn("beta", html)
        self.assertIn("gamma", html)

    def test_html_sensitive_content_escaped(self):
        html = format_finding_evidence_html(['<script>alert("x")</script>'])
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_empty_evidence_renders_placeholder(self):
        for empty in (None, [], {}, "   "):
            with self.subTest(empty=empty):
                html = format_finding_evidence_html(empty)
                self.assertIn("No evidence recorded", html)

    def test_large_evidence_preview_capped(self):
        entries = [f"entry-{i}" for i in range(FINDING_EVIDENCE_PREVIEW_LIMIT + 5)]
        html = format_finding_evidence_html(entries)
        self.assertEqual(html.count("•"), FINDING_EVIDENCE_PREVIEW_LIMIT)
        self.assertIn("+5 more", html)
        self.assertIn("Collected Evidence", html)
        self.assertNotIn(f"entry-{FINDING_EVIDENCE_PREVIEW_LIMIT + 4}", html)

    def test_card_does_not_duplicate_entire_collection(self):
        entries = [f"entry-{i}" for i in range(50)]
        finding = _finding("Big finding", evidence=entries)
        html = self.window.format_findings_html([finding], evidence_count=0)
        # Only preview entries plus one "+N more" note may appear.
        self.assertEqual(html.count("entry-"), FINDING_EVIDENCE_PREVIEW_LIMIT)
        self.assertIn("+40 more", html)

    def test_long_strings_use_word_break(self):
        html = format_finding_evidence_html(["x" * 500])
        self.assertIn("word-break", html)


class TestSummaryCounts(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    def _summary_html(self, findings, footprint_count, status="COMPLETED"):
        return self.window.format_findings_html(
            findings, evidence_count=footprint_count, scan_status=status
        )

    def test_evidence_count_matches_footprint_records(self):
        # Three FootprintData records -> Evidence Items reports exactly 3,
        # even though finding evidence lists reference the same data.
        findings = [_finding("F1", evidence=["a", "b", "c"])]
        html = self._summary_html(findings, 3)
        self.assertIn("Evidence Items:", html)
        self.assertIn(">3<", html)
        # Finding evidence entries are not added on top.
        self.assertNotIn(">6<", html)

    def test_findings_and_evidence_counts_distinct(self):
        findings = [_finding("F1"), _finding("F2")]
        html = self._summary_html(findings, 3133)
        self.assertIn("Total Findings:", html)
        self.assertIn(">2<", html)
        self.assertIn(">3133<", html)

    def test_empty_data_renders_cleanly(self):
        html = self._summary_html([], 0)
        self.assertIn("Total Findings:", html)
        self.assertIn(">0<", html)
        self.assertIn("No findings were generated", html)

    def test_concerns_vs_observations(self):
        findings = [
            _finding("C1", severity="High", category="Concern"),
            _finding("O1", category="Observation"),
            _finding("O2", category="Observation"),
        ]
        html = self._summary_html(findings, 0)
        self.assertIn("Concerns:", html)
        self.assertIn("Observations:", html)
        # 1 concern + 2 observations out of 3 findings.
        self.assertIn(">3<", html)

    def test_limitations_shown_as_coverage_not_exposure(self):
        findings = [
            _finding("Real concern", severity="High", category="Concern"),
            Finding(
                finding_id="lim-1",
                finding_type="Scan Limitation",
                title="Module Limitation: Browser",
                description="Browser unavailable",
                evidence=["unavailable"],
                severity="Info",
                status="Limitation",
                category="Observation",
            ),
        ]
        html = self._summary_html(findings, 5, status="PARTIAL")
        self.assertIn("Scan Limitations (1)", html)
        self.assertIn("not confirmed privacy exposures", html)
        # The limitation does not inflate the Concerns count.
        self.assertIn(">1<", html)  # one concern only

    def test_status_banner_rendered(self):
        for status in ("COMPLETED", "PARTIAL", "ERROR"):
            with self.subTest(status=status):
                html = self._summary_html([], 0, status=status)
                self.assertIn("Scan Status:", html)
                self.assertIn(status, html)

    def test_repeated_references_not_double_counted(self):
        # Same record referenced by a finding and present in footprint data
        # counts once: the summary uses len(footprint_data) only.
        findings = [_finding("F1", evidence=["shared-record"])]
        footprint = [_footprint("System", "Operating System", "shared-record")]
        result = ScanResult(
            scan_id="r1",
            analysis_mode="Full Footprint Analysis",
            scan_type="Full Scan",
            scan_category="Unified Footprint",
            status="COMPLETED",
            message="done",
            footprint_data=footprint,
            findings=findings,
        )
        html = self.window.format_findings_html(
            result.findings,
            evidence_count=len(result.footprint_data),
            scan_status=result.status,
        )
        self.assertIn(">1<", html)
        self.assertNotIn(">2<", html)


class TestFullScanReportViews(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    def _full_result(self, status="COMPLETED", message="done.", findings=(), footprint=()):
        return ScanResult(
            scan_id="full-1",
            analysis_mode="Full Footprint Analysis",
            scan_type="Full Scan",
            scan_category="Unified Footprint",
            status=status,
            message=message,
            footprint_data=list(footprint),
            findings=list(findings),
        )

    def test_startup_evidence_readable_lines(self):
        apps = [
            f"Name: App{i} | Scope: user | Enabled: True | Path: /usr/bin/app{i}"
            for i in range(12)
        ]
        result = self._full_result(
            findings=[_finding("Persistent Startup Footprint (12 detected)",
                               severity="Low", evidence=apps)],
            footprint=[_footprint("System", "Startup Applications", a) for a in apps],
        )
        self.window.on_scan_complete(result)
        card_html = self.window.full_scan_findings_area.toHtml()
        self.assertEqual(
            card_html.count("Name: App"), FINDING_EVIDENCE_PREVIEW_LIMIT
        )
        self.assertIn("+2 more", card_html)
        self.assertNotIn("Name: App0, Name: App1", card_html)

    def test_individual_system_view_uses_shared_renderer(self):
        result = ScanResult(
            scan_id="sys-1",
            analysis_mode="My Footprint",
            scan_type="System",
            scan_category="System Footprint",
            status="COMPLETED",
            message="done",
            footprint_data=[_footprint("System", "Operating System", "TestOS")],
            findings=[_finding("Sys finding", evidence=["one", "two"])],
        )
        self.window.on_scan_complete(result)
        card_html = self.window.sys_findings_area.toHtml()
        self.assertIn("Sys finding", card_html)
        self.assertIn("Scan Status:", card_html)
        self.assertIn("COMPLETED", card_html)
        self.assertNotIn("one, two", card_html)


if __name__ == "__main__":
    unittest.main()
