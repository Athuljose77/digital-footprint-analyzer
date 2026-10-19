"""Tests for the expanded pages: assessment, evidence, actions, and history.

These tests drive the real MainWindow, because the property that matters most
is that every page shows the same numbers as the dashboard and the exports for
one and the same scan.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from PySide6.QtWidgets import QApplication

from app.core.findings_processor import with_provenance
from app.core.history import ScanHistoryStore
from app.core.remediation.models import COMPLETED, DISMISSED, PENDING
from app.core.remediation.store import ActionStateStore
from app.models.common import Finding, FootprintData, ScanResult
from app.ui.main_window import MainWindow

app = QApplication.instance()
if app is None:
    app = QApplication([])

TOKEN = "AKIAIOSFODNN7EXAMPLE1234"

FULL_COVERAGE = [
    {"name": "System", "key": "system", "state": "completed", "note": "Completed"},
    {"name": "Browser", "key": "browser", "state": "completed", "note": "Completed"},
    {"name": "File", "key": "file_metadata", "state": "completed", "note": "Completed"},
]

PARTIAL_COVERAGE = [
    {"name": "System", "key": "system", "state": "completed", "note": "Completed"},
    {"name": "Browser", "key": "browser", "state": "unavailable",
     "note": "Unavailable on this platform — not scanned"},
    {"name": "File", "key": "file_metadata", "state": "skipped",
     "note": "Skipped — no file was selected"},
]

# Includes the email module, so a finding owned by "email" can legitimately be
# called resolved when it disappears from the next scan.
EMAIL_COVERAGE = FULL_COVERAGE + [
    {"name": "Email", "key": "email", "state": "completed", "note": "Completed"},
]


def _finding(title, severity="High", finding_type="Email Breach",
             rule_id="EML-BREACH-001", module="email",
             verification="provider-verified", evidence=("emails: 3",),
             description="", category="Observation"):
    finding = Finding(
        finding_id=f"id-{title}",
        finding_type=finding_type,
        title=title,
        description=description or f"Description for {title}",
        evidence=list(evidence),
        severity=severity,
        status="Unremediated",
        rule_id=rule_id,
        category=category,
    )
    return with_provenance(finding, explicit_module=module,
                           explicit_verification=verification)


def _footprint(value="Linux"):
    return FootprintData(category="System", subcategory="Operating System",
                         source="Test", data_type="String", value=value,
                         sensitivity="Low")


def _result(scan_type="Full Scan", status="COMPLETED", findings=(),
            footprint=None, coverage=None, message="ok"):
    categories = {"Full Scan": "Unified Footprint", "System": "System Footprint",
                  "Email": "Email Footprint"}
    result = ScanResult(
        scan_id=f"{scan_type}-{status}-1",
        analysis_mode="Full Footprint Analysis" if scan_type == "Full Scan"
        else "My Footprint",
        scan_type=scan_type,
        scan_category=categories.get(scan_type, "Test"),
        status=status,
        message=message,
        footprint_data=list(footprint if footprint is not None
                            else [_footprint()]),
        findings=list(findings),
        module_coverage=coverage,
    )
    result.started_at = "2026-10-19T10:00:00Z"
    result.finished_at = "2026-10-19T10:00:05Z"
    return result


class ExpandedPageTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dfa-pages-test-")
        self.window = MainWindow()
        # Isolate storage so tests never see each other's scans.
        history = ScanHistoryStore(os.path.join(self.tmp, "history.db"))
        actions = ActionStateStore(os.path.join(self.tmp, "actions.db"))
        self.window.history_store = history
        self.window.action_store = actions
        self.window.history_page.set_store(history)

    def tearDown(self):
        self.window.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_scan(self, result):
        self.window.on_scan_complete(result)
        return result


class TestNavigation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dfa-nav-test-")
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_new_pages_are_appended_after_settings(self):
        labels = [self.window.sidebar.item(i).text()
                  for i in range(self.window.sidebar.count())]
        self.assertEqual(labels, ["Home", "My Footprint", "Public Lookup",
                                  "Settings", "Assessment", "Evidence",
                                  "Actions", "History"])
        self.assertEqual(self.window.pages.count(), 8)

    def test_existing_page_indices_are_unchanged(self):
        for index in range(4):
            self.window.sidebar.setCurrentRow(index)
            self.assertEqual(self.window.pages.currentIndex(), index)
        self.assertEqual(self.window.pages.currentIndex(), 3)

    def test_show_page_selects_by_name(self):
        self.assertTrue(self.window.show_page("actions"))
        self.assertEqual(self.window.pages.currentIndex(), 6)
        self.assertEqual(self.window.sidebar.currentRow(), 6)
        self.assertTrue(self.window.show_page("Home"))
        self.assertEqual(self.window.pages.currentIndex(), 0)

    def test_show_page_rejects_unknown_names(self):
        self.assertFalse(self.window.show_page("nope"))


class TestDashboardStrip(ExpandedPageTestCase):
    def test_empty_state_before_any_scan(self):
        self.assertIn("No scan yet", self.window.home_risk_label.text())
        self.assertIn("No actions yet", self.window.home_actions_label.text())

    def test_strip_matches_the_score_everywhere_else(self):
        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=FULL_COVERAGE))
        risk = self.window.latest_risk
        self.assertIsNotNone(risk)
        self.assertIn(f"{risk.score}/100", self.window.home_risk_label.text())
        self.assertIn(risk.band, self.window.home_risk_label.text())
        self.assertIn(f"{risk.score}", self.window.assessment_page.score_label.text())

    def test_strip_reports_pending_actions(self):
        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=FULL_COVERAGE))
        self.assertIn("1", self.window.home_actions_label.text())
        self.assertIn("pending", self.window.home_actions_label.text())

    def test_score_without_coverage_shows_no_number_and_says_why(self):
        self.run_scan(_result(
            status="ERROR", findings=[], coverage=[
                {"name": "System", "key": "system", "state": "failed",
                 "note": "boom"}],
            message="all modules failed"))
        self.assertIsNone(self.window.latest_risk.score)
        self.assertIn("No score", self.window.home_risk_label.text())
        self.assertIn("Indeterminate", self.window.home_risk_label.text())


class TestAssessmentPage(ExpandedPageTestCase):
    def test_export_disabled_until_a_scan_runs(self):
        self.assertFalse(self.window.assessment_page.pdf_btn.isEnabled())
        self.assertFalse(self.window.assessment_page.json_btn.isEnabled())
        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=FULL_COVERAGE))
        self.assertTrue(self.window.assessment_page.pdf_btn.isEnabled())

    def test_body_explains_the_score(self):
        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=FULL_COVERAGE))
        body = self.window.assessment_page.body.toPlainText()
        for expected in ("How this score was calculated",
                         "What this assessment does not cover",
                         "Module coverage",
                         "Top issues by weight",
                         "Exposed in Adobe"):
            self.assertIn(expected, body)

    def test_coverage_label_lists_gaps(self):
        self.run_scan(_result(status="PARTIAL", coverage=PARTIAL_COVERAGE,
                              message="partial"))
        text = self.window.assessment_page.coverage_label.text()
        self.assertIn("1 of 3", text)
        self.assertIn("Browser", text)
        self.assertIn("File", text)

    def test_export_writes_all_three_formats(self):
        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=FULL_COVERAGE))
        page = self.window.assessment_page
        for fmt, extension in (("json", ".json"), ("csv", ".csv"),
                               ("pdf", ".pdf")):
            written = page.export(fmt, os.path.join(self.tmp, f"report{extension}"))
            self.assertTrue(os.path.exists(written))
            self.assertGreater(os.path.getsize(written), 0)

    def test_export_failure_is_reported_inline(self):
        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=FULL_COVERAGE))
        with self.assertRaises(Exception):
            self.window.assessment_page.export(
                "json", os.path.join(self.tmp, "missing", "r.json"))

    def test_export_before_a_scan_is_refused_cleanly(self):
        with self.assertRaises(Exception):
            self.window.assessment_page.export(
                "json", os.path.join(self.tmp, "r.json"))

    def test_suggested_name_has_no_private_paths(self):
        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=FULL_COVERAGE))
        name = self.window.assessment_page.suggested_name("pdf")
        self.assertTrue(name.startswith("footprint-full-scan-"))
        self.assertTrue(name.endswith(".pdf"))
        self.assertNotIn("/", name)

    def test_theme_switch_keeps_the_assessment_readable(self):
        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=FULL_COVERAGE))
        from app.ui import theme

        try:
            theme.set_dark_theme(False)
            self.window.assessment_page.refresh_theme()
            light = self.window.assessment_page.body.toPlainText()
            theme.set_dark_theme(True)
            self.window.assessment_page.refresh_theme()
            dark = self.window.assessment_page.body.toPlainText()
            self.assertEqual(light, dark)
        finally:
            theme.set_dark_theme(self.window.is_dark_mode)


class TestEvidencePage(ExpandedPageTestCase):
    def setUp(self):
        super().setUp()
        self.run_scan(_result(
            findings=[
                _finding("Exposed in Adobe", severity="High"),
                _finding("Public Profile Discovered on ExampleSite",
                         severity="Info", finding_type="Public Presence",
                         rule_id="USR-PROFILE-001", module="username",
                         verification="unconfirmed"),
                _finding("Sensitive Metadata in holiday.jpg", severity="Medium",
                         finding_type="Sensitive Metadata",
                         rule_id="FILE-GPS-001", module="file_metadata",
                         verification="direct-observation",
                         evidence=("GPS: 35.6895, 139.6917",)),
            ],
            coverage=FULL_COVERAGE))

    def test_all_findings_are_listed(self):
        self.assertEqual(self.window.evidence_page.table.rowCount(), 3)

    def test_severity_filter_narrows_the_list(self):
        page = self.window.evidence_page
        page.severity_filter.setCurrentText("Medium")
        self.assertEqual(page.visible_titles(),
                         ["Sensitive Metadata in holiday.jpg"])
        self.assertIn("Showing 1 of 3", page.count_label.text())

    def test_module_filter_narrows_the_list(self):
        page = self.window.evidence_page
        page.module_filter.setCurrentText("username")
        self.assertEqual(page.visible_titles(),
                         ["Public Profile Discovered on ExampleSite"])

    def test_verification_filter_narrows_the_list(self):
        page = self.window.evidence_page
        page.verification_filter.setCurrentText("unconfirmed")
        self.assertEqual(len(page.visible_findings()), 1)

    def test_confidence_filter_narrows_the_list(self):
        page = self.window.evidence_page
        page.confidence_filter.setCurrentText("high")
        self.assertEqual(len(page.visible_findings()), 2)

    def test_search_matches_title_and_evidence(self):
        page = self.window.evidence_page
        page.search.setText("holiday")
        self.assertEqual(len(page.visible_findings()), 1)
        page.search.setText("35.6895")
        self.assertEqual(len(page.visible_findings()), 1)
        page.search.setText("nothing-matches-this")
        self.assertEqual(len(page.visible_findings()), 0)
        self.assertIn("No findings match", page.count_label.text())

    def test_sorting_changes_order(self):
        page = self.window.evidence_page
        page.sort_combo.setCurrentText("Module")
        modules = [str(getattr(f, "source_module", ""))
                   for f in page.visible_findings()]
        self.assertEqual(modules, sorted(modules))

    def test_detail_pane_shows_provenance(self):
        page = self.window.evidence_page
        page.search.setText("holiday")
        detail = page.detail_text()
        for expected in ("file_metadata", "direct-observation", "GPS",
                         "Why it matters", "Identity key"):
            self.assertIn(expected, detail)

    def test_empty_scan_shows_an_empty_state(self):
        self.window.evidence_page.clear()
        self.assertEqual(self.window.evidence_page.table.rowCount(), 0)
        self.assertIn("No scan data yet",
                      self.window.evidence_page.count_label.text())

    def test_stored_findings_can_be_shown(self):
        record = self.window.history_store.list_scans()[0]
        self.window.show_stored_findings(record)
        self.assertEqual(self.window.pages.currentIndex(), 5)
        self.assertIn("stored scan", self.window.evidence_page.count_label.text())

    def test_large_result_sets_render(self):
        findings = [_finding(f"Finding number {index}",
                             severity=["High", "Medium", "Low", "Info"][index % 4])
                    for index in range(300)]
        self.run_scan(_result(findings=findings, coverage=FULL_COVERAGE))
        page = self.window.evidence_page
        self.assertEqual(page.table.rowCount(), 300)
        page.search.setText("number 42 —")
        page.search.setText("Finding number 42")
        self.assertGreaterEqual(len(page.visible_findings()), 1)


class TestActionCentre(ExpandedPageTestCase):
    def setUp(self):
        super().setUp()
        self.run_scan(_result(
            findings=[
                _finding("Exposed in Adobe", severity="High"),
                _finding("Public Profile Discovered on ExampleSite",
                         severity="Info", finding_type="Public Presence",
                         rule_id="USR-PROFILE-001", module="username",
                         verification="unconfirmed"),
            ],
            coverage=FULL_COVERAGE))

    def key_for(self, index=0):
        return self.window.action_page.board.items[index].action.action_key

    def test_actions_are_derived_from_findings(self):
        titles = self.window.action_page.card_titles()
        self.assertEqual(len(titles), 2)
        self.assertTrue(any("Adobe" in t for t in titles))

    def test_pending_count_is_shown(self):
        self.assertEqual(self.window.action_page.pending_count(), 2)
        self.assertIn("2", self.window.action_page.summary_text())

    def test_marking_complete_persists_and_updates_the_dashboard(self):
        key = self.key_for(0)
        self.window.on_action_state_changed(key, COMPLETED)
        self.assertEqual(self.window.action_store.get_state(key), COMPLETED)
        self.assertEqual(self.window.action_page.pending_count(), 1)
        self.assertIn("1", self.window.home_actions_label.text())

    def test_marking_complete_is_not_a_verification(self):
        key = self.key_for(0)
        self.window.on_action_state_changed(key, COMPLETED)
        board = self.window.action_page.board
        completed = [item for item in board.items if item.action.action_key == key]
        self.assertTrue(completed)
        self.assertIn("Marked complete by you", completed[0].status_note)
        self.assertIn("not a technical verification", completed[0].status_note)
        # Marking complete does not remove it from the plan: the finding is
        # still in the latest scan, so it is not claimed to be gone.
        self.assertTrue(completed[0].present_in_latest_scan)
        self.assertEqual(board.not_detected, [])
        self.assertIn("Re-run the scan", completed[0].status_note)

    def test_dismiss_keeps_it_visible_and_counted_separately(self):
        key = self.key_for(0)
        self.window.on_action_state_changed(key, DISMISSED)
        self.assertEqual(self.window.action_page.board.dismissed, 1)
        self.assertEqual(self.window.action_page.pending_count(), 1)

    def test_reopen_returns_an_action_to_pending(self):
        key = self.key_for(0)
        self.window.on_action_state_changed(key, COMPLETED)
        self.window.on_action_state_changed(key, PENDING)
        self.assertEqual(self.window.action_store.get_state(key), PENDING)
        self.assertEqual(self.window.action_page.pending_count(), 2)

    def test_filtering_by_state(self):
        page = self.window.action_page
        self.window.on_action_state_changed(self.key_for(0), COMPLETED)
        page.filter_combo.setCurrentText("Completed by you")
        self.assertEqual(len(page.visible_titles()), 1)
        page.filter_combo.setCurrentText("Pending")
        self.assertEqual(len(page.visible_titles()), 1)
        page.filter_combo.setCurrentText("All actions")
        self.assertEqual(len(page.visible_titles()), 2)

    def test_unconfirmed_evidence_is_flagged_to_check_first(self):
        board = self.window.action_page.board
        flagged = [item for item in board.items if item.action.verify_first]
        self.assertTrue(flagged)
        self.assertIn("check it before acting", flagged[0].status_note)

    def test_no_findings_means_no_advice(self):
        self.run_scan(_result(findings=[], coverage=FULL_COVERAGE))
        self.assertEqual(self.window.action_page.pending_count(), 0)
        self.assertEqual(self.window.action_page.card_titles(), [])
        self.assertIn("No findings were detected",
                      self.window.action_page.plan.note)

    def test_completed_action_survives_a_restart(self):
        key = self.key_for(0)
        self.window.on_action_state_changed(key, COMPLETED)
        reopened = ActionStateStore(os.path.join(self.tmp, "actions.db"))
        self.assertEqual(reopened.get_state(key), COMPLETED)

    def test_actions_do_not_leak_file_paths(self):
        self.run_scan(_result(
            findings=[_finding("Sensitive Metadata in /home/someone/private/a.png",
                               finding_type="Sensitive Metadata",
                               rule_id="FILE-GPS-001", module="file_metadata",
                               severity="Medium",
                               verification="direct-observation")],
            coverage=FULL_COVERAGE))
        titles = self.window.action_page.card_titles()
        self.assertTrue(titles)
        for title in titles:
            self.assertNotIn("/home/someone", title)


class TestHistoryPage(ExpandedPageTestCase):
    def scan_twice(self, second_findings, second_coverage=EMAIL_COVERAGE):
        """Run an email-module scan twice so both scans cover the same module.

        The default coverage includes the email module, because a finding may
        only be called resolved when its own module ran again.
        """
        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=EMAIL_COVERAGE))
        first = self.window.history_store.list_scans()[0]
        self.run_scan(_result(findings=second_findings,
                              coverage=second_coverage))
        scans = self.window.history_store.list_scans()
        second = [s for s in scans if s.id != first.id][0]
        return first, second

    def test_completed_scans_are_stored(self):
        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=FULL_COVERAGE))
        self.assertEqual(self.window.history_page.table.rowCount(), 1)
        self.assertIn("1 stored scan", self.window.history_page.count_text())

    def test_history_survives_a_new_store_instance(self):
        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=FULL_COVERAGE))
        reopened = ScanHistoryStore(os.path.join(self.tmp, "history.db"))
        self.assertEqual(reopened.count(), 1)

    def test_delete_selected_removes_one_row(self):
        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=FULL_COVERAGE))
        self.run_scan(_result(findings=[_finding("Second issue")],
                              coverage=FULL_COVERAGE))
        page = self.window.history_page
        self.assertEqual(page.table.rowCount(), 2)
        page.select_rows(0)
        self.assertEqual(page.delete_selected(confirm=False), 1)
        self.assertEqual(page.table.rowCount(), 1)

    def test_clear_all_removes_every_row(self):
        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=FULL_COVERAGE))
        page = self.window.history_page
        self.assertEqual(page.clear_all(confirm=False), 1)
        self.assertEqual(page.table.rowCount(), 0)
        self.assertIn("Cleared 1", page.count_text())
        page.refresh()
        self.assertEqual(page.table.rowCount(), 0)
        self.assertIn("No scans stored", page.count_text())

    def test_comparison_needs_exactly_two_rows(self):
        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=FULL_COVERAGE))
        page = self.window.history_page
        page.select_rows(0)
        self.assertIsNone(page.compare_selected(confirm=False))
        self.assertIn("exactly two", page.comparison_text())

    def test_resolved_finding_is_reported_honestly(self):
        first, second = self.scan_twice([])
        page = self.window.history_page
        page.select_rows(0, 1)
        comparison = page.compare_selected(confirm=False)
        self.assertIsNotNone(comparison)
        self.assertEqual(comparison.counts["resolved"], 1)
        self.assertIn("1 resolved", page.comparison_text())

    def test_not_rechecked_when_the_owning_module_did_not_run(self):
        self.run_scan(_result(findings=[_finding("Browser Profile Detected",
                                                 finding_type="Browser Profile",
                                                 rule_id="BRW-PROFILE-001",
                                                 module="browser",
                                                 severity="Medium")],
                              coverage=FULL_COVERAGE))
        limited = [dict(row) for row in FULL_COVERAGE]
        limited[1] = {"name": "Browser", "key": "browser", "state": "failed",
                      "note": "boom"}
        self.run_scan(_result(findings=[], coverage=limited))
        page = self.window.history_page
        page.select_rows(0, 1)
        comparison = page.compare_selected(confirm=False)
        self.assertEqual(comparison.counts["not_rechecked"], 1)
        self.assertEqual(comparison.counts["resolved"], 0)
        self.assertIn("not rechecked", page.comparison_text())

    def test_score_delta_hidden_when_coverage_changes(self):
        restricted = [{"name": "System", "key": "system", "state": "completed",
                       "note": "Completed"}]
        self.scan_twice([_finding("Another issue")], second_coverage=restricted)
        page = self.window.history_page
        page.select_rows(0, 1)
        comparison = page.compare_selected(confirm=False)
        self.assertFalse(comparison.score_comparable)
        self.assertIsNone(comparison.score_delta)
        self.assertIn("different modules", page.comparison_text())

    def test_comparison_lists_new_findings(self):
        self.scan_twice([_finding("Exposed in Adobe"),
                         _finding("Exposed in NewService")])
        page = self.window.history_page
        page.select_rows(0, 1)
        comparison = page.compare_selected(confirm=False)
        self.assertEqual(comparison.counts["new"], 1)
        self.assertEqual(comparison.counts["unchanged"], 1)

    def test_storage_path_is_stated(self):
        self.assertIn("History file:", self.window.history_page.storage_note.text())


class TestPrivacyAndStorage(ExpandedPageTestCase):
    def test_history_masks_targets_and_tokens(self):
        self.window.target_input.setText("someone@example.com")
        self.window.on_scan_complete(_result(
            scan_type="Email",
            findings=[_finding("System Configuration",
                               finding_type="System Configuration",
                               rule_id="SYS-STARTUP-001", module="system",
                               evidence=(f"command: run --token {TOKEN}",),
                               severity="Low")],
            coverage=None))
        record = self.window.history_store.list_scans()[0]
        self.assertEqual(record.target_label, "s***@example.com")
        blob = " ".join(record.findings[0].evidence_preview)
        self.assertNotIn(TOKEN, blob)

        with open(self.window.history_store.db_path, "rb") as handle:
            raw = handle.read()
        self.assertNotIn(TOKEN.encode(), raw)

    def test_report_does_not_contain_secrets(self):
        self.run_scan(_result(
            findings=[_finding("Sensitive Metadata in /home/someone/private/a.png",
                               finding_type="Sensitive Metadata",
                               rule_id="FILE-GPS-001", module="file_metadata",
                               severity="Medium",
                               verification="direct-observation",
                               evidence=(f"api_key={TOKEN}",
                                         "/home/someone/private/a.png"))],
            coverage=FULL_COVERAGE))
        written = self.window.assessment_page.export(
            "json", os.path.join(self.tmp, "report.json"))
        with open(written, "rb") as handle:
            raw = handle.read()
        self.assertNotIn(TOKEN.encode(), raw)
        self.assertNotIn(b"/home/someone/private", raw)

    def test_broken_history_store_does_not_break_scanning(self):
        class Broken(ScanHistoryStore):
            def record_scan(self, *args, **kwargs):
                from app.core.history import HistoryStoreError

                raise HistoryStoreError("disk full")

        self.window.history_store = Broken(os.path.join(self.tmp, "broken.db"))
        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=FULL_COVERAGE))
        self.assertIsNotNone(self.window.latest_risk)
        self.assertIn("disk full", self.window.history_page.count_label.text())

    def test_broken_action_store_does_not_break_the_page(self):
        class Broken(ActionStateStore):
            def sync(self, actions):
                raise RuntimeError("disk full")

            def all_states(self):
                raise RuntimeError("disk full")

        self.window.action_store = Broken(os.path.join(self.tmp, "broken2.db"))
        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=FULL_COVERAGE))
        self.assertEqual(self.window.action_page.pending_count(), 1)

    def test_action_state_error_is_reported_not_raised(self):
        class Broken(ActionStateStore):
            def set_state(self, *args, **kwargs):
                raise RuntimeError("read only")

        self.run_scan(_result(findings=[_finding("Exposed in Adobe")],
                              coverage=FULL_COVERAGE))
        self.window.action_store = Broken(os.path.join(self.tmp, "broken3.db"))
        key = self.window.action_page.board.items[0].action.action_key
        self.window.on_action_state_changed(key, COMPLETED)
        self.assertIn("Could not save", self.window.action_page.privacy_note.text())


class TestSinglePipeline(ExpandedPageTestCase):
    def test_one_score_for_dashboard_pages_and_report(self):
        import json

        result = _result(findings=[_finding("Exposed in Adobe"),
                                   _finding("Sensitive Metadata in a.png",
                                            severity="Medium",
                                            finding_type="Sensitive Metadata",
                                            rule_id="FILE-GPS-001",
                                            module="file_metadata",
                                            verification="direct-observation")],
                         coverage=FULL_COVERAGE)
        self.run_scan(result)
        risk = self.window.latest_risk

        written = self.window.assessment_page.export(
            "json", os.path.join(self.tmp, "r.json"))
        with open(written, encoding="utf-8") as handle:
            payload = json.load(handle)

        self.assertEqual(payload["assessment"]["score"], risk.score)
        self.assertEqual(payload["assessment"]["band"], risk.band)
        self.assertEqual(payload["assessment"]["methodology_version"],
                         risk.methodology_version)
        self.assertIn(f"{risk.score}/100", self.window.home_risk_label.text())
        self.assertEqual(len(payload["findings"]), 2)


if __name__ == "__main__":
    unittest.main()
