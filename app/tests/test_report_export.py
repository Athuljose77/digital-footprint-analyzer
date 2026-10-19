"""Report export tests.

What matters here: all three formats must show the same findings and the same
score as the assessment, an empty or partial scan must produce an honest
report rather than a blank one, no secret may reach a file, and a failing
write must be reported as an error rather than leaving a broken file behind.
"""

import csv
import io
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from PySide6.QtWidgets import QApplication

app = QApplication.instance()
if app is None:
    app = QApplication([])

from app.core.findings_processor import with_provenance
from app.core.remediation import build_plan
from app.core.reporting import (
    COLUMNS,
    FORMAT_CSV,
    FORMAT_JSON,
    FORMAT_PDF,
    ReportExportError,
    build_report_bundle,
    build_rows,
    export_report,
    normalize_path,
    render,
    render_csv,
    render_json,
)
from app.core.risk import build_risk_summary
from app.models.common import Finding, FootprintData, ScanResult

FULL_COVERAGE = [
    {"name": "System", "key": "system", "state": "completed", "note": "Completed"},
    {"name": "Browser", "key": "browser", "state": "completed", "note": "Completed"},
    {"name": "File", "key": "file_metadata", "state": "skipped",
     "note": "Skipped — no file was selected"},
]


def _finding(title, severity="High", finding_type="Email Breach",
             rule_id="EML-BREACH-001", module="email",
             verification="provider-verified",
             description="Records exposed: 3.", evidence=("emails: 3",)):
    finding = Finding(
        finding_id=f"id-{title}",
        finding_type=finding_type,
        title=title,
        description=description,
        evidence=list(evidence),
        severity=severity,
        status="Unremediated",
        rule_id=rule_id,
    )
    return with_provenance(finding, explicit_module=module,
                           explicit_verification=verification)


def _result(findings=(), footprint=(), status="COMPLETED",
            module_coverage=None, message="ok", scan_type="Full Scan"):
    result = ScanResult(
        scan_id="scan-1",
        analysis_mode="Full Footprint Analysis",
        scan_type=scan_type,
        scan_category="Unified Footprint",
        status=status,
        message=message,
        footprint_data=list(footprint),
        findings=list(findings),
        module_coverage=module_coverage,
    )
    result.started_at = "2026-10-19T10:00:00Z"
    result.finished_at = "2026-10-19T10:00:05Z"
    return result


def _bundle(result, target=None):
    risk = build_risk_summary(result)
    plan = build_plan(result)
    return build_report_bundle(result, risk_summary=risk, plan=plan, target=target)


def _footprint(category="System"):
    return FootprintData(category=category, subcategory="Operating System",
                         source="Test", data_type="String", value="Linux",
                         sensitivity="Low")


class ReportTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dfa-report-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def path(self, name):
        return os.path.join(self.tmp, name)


class TestBundleContent(ReportTestCase):
    def test_bundle_mirrors_the_assessment_score(self):
        result = _result(findings=[_finding("Exposed in Adobe")],
                         footprint=[_footprint()],
                         module_coverage=FULL_COVERAGE)
        risk = build_risk_summary(result)
        bundle = build_report_bundle(result, risk_summary=risk)
        self.assertEqual(bundle.assessment.score, risk.score)
        self.assertEqual(bundle.assessment.band, risk.band)
        self.assertEqual(bundle.assessment.methodology_version,
                         risk.methodology_version)
        self.assertEqual(bundle.assessment.coverage_key, risk.coverage_key)

    def test_bundle_reuses_the_supplied_assessment(self):
        """The report must not recompute a score of its own."""
        result = _result(findings=[_finding("Exposed in Adobe")],
                         footprint=[_footprint()], module_coverage=FULL_COVERAGE)
        risk = build_risk_summary(result)
        risk.score = None
        risk.band = "Indeterminate"
        bundle = build_report_bundle(result, risk_summary=risk)
        self.assertIsNone(bundle.assessment.score)
        self.assertEqual(bundle.assessment.band, "Indeterminate")

    def test_findings_excluded_from_scoring_still_appear(self):
        findings = [_finding(f"Breach {index}") for index in range(5)]
        result = _result(findings=findings, footprint=[_footprint()],
                         module_coverage=FULL_COVERAGE)
        bundle = _bundle(result)
        self.assertEqual(len(bundle.findings), 5)

    def test_coverage_rows_carry_state_and_note(self):
        result = _result(footprint=[_footprint()], module_coverage=FULL_COVERAGE)
        bundle = _bundle(result)
        states = {row.name: row.state for row in bundle.coverage}
        self.assertEqual(states["System"], "completed")
        self.assertEqual(states["File"], "skipped")

    def test_recommendations_match_the_plan(self):
        result = _result(findings=[_finding("Exposed in Adobe")],
                         footprint=[_footprint()], module_coverage=FULL_COVERAGE)
        plan = build_plan(result)
        bundle = build_report_bundle(result, risk_summary=None, plan=plan)
        self.assertEqual([a.action_key for a in bundle.actions],
                         [a.action_key for a in plan.actions])
        self.assertTrue(bundle.actions[0].steps)
        self.assertTrue(bundle.actions[0].docs)

    def test_target_is_masked_in_the_bundle(self):
        bundle = _bundle(_result(), target="someone@example.com")
        self.assertEqual(bundle.assessment.target_label, "s***@example.com")

    def test_empty_scan_has_a_stated_reason(self):
        result = _result(footprint=[_footprint()], module_coverage=FULL_COVERAGE)
        bundle = _bundle(result)
        self.assertTrue(bundle.is_empty)
        self.assertIn("not evidence", bundle.empty_reason)

    def test_empty_scan_without_coverage_says_so(self):
        result = _result(status="ERROR", module_coverage=[
            {"name": "System", "key": "system", "state": "failed", "note": "boom"},
        ])
        bundle = _bundle(result)
        self.assertTrue(bundle.is_empty)
        self.assertIn("nothing could be assessed", bundle.empty_reason)


class TestJsonReport(ReportTestCase):
    def test_json_has_the_schema_and_sections(self):
        import json

        bundle = _bundle(_result(findings=[_finding("Exposed in Adobe")],
                                 footprint=[_footprint()],
                                 module_coverage=FULL_COVERAGE))
        data = json.loads(render_json(bundle))
        self.assertEqual(data["schema_version"], "dfa-report-v1")
        for key in ("assessment", "coverage", "findings", "actions", "notes"):
            self.assertIn(key, data)
        self.assertEqual(data["assessment"]["score"], bundle.assessment.score)
        self.assertEqual(len(data["findings"]), 1)

    def test_json_export_writes_utf8(self):
        bundle = _bundle(_result(findings=[_finding("Exposé in Adobé")],
                                 footprint=[_footprint()],
                                 module_coverage=FULL_COVERAGE))
        path = export_report(bundle, self.path("report.json"), FORMAT_JSON)
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("Adobé", text)


class TestCsvReport(ReportTestCase):
    def _rows(self, bundle):
        return list(csv.DictReader(io.StringIO(render_csv(bundle))))

    def test_every_row_uses_the_same_columns(self):
        bundle = _bundle(_result(findings=[_finding("Exposed in Adobe")],
                                 footprint=[_footprint()],
                                 module_coverage=FULL_COVERAGE))
        rows = self._rows(bundle)
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(list(row.keys()), COLUMNS)

    def test_all_record_types_are_present(self):
        bundle = _bundle(_result(findings=[_finding("Exposed in Adobe")],
                                 footprint=[_footprint()],
                                 module_coverage=FULL_COVERAGE))
        types = {row["record_type"] for row in self._rows(bundle)}
        self.assertEqual(types, {"assessment", "finding", "coverage",
                                 "recommendation"})

    def test_assessment_row_carries_the_score(self):
        bundle = _bundle(_result(findings=[_finding("Exposed in Adobe")],
                                 footprint=[_footprint()],
                                 module_coverage=FULL_COVERAGE))
        assessment = [r for r in self._rows(bundle)
                      if r["record_type"] == "assessment"][0]
        self.assertEqual(assessment["score"], str(bundle.assessment.score))
        self.assertEqual(assessment["band"], bundle.assessment.band)
        self.assertEqual(assessment["methodology"],
                         bundle.assessment.methodology_version)

    def test_file_is_written_with_a_bom(self):
        bundle = _bundle(_result(footprint=[_footprint()],
                                 module_coverage=FULL_COVERAGE))
        path = export_report(bundle, self.path("report.csv"), FORMAT_CSV)
        with open(path, "rb") as handle:
            self.assertTrue(handle.read(3).startswith(b"\xef\xbb\xbf"))

    def test_formula_like_values_are_defused(self):
        bundle = _bundle(_result(
            findings=[_finding("=cmd|' /C calc'!A0")],
            footprint=[_footprint()], module_coverage=FULL_COVERAGE))
        rows = self._rows(bundle)
        titles = [row["title"] for row in rows]
        self.assertIn("'=cmd|' /C calc'!A0", titles)
        for row in rows:
            for value in row.values():
                self.assertFalse(str(value).startswith("="))

    def test_plain_values_are_untouched(self):
        bundle = _bundle(_result(findings=[_finding("Exposed in Adobe")],
                                 footprint=[_footprint()],
                                 module_coverage=FULL_COVERAGE))
        titles = [row["title"] for row in self._rows(bundle)]
        self.assertIn("Exposed in Adobe", titles)

    def test_evidence_is_joined_not_split_into_columns(self):
        bundle = _bundle(_result(
            findings=[_finding("Exposed in Adobe", evidence=("a: 1", "b: 2"))],
            footprint=[_footprint()], module_coverage=FULL_COVERAGE))
        finding_rows = [r for r in self._rows(bundle)
                        if r["record_type"] == "finding"]
        self.assertIn("a: 1 | b: 2", finding_rows[0]["evidence"])


class TestPdfReport(ReportTestCase):
    def _pdf_text(self, path):
        import re as _re

        from PySide6.QtPdf import QPdfDocument

        document = QPdfDocument()
        status = document.load(str(path))
        self.assertEqual(status, QPdfDocument.Error.None_,
                         "PDF could not be loaded")
        self.assertGreater(document.pageCount(), 0)
        raw = "".join(document.getAllText(index).text()
                      for index in range(document.pageCount()))
        # Qt wraps lines; collapse whitespace so assertions test content, not
        # line breaks.
        return _re.sub(r"\s+", " ", raw)

    def test_pdf_is_written_and_readable(self):
        bundle = _bundle(_result(findings=[_finding("Exposed in Adobe")],
                                 footprint=[_footprint()],
                                 module_coverage=FULL_COVERAGE))
        path = export_report(bundle, self.path("report.pdf"), FORMAT_PDF)
        with open(path, "rb") as handle:
            self.assertTrue(handle.read(5).startswith(b"%PDF-"))
        text = self._pdf_text(path)
        self.assertIn("Exposed in Adobe", text)
        self.assertIn("Module coverage", text)
        self.assertIn("Recommended actions", text)

    def test_pdf_states_a_missing_score_instead_of_a_number(self):
        result = _result(status="ERROR", module_coverage=[
            {"name": "System", "key": "system", "state": "failed", "note": "boom"},
        ])
        bundle = _bundle(result)
        path = export_report(bundle, self.path("failed.pdf"), FORMAT_PDF)
        text = self._pdf_text(path)
        self.assertIn("not available", text)
        self.assertIn("completed or partially completed", text)

    def test_pdf_of_an_empty_scan_says_none_recorded(self):
        bundle = _bundle(_result(footprint=[_footprint()],
                                 module_coverage=FULL_COVERAGE))
        path = export_report(bundle, self.path("empty.pdf"), FORMAT_PDF)
        self.assertIn("None recorded", self._pdf_text(path))

    def test_pdf_reports_coverage_gaps(self):
        result = _result(footprint=[_footprint()], message="partial", status="PARTIAL",
                         module_coverage=[
                             {"name": "System", "key": "system",
                              "state": "completed", "note": "Completed"},
                             {"name": "Browser", "key": "browser",
                              "state": "unavailable",
                              "note": "Unavailable on this platform — not scanned"},
                             {"name": "File", "key": "file_metadata",
                              "state": "skipped", "note": "Skipped"},
                         ])
        path = export_report(_bundle(result), self.path("partial.pdf"), FORMAT_PDF)
        text = self._pdf_text(path)
        self.assertIn("not covered", text)
        self.assertIn("Browser", text)
        self.assertIn("File", text)


class TestNoSecretsInReports(ReportTestCase):
    SECRETS = (
        "AKIAIOSFODNN7EXAMPLE1234",
        "/home/someone/private/vault",
        "someone@example.com",
    )

    def _risky_result(self):
        finding = _finding(
            "Sensitive Metadata in /home/someone/private/vault/report.pdf",
            finding_type="Sensitive Metadata", rule_id="FILE-GPS-001",
            module="file_metadata", severity="Medium",
            verification="direct-observation",
            description=("api_key=AKIAIOSFODNN7EXAMPLE1234 shared by "
                         "someone@example.com"),
            evidence=("image.png /home/someone/private/vault/report.pdf",
                      "api_key=AKIAIOSFODNN7EXAMPLE1234",
                      "someone@example.com"),
        )
        return _result(findings=[finding], footprint=[_footprint()],
                       module_coverage=FULL_COVERAGE)

    def test_no_secret_reaches_any_exported_file(self):
        bundle = _bundle(self._risky_result(), target="someone@example.com")

        paths = []
        for fmt in (FORMAT_JSON, FORMAT_CSV, FORMAT_PDF):
            paths.append(export_report(bundle, self.path(f"r.{fmt}"), fmt))

        for path in paths:
            with open(path, "rb") as handle:
                raw = handle.read()
            for secret in self.SECRETS:
                self.assertNotIn(secret.encode(), raw,
                                 f"{secret!r} leaked into {os.path.basename(path)}")

    def test_file_name_is_still_useful_after_sanitizing(self):
        bundle = _bundle(self._risky_result())
        blob = render_json(bundle)
        self.assertIn("report.pdf", blob)


class TestExportDestination(ReportTestCase):
    def test_missing_extension_is_added(self):
        bundle = _bundle(_result(footprint=[_footprint()]))
        path = export_report(bundle, self.path("summary"), FORMAT_JSON)
        self.assertTrue(str(path).endswith(".json"))
        self.assertTrue(os.path.exists(path))

    def test_wrong_extension_is_corrected(self):
        path = normalize_path(self.path("summary.txt"), FORMAT_CSV)
        self.assertTrue(str(path).endswith(".csv"))

    def test_existing_extension_is_kept(self):
        path = normalize_path(self.path("summary.pdf"), FORMAT_PDF)
        self.assertEqual(str(path), self.path("summary.pdf"))

    def test_directory_is_rejected(self):
        with self.assertRaises(ReportExportError) as ctx:
            export_report(_bundle(_result()), self.tmp, FORMAT_JSON)
        self.assertIn("folder", str(ctx.exception))

    def test_missing_folder_is_rejected(self):
        with self.assertRaises(ReportExportError) as ctx:
            export_report(_bundle(_result()),
                          os.path.join(self.tmp, "nope", "r.json"), FORMAT_JSON)
        self.assertIn("does not exist", str(ctx.exception))

    def test_empty_path_is_rejected(self):
        with self.assertRaises(ReportExportError):
            export_report(_bundle(_result()), "", FORMAT_JSON)

    def test_unknown_format_is_rejected(self):
        with self.assertRaises(ReportExportError):
            export_report(_bundle(_result()), self.path("r.xml"), "xml")

    def test_write_failure_is_reported_not_swallowed(self):
        bundle = _bundle(_result(footprint=[_footprint()]))
        with patch("builtins.open", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(ReportExportError) as ctx:
                export_report(bundle, self.path("full.json"), FORMAT_JSON)
        self.assertIn("Could not write", str(ctx.exception))

    def test_pdf_render_failure_is_reported(self):
        bundle = _bundle(_result(footprint=[_footprint()]))
        with patch("app.core.reporting.exporter.render_pdf",
                   side_effect=RuntimeError("no print subsystem")):
            with self.assertRaises(ReportExportError):
                export_report(bundle, self.path("broken.pdf"), FORMAT_PDF)

    def test_overwriting_an_existing_report_works(self):
        bundle = _bundle(_result(findings=[_finding("Exposed in Adobe")],
                                 footprint=[_footprint()],
                                 module_coverage=FULL_COVERAGE))
        first = export_report(bundle, self.path("r.json"), FORMAT_JSON)
        second = export_report(bundle, self.path("r.json"), FORMAT_JSON)
        self.assertEqual(first, second)


class TestRenderToBytes(ReportTestCase):
    def test_json_and_csv_render_to_bytes(self):
        bundle = _bundle(_result(findings=[_finding("Exposed in Adobe")],
                                 footprint=[_footprint()],
                                 module_coverage=FULL_COVERAGE))
        self.assertTrue(render(bundle, FORMAT_JSON).startswith(b"{"))
        self.assertTrue(render(bundle, FORMAT_CSV).startswith(b"\xef\xbb\xbf"))

    def test_pdf_renders_to_bytes(self):
        bundle = _bundle(_result(footprint=[_footprint()],
                                 module_coverage=FULL_COVERAGE))
        self.assertTrue(render(bundle, FORMAT_PDF).startswith(b"%PDF-"))

    def test_rows_helper_matches_the_csv(self):
        bundle = _bundle(_result(findings=[_finding("Exposed in Adobe")],
                                 footprint=[_footprint()],
                                 module_coverage=FULL_COVERAGE))
        rows = build_rows(bundle)
        parsed = list(csv.DictReader(io.StringIO(render_csv(bundle))))
        self.assertEqual([r["title"] for r in rows], [r["title"] for r in parsed])

    def test_every_row_has_a_known_record_type(self):
        bundle = _bundle(_result(findings=[_finding("Exposed in Adobe")],
                                 footprint=[_footprint()],
                                 module_coverage=FULL_COVERAGE))
        allowed = {"assessment", "finding", "coverage", "recommendation"}
        for row in build_rows(bundle):
            self.assertIn(row["record_type"], allowed)


if __name__ == "__main__":
    unittest.main()
