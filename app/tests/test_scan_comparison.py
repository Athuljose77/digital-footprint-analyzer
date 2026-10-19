"""Scan comparison tests.

The rules under test are the honest ones: a finding may only be called
resolved when the module that produced it actually ran again, and a score
change may only be shown when the two scans are genuinely comparable.
"""

import os
import sys
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from app.core.history.compare import (
    MODIFIED,
    NEW,
    NOT_RECHECKED,
    RESOLVED,
    UNCHANGED,
    change_label,
    compare_scans,
)
from app.core.history.models import ScanRecord, StoredFinding
from app.core.history.sanitize import content_signature
from app.core.risk.models import METHODOLOGY_VERSION

FULL_COVERAGE = [
    {"name": "System", "key": "system", "state": "completed"},
    {"name": "Browser", "key": "browser", "state": "completed"},
    {"name": "File", "key": "file_metadata", "state": "completed"},
]

FULL_COVERAGE_KEY = "browser:full|file_metadata:full|system:full"


def _stored(key, title="Issue", severity="High", status="Unremediated",
            module="system", verification="direct-observation",
            evidence=("evidence",), signature=None):
    preview = list(evidence)
    return StoredFinding(
        identity_key=key,
        title=title,
        severity=severity,
        status=status,
        source_module=module,
        verification=verification,
        evidence_preview=preview,
        signature=(signature if signature is not None else content_signature(
            severity, status, verification, preview)),
    )


def _record(rid, findings=(), modules=None, score=None,
            methodology=METHODOLOGY_VERSION, coverage_key=FULL_COVERAGE_KEY,
            finished="2026-01-01T00:00:00Z"):
    return ScanRecord(
        id=rid,
        scan_id=f"scan-{rid}",
        scan_type="Full Scan",
        status="COMPLETED",
        finished_at=finished,
        score=score,
        band="Low" if score is not None else "",
        methodology_version=methodology,
        coverage_key=coverage_key,
        modules=list(modules if modules is not None else FULL_COVERAGE),
        findings=list(findings),
    )


class TestFindingChanges(unittest.TestCase):
    def test_identical_scans_report_everything_unchanged(self):
        finding = _stored("k1")
        comparison = compare_scans(_record(1, [finding]), _record(2, [finding]))
        self.assertEqual(comparison.counts[UNCHANGED], 1)
        self.assertEqual(comparison.counts[NEW], 0)
        self.assertEqual(comparison.changes[0].change, UNCHANGED)

    def test_finding_only_in_newer_scan_is_new(self):
        comparison = compare_scans(_record(1), _record(2, [_stored("k1")]))
        self.assertEqual(comparison.counts[NEW], 1)
        self.assertEqual(comparison.changes[0].severity_after, "High")

    def test_changed_content_is_modified(self):
        older = _stored("k1", severity="Medium", status="Unremediated")
        newer = _stored("k1", severity="High", status="Unremediated")
        comparison = compare_scans(_record(1, [older]), _record(2, [newer]))
        change = comparison.changes[0]
        self.assertEqual(change.change, MODIFIED)
        self.assertEqual(change.severity_before, "Medium")
        self.assertEqual(change.severity_after, "High")
        self.assertTrue(change.is_regression)

    def test_severity_drop_is_not_a_regression(self):
        older = _stored("k1", severity="High")
        newer = _stored("k1", severity="Low")
        comparison = compare_scans(_record(1, [older]), _record(2, [newer]))
        self.assertEqual(comparison.changes[0].change, MODIFIED)
        self.assertFalse(comparison.changes[0].is_regression)
        self.assertIn("decreased", comparison.changes[0].note)

    def test_absent_finding_is_resolved_when_its_module_completed(self):
        older = _stored("k1", module="system")
        comparison = compare_scans(_record(1, [older]), _record(2))
        change = comparison.changes[0]
        self.assertEqual(change.change, RESOLVED)
        self.assertIn("not detected again", change.note.lower())

    def test_absent_finding_is_not_rechecked_when_its_module_failed(self):
        older = _stored("k1", module="browser")
        modules = [
            {"name": "System", "key": "system", "state": "completed"},
            {"name": "Browser", "key": "browser", "state": "failed"},
            {"name": "File", "key": "file_metadata", "state": "skipped"},
        ]
        comparison = compare_scans(_record(1, [older]), _record(2, modules=modules))
        change = comparison.changes[0]
        self.assertEqual(change.change, NOT_RECHECKED)
        self.assertIn("not rechecked", change.note)
        self.assertEqual(comparison.counts[RESOLVED], 0)

    def test_absent_finding_with_unknown_module_is_not_rechecked(self):
        older = _stored("k1", module=None)
        comparison = compare_scans(_record(1, [older]), _record(2))
        self.assertEqual(comparison.changes[0].change, NOT_RECHECKED)

    def test_no_coverage_information_never_claims_resolution(self):
        older = _stored("k1", module="system")
        newer = _record(2, modules=[])
        comparison = compare_scans(_record(1, [older]), newer)
        self.assertEqual(comparison.changes[0].change, NOT_RECHECKED)
        self.assertEqual(comparison.resolved_confidence, "low")

    def test_change_order_puts_new_and_changed_first(self):
        older = [_stored("k-resolved", module="system"), _stored("k-changed")]
        newer = [_stored("k-new"), _stored("k-changed", status="Remediated")]
        comparison = compare_scans(_record(1, older), _record(2, newer))
        self.assertEqual([c.change for c in comparison.changes],
                         [NEW, MODIFIED, RESOLVED])


class TestScoreComparison(unittest.TestCase):
    def test_delta_shown_when_methodology_and_coverage_match(self):
        comparison = compare_scans(_record(1, score=20), _record(2, score=35))
        self.assertTrue(comparison.score_comparable)
        self.assertEqual(comparison.score_delta, 15)
        self.assertIn("up 15", comparison.headline.lower())

    def test_delta_hidden_when_coverage_differs(self):
        narrower = _record(
            2, score=10,
            modules=[{"name": "System", "key": "system", "state": "completed"}],
            coverage_key="system:full")
        comparison = compare_scans(_record(1, score=40), narrower)
        self.assertFalse(comparison.score_comparable)
        self.assertIsNone(comparison.score_delta)
        self.assertIn("different modules", comparison.score_note)

    def test_delta_hidden_across_methodology_versions(self):
        older = _record(1, score=40, methodology="exposure-v1")
        newer = _record(2, score=10, methodology="exposure-v2")
        comparison = compare_scans(older, newer)
        self.assertFalse(comparison.score_comparable)
        self.assertIsNone(comparison.score_delta)
        self.assertIn("methodology", comparison.score_note.lower())

    def test_delta_hidden_when_a_scan_has_no_score(self):
        comparison = compare_scans(_record(1, score=None), _record(2, score=12))
        self.assertFalse(comparison.score_comparable)
        self.assertIsNone(comparison.score_delta)
        self.assertIn("did not produce a score", comparison.score_note)

    def test_zero_delta_is_reported_as_unchanged(self):
        comparison = compare_scans(_record(1, score=12), _record(2, score=12))
        self.assertEqual(comparison.score_delta, 0)
        self.assertTrue(comparison.score_comparable)
        self.assertIn("unchanged", comparison.headline)


class TestCoverageChanges(unittest.TestCase):
    def test_coverage_changes_are_listed(self):
        modules = [
            {"name": "System", "key": "system", "state": "completed"},
            {"name": "Browser", "key": "browser", "state": "failed"},
            {"name": "File", "key": "file_metadata", "state": "completed"},
        ]
        comparison = compare_scans(_record(1), _record(2, modules=modules))
        changed = {c.key: (c.before, c.after) for c in comparison.coverage_changes}
        self.assertEqual(changed["browser"], ("completed", "failed"))

    def test_no_coverage_changes_when_coverage_is_identical(self):
        comparison = compare_scans(_record(1), _record(2))
        self.assertEqual(comparison.coverage_changes, [])

    def test_resolved_note_warns_about_gaps(self):
        modules = [
            {"name": "System", "key": "system", "state": "completed"},
            {"name": "Browser", "key": "browser", "state": "unavailable"},
            {"name": "File", "key": "file_metadata", "state": "skipped"},
        ]
        comparison = compare_scans(_record(1), _record(2, modules=modules))
        self.assertEqual(comparison.resolved_confidence, "low")
        self.assertIn("Browser", comparison.resolved_note)


class TestLabels(unittest.TestCase):
    def test_every_change_kind_has_a_label(self):
        for kind in (NEW, UNCHANGED, RESOLVED, MODIFIED, NOT_RECHECKED):
            self.assertTrue(change_label(kind))

    def test_headline_counts_new_and_resolved(self):
        older = [_stored("k-old", module="system")]
        newer = [_stored("k-new")]
        comparison = compare_scans(_record(1, older), _record(2, newer))
        self.assertIn("1 new", comparison.headline)
        self.assertIn("1 resolved", comparison.headline)

    def test_empty_comparison_has_a_plain_headline(self):
        comparison = compare_scans(_record(1), _record(2))
        self.assertIn("No differences", comparison.headline)


if __name__ == "__main__":
    unittest.main()
