"""Exposure scoring tests.

The model must be deterministic, must never invent a number it cannot
justify, and must never count one issue twice.
"""

import os
import sys
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from app.core.risk import build_risk_summary
from app.core.risk.models import BAND_INDETERMINATE, METHODOLOGY_VERSION
from app.core.risk.scoring import MAX_ISSUES_PER_RULE, SEVERITY_WEIGHTS
from app.models.common import Finding, FootprintData, ScanResult


def _finding(title, severity="High", finding_type="Email Breach",
             rule_id="EML-BREACH-001", module="email",
             verification="provider-verified", confidence="high"):
    return Finding(
        finding_id=f"id-{title}",
        finding_type=finding_type,
        title=title,
        description=f"Description for {title}",
        evidence=[title],
        severity=severity,
        status="Unremediated",
        rule_id=rule_id,
        source_module=module,
        verification=verification,
        confidence=confidence,
    )


def _footprint(category, subcategory="Operating System", value="x"):
    return FootprintData(
        category=category, subcategory=subcategory, source="Test",
        data_type="String", value=value, sensitivity="Low",
    )


def _result(status="COMPLETED", findings=(), footprint=(), message="ok",
            module_coverage=None, scan_type="Full Scan"):
    return ScanResult(
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


def _full_coverage(states=None):
    states = states or {"System": "completed", "Browser": "completed",
                        "File": "skipped"}
    return [
        {"name": name, "key": name.lower() if name != "File" else "file_metadata",
         "state": state, "note": ""}
        for name, state in states.items()
    ]


class TestScoringGates(unittest.TestCase):
    def test_failed_scan_produces_no_number(self):
        result = _result(
            status="ERROR",
            message="everything failed",
            module_coverage=_full_coverage(
                {"System": "failed", "Browser": "failed", "File": "skipped"}),
        )
        summary = build_risk_summary(result)
        self.assertIsNone(summary.score)
        self.assertFalse(summary.score_available)
        self.assertEqual(summary.band, BAND_INDETERMINATE)
        self.assertIn("status ERROR", summary.unavailable_reason)

    def test_scan_without_any_completed_module_produces_no_number(self):
        result = _result(
            status="PARTIAL",
            module_coverage=_full_coverage(
                {"System": "unavailable", "Browser": "unavailable",
                 "File": "skipped"}),
        )
        summary = build_risk_summary(result)
        self.assertIsNone(summary.score)
        self.assertIn("no module completed", summary.unavailable_reason.lower())

    def test_empty_completed_scan_scores_zero_with_caveat(self):
        result = _result(status="COMPLETED", footprint=[_footprint("System")])
        summary = build_risk_summary(result)
        self.assertEqual(summary.score, 0)
        self.assertEqual(summary.band, "None detected")
        self.assertTrue(any("not evidence" in c for c in summary.caveats))

    def test_browser_unavailable_is_reported_as_a_gap(self):
        result = _result(
            status="PARTIAL",
            footprint=[_footprint("System")],
            module_coverage=_full_coverage(
                {"System": "completed", "Browser": "unavailable",
                 "File": "skipped"}),
        )
        summary = build_risk_summary(result)
        states = {m.name: m.state for m in summary.modules}
        self.assertEqual(states["Browser"], "unavailable")
        self.assertEqual(summary.counts["unsupported_checks"], 1)
        self.assertTrue(any("Browser" in c for c in summary.caveats))


class TestScoringDeterminism(unittest.TestCase):
    def test_identical_input_gives_identical_summary(self):
        findings = [_finding("Confirmed Breach Exposure: Adobe"),
                    _finding("Confirmed Breach Exposure: LinkedIn")]
        first = build_risk_summary(_result(findings=findings,
                                           footprint=[_footprint("System")]))
        second = build_risk_summary(_result(findings=findings,
                                            footprint=[_footprint("System")]))
        self.assertEqual(first.model_dump(), second.model_dump())

    def test_points_equal_sum_of_counted_contributions(self):
        findings = [_finding("A"), _finding("B"), _finding("C")]
        summary = build_risk_summary(
            _result(findings=findings, footprint=[_footprint("System")]))
        self.assertEqual(
            summary.points,
            round(sum(c.contribution for c in summary.components if c.counted), 2),
        )

    def test_methodology_version_is_reported(self):
        summary = build_risk_summary(_result(footprint=[_footprint("System")]))
        self.assertEqual(summary.methodology_version, METHODOLOGY_VERSION)


class TestDeduplication(unittest.TestCase):
    def test_same_issue_from_two_modules_counts_once(self):
        findings = [
            _finding("Embedded GPS Location Data Detected", severity="Medium",
                     finding_type="Sensitive Metadata", rule_id="FILE-GPS-001",
                     module="file_metadata", verification="direct-observation"),
            _finding("Embedded GPS Location Data Detected", severity="Medium",
                     finding_type="Sensitive Metadata", rule_id="FILE-GPS-001",
                     module="browser", verification="direct-observation"),
        ]
        summary = build_risk_summary(
            _result(findings=findings, footprint=[_footprint("System")]))
        self.assertEqual(summary.distinct_issues, 1)
        self.assertEqual(summary.points, SEVERITY_WEIGHTS["Medium"])
        self.assertEqual(sorted(summary.components[0].sources),
                         ["browser", "file_metadata"])

    def test_highest_severity_wins_within_an_issue(self):
        findings = [
            _finding("Same issue", severity="Low"),
            _finding("Same issue", severity="High"),
        ]
        summary = build_risk_summary(
            _result(findings=findings, footprint=[_footprint("System")]))
        self.assertEqual(summary.severity_breakdown["High"], 1)
        self.assertEqual(summary.severity_breakdown["Low"], 0)

    def test_one_rule_contributes_at_most_the_cap(self):
        findings = [_finding(f"Breach {i}") for i in range(MAX_ISSUES_PER_RULE + 3)]
        summary = build_risk_summary(
            _result(findings=findings, footprint=[_footprint("System")]))
        self.assertEqual(sum(1 for c in summary.components if c.counted),
                         MAX_ISSUES_PER_RULE)
        self.assertEqual(sum(1 for c in summary.components if c.capped), 3)
        self.assertEqual(summary.points,
                         round(MAX_ISSUES_PER_RULE * SEVERITY_WEIGHTS["High"], 2))
        self.assertTrue(any(c.capped for c in summary.components))


class TestConfidenceWeighting(unittest.TestCase):
    def test_unverified_findings_weigh_less_than_verified_ones(self):
        verified = build_risk_summary(_result(
            findings=[_finding("Breach X", verification="provider-verified",
                               confidence="high")],
            footprint=[_footprint("System")]))
        unconfirmed = build_risk_summary(_result(
            findings=[_finding("Breach X", verification="unconfirmed",
                               confidence="low")],
            footprint=[_footprint("System")]))
        self.assertLess(unconfirmed.points, verified.points)
        self.assertLess(unconfirmed.score, verified.score)

    def test_unverified_findings_are_flagged_as_leads(self):
        summary = build_risk_summary(_result(
            findings=[_finding("Breach X", verification="provider-reported",
                               confidence="low")],
            footprint=[_footprint("System")]))
        self.assertEqual(summary.counts["potential"], 1)
        self.assertEqual(summary.counts["confirmed"], 0)
        self.assertTrue(any("unverified" in c for c in summary.caveats))


class TestCoverageHandling(unittest.TestCase):
    def test_coverage_findings_never_raise_the_score(self):
        coverage_finding = _finding(
            "Module Limitation: Browser", severity="Info",
            finding_type="Scan Limitation", rule_id=None, module=None,
            verification="not-applicable", confidence=None)
        summary = build_risk_summary(_result(
            status="PARTIAL",
            findings=[coverage_finding],
            footprint=[_footprint("System")],
            module_coverage=_full_coverage(
                {"System": "completed", "Browser": "failed", "File": "skipped"}),
        ))
        self.assertEqual(summary.points, 0.0)
        self.assertEqual(summary.counts["coverage_findings"], 1)
        self.assertEqual(summary.distinct_issues, 0)

    def test_coverage_key_changes_with_coverage(self):
        narrow = build_risk_summary(_result(
            footprint=[_footprint("System")],
            module_coverage=_full_coverage(
                {"System": "completed", "Browser": "failed", "File": "skipped"})))
        wide = build_risk_summary(_result(
            footprint=[_footprint("System"), _footprint("Browser")],
            module_coverage=_full_coverage()))
        self.assertNotEqual(narrow.coverage_key, wide.coverage_key)

    def test_recorded_coverage_is_authoritative(self):
        result = _result(
            footprint=[],
            module_coverage=_full_coverage(
                {"System": "completed", "Browser": "completed", "File": "skipped"}),
        )
        summary = build_risk_summary(result)
        self.assertEqual([m.state for m in summary.modules],
                         ["completed", "completed", "skipped"])
        self.assertTrue(summary.score_available)


class TestExplanation(unittest.TestCase):
    def test_top_findings_are_ordered_and_capped(self):
        findings = [_finding(f"Breach {i}", severity=sev)
                    for i, sev in enumerate(
                        ["Info", "Low", "Medium", "High", "Critical", "High"])]
        summary = build_risk_summary(
            _result(findings=findings, footprint=[_footprint("System")]))
        self.assertLessEqual(len(summary.top_findings), 5)
        contributions = [c.contribution for c in summary.top_findings]
        self.assertEqual(contributions, sorted(contributions, reverse=True))

    def test_components_explain_why_the_finding_matters(self):
        summary = build_risk_summary(_result(
            findings=[_finding("Confirmed Breach Exposure: Adobe")],
            footprint=[_footprint("System")]))
        component = summary.components[0]
        self.assertTrue(component.why_it_matters)
        self.assertEqual(component.verification, "provider-verified")

    def test_factors_state_the_method(self):
        summary = build_risk_summary(
            _result(footprint=[_footprint("System")]))
        names = {f.name for f in summary.factors}
        self.assertIn("Coverage", names)
        self.assertIn("Methodology", names)

    def test_severity_breakdown_counts_distinct_issues(self):
        summary = build_risk_summary(_result(
            findings=[_finding("Same thing", severity="High"),
                      _finding("Same thing", severity="High"),
                      _finding("Other", severity="Low")],
            footprint=[_footprint("System")]))
        self.assertEqual(summary.severity_breakdown["High"], 1)
        self.assertEqual(summary.severity_breakdown["Low"], 1)


class TestBandMapping(unittest.TestCase):
    def test_bands_increase_with_points(self):
        bands = []
        for count in range(6):
            summary = build_risk_summary(_result(
                findings=[_finding(f"Critical issue {i}", severity="Critical",
                                   verification="direct-observation",
                                   confidence="high")
                          for i in range(count)],
                footprint=[_footprint("System")]))
            bands.append((summary.score, summary.band))
        labels = [b for _, b in bands]
        order = ["None detected", "Low", "Moderate", "Elevated", "High"]
        indices = [order.index(l) for l in labels]
        self.assertEqual(indices, sorted(indices))
        self.assertEqual(labels[0], "None detected")


if __name__ == "__main__":
    unittest.main()
