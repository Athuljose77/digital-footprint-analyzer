import unittest

from app.core.findings_processor import FindingsProcessor as CanonicalFindingsProcessor
from app.core.findings.processor import FindingsProcessor as ModularFindingsProcessor
from app.core.findings.adapters import (
    adapt_email_result,
    adapt_file_metadata_result,
)
from app.models.common import FootprintData, ScanResult, Finding


class TestFindingsPhase3Comparison(unittest.TestCase):
    """Controlled comparison tests, isolated to test-only helpers."""

    def _content_key(self, finding: Finding):
        """
        Compare meaningful finding content while ignoring non-deterministic
        UUIDs.
        """
        evidence = finding.evidence
        if isinstance(evidence, list):
            evidence_view = tuple(evidence)
        elif isinstance(evidence, dict):
            evidence_view = tuple(sorted(
                (str(key), str(value)) for key, value in evidence.items()
            ))
        else:
            evidence_view = str(evidence) if evidence is not None else "None"

        return (
            finding.finding_type,
            finding.title,
            finding.description,
            finding.severity,
            finding.status,
            finding.category,
            finding.rule_id,
            finding.limitations,
            evidence_view,
        )

    def _canonical_email_findings(self, breaches):
        return CanonicalFindingsProcessor.extract_module_findings(
            "email",
            {"status": "SUCCESS", "breaches": breaches},
        )

    def _modular_email_findings(self, breaches):
        normalized = adapt_email_result(
            {"status": "SUCCESS", "breaches": breaches}
        )
        return ModularFindingsProcessor().process(normalized)

    def _canonical_file_findings(self, sensitive_items):
        return CanonicalFindingsProcessor.extract_module_findings(
            "file & metadata",
            {
                "status": "SUCCESS",
                "results": {
                    "is_supported": True,
                    "potentially_sensitive": sensitive_items,
                },
            },
        )

    def _modular_file_findings(self, sensitive_items):
        normalized = adapt_file_metadata_result(
            {
                "status": "SUCCESS",
                "results": {
                    "is_supported": True,
                    "potentially_sensitive": sensitive_items,
                },
            }
        )
        return ModularFindingsProcessor().process(normalized)

    def test_email_verified_and_password_risk_is_expected_difference(self):
        breaches = [
            {
                "name": "VerifiedCorp",
                "records_exposed": 10,
                "breach_date": "2024-01-01",
                "industry": "Tech",
                "password_risk": True,
                "verified": True,
                "exposed_data": ["Email", "Password"],
            }
        ]

        canonical = self._canonical_email_findings(breaches)
        modular = self._modular_email_findings(breaches)

        self.assertEqual(len(canonical), 1)
        self.assertEqual(len(modular), 1)

        canonical_first = canonical[0]
        modular_first = modular[0]

        # Both treat the email as exposed by a breach.
        self.assertEqual(canonical_first.severity, "High")
        self.assertEqual(modular_first.severity, "High")
        self.assertEqual(canonical_first.status, "Unremediated")
        self.assertEqual(modular_first.status, "Unremediated")

        # Intentional title and enrichment differences.
        self.assertEqual(canonical_first.title, "Exposed in VerifiedCorp")
        self.assertEqual(modular_first.title, "Confirmed Breach Exposure: VerifiedCorp")
        self.assertEqual(modular_first.category, "Concern")
        self.assertEqual(modular_first.rule_id, "EML-BREACH-001")
        self.assertTrue(modular_first.limitations)

        # Canonical has no rule metadata because it is not rule-based.
        self.assertIsNone(canonical_first.rule_id)
        self.assertEqual(canonical_first.category, "Observation")
        self.assertIsNone(canonical_first.limitations)

    def test_email_unverified_breach_severity_difference_is_intentional(self):
        breaches = [
            {
                "name": "UnverifiedCorp",
                "records_exposed": 10,
                "breach_date": "2024-01-01",
                "industry": "Tech",
                "password_risk": True,
                "verified": False,
                "exposed_data": ["Email", "Password"],
            }
        ]

        canonical = self._canonical_email_findings(breaches)
        modular = self._modular_email_findings(breaches)

        self.assertEqual(len(canonical), 1)
        self.assertEqual(len(modular), 1)
        self.assertEqual(canonical[0].severity, "High")
        self.assertEqual(modular[0].severity, "Info")
        self.assertEqual(canonical[0].status, "Unremediated")
        self.assertEqual(modular[0].status, "Informational")
        self.assertEqual(modular[0].title, "Unconfirmed Breach Record: UnverifiedCorp")

    def test_email_password_risk_false_is_intentional_difference(self):
        breaches = [
            {
                "name": "CleanVerifiedCorp",
                "records_exposed": 10,
                "breach_date": "2024-01-01",
                "industry": "Tech",
                "password_risk": False,
                "verified": True,
                "exposed_data": ["Email"],
            }
        ]

        canonical = self._canonical_email_findings(breaches)
        modular = self._modular_email_findings(breaches)

        self.assertEqual(len(canonical), 1)
        self.assertEqual(len(modular), 1)
        self.assertEqual(canonical[0].severity, "Medium")
        self.assertEqual(modular[0].severity, "High")
        self.assertEqual(canonical[0].title, "Exposed in CleanVerifiedCorp")
        self.assertEqual(modular[0].title, "Confirmed Breach Exposure: CleanVerifiedCorp")

    def test_email_empty_results_agree_on_count(self):
        breaches = []

        canonical = self._canonical_email_findings(breaches)
        modular = self._modular_email_findings(breaches)

        self.assertEqual(canonical, [])
        self.assertEqual(modular, [])

    def test_email_failed_inputs_have_empty_findings(self):
        canonical = CanonicalFindingsProcessor.extract_module_findings(
            "email", {"status": "ERROR", "message": "Breach database unavailable"}
        )
        normalized = adapt_email_result(
            {"status": "ERROR", "message": "Breach database unavailable"}
        )
        modular = ModularFindingsProcessor().process(normalized)

        self.assertEqual(canonical, [])
        self.assertEqual(modular, [])

    def test_email_duplicate_breaches_are_handled_differently(self):
        breaches = [
            {
                "name": "DuplicateCorp",
                "records_exposed": 10,
                "verified": True,
                "password_risk": False,
                "exposed_data": ["Email"],
            },
            {
                "name": "DuplicateCorp",
                "records_exposed": 10,
                "verified": True,
                "password_risk": False,
                "exposed_data": ["Password"],
            },
        ]

        canonical = self._canonical_email_findings(breaches)
        modular = self._modular_email_findings(breaches)

        # Canonical dedups by finding type + title and merges evidence.
        self.assertEqual(len(canonical), 1)
        self.assertEqual(
            sorted(canonical[0].evidence), ["Email", "Password"]
        )

        # Modular uses (rule, module, evidence_key), so the second item is skipped
        # instead of merged. This is an uncovered reconciliation difference.
        self.assertEqual(len(modular), 1)

    def test_complementary_evidence_is_retained_only_by_canonical_now(self):
        breaches = [
            {
                "name": "ComplementCorp",
                "records_exposed": 10,
                "verified": True,
                "password_risk": False,
                "exposed_data": ["Email"],
            },
            {
                "name": "ComplementCorp",
                "records_exposed": 10,
                "verified": True,
                "password_risk": False,
                "exposed_data": ["Password"],
            },
        ]

        canonical = self._canonical_email_findings(breaches)
        canonical_evidence = sorted(canonical[0].evidence)
        self.assertEqual(canonical_evidence, ["Email", "Password"])

        modular = self._modular_email_findings(breaches)
        # Reconciliation policy now merges complementary evidence instead of
        # discarding it.
        self.assertEqual(modular[0].evidence, ["Email", "Password"])

    def test_file_metadata_comparison_reports_severity_difference(self):
        sensitive_items = [
            {
                "category": "Location & GPS",
                "field": "GPS Coordinates",
                "value": "37.00, -122.00",
                "description": "Embedded geographic location coordinates",
            }
        ]

        canonical = self._canonical_file_findings(sensitive_items)
        modular = self._modular_file_findings(sensitive_items)

        self.assertEqual(len(canonical), 1)
        self.assertEqual(len(modular), 1)
        self.assertEqual(canonical[0].finding_type, "Sensitive Metadata")
        self.assertEqual(canonical[0].severity, "High")
        self.assertEqual(modular[0].finding_type, "Embedded Geolocation")
        self.assertEqual(modular[0].severity, "Medium")
        self.assertEqual(modular[0].status, "Unremediated")
        self.assertEqual(modular[0].category, "Concern")
        self.assertEqual(modular[0].rule_id, "FILE-GPS-001")
        self.assertTrue(modular[0].limitations)

    def test_file_metadata_empty_results_agree_on_count(self):
        sensitive_items = []

        canonical = self._canonical_file_findings(sensitive_items)
        modular = self._modular_file_findings(sensitive_items)

        self.assertEqual(canonical, [])
        self.assertEqual(modular, [])

    def test_file_metadata_failed_inputs_have_empty_findings(self):
        canonical = CanonicalFindingsProcessor.extract_module_findings(
            "file & metadata",
            {"status": "ERROR", "message": "Metadata analysis failed"},
        )
        normalized = adapt_file_metadata_result(
            {"status": "ERROR", "message": "Metadata analysis failed"}
        )
        modular = ModularFindingsProcessor().process(normalized)

        self.assertEqual(canonical, [])
        self.assertEqual(modular, [])

    def test_missing_optional_fields_are_safe_everywhere(self):
        finding = Finding(
            finding_id="missing-fields",
            finding_type="Observation",
            title="No optional fields",
            description="Test",
            severity="Info",
            status="Active",
            # category, rule_id, and limitations omitted intentionally
        )
        normalized = CanonicalFindingsProcessor.normalize_finding(finding)

        self.assertEqual(normalized.category, "Observation")
        self.assertIsNone(normalized.rule_id)
        self.assertIsNone(normalized.limitations)


    def test_deterministic_output_content_for_canonical_and_modular(self):
        breaches = [
            {
                "name": "DeterminismCorp",
                "records_exposed": 10,
                "verified": True,
                "password_risk": False,
                "exposed_data": ["Email"],
            }
        ]

        canonical_first = self._canonical_email_findings(breaches)
        canonical_second = self._canonical_email_findings(breaches)
        modular_first = self._modular_email_findings(breaches)
        modular_second = self._modular_email_findings(breaches)

        self.assertEqual(
            [self._content_key(f) for f in canonical_first],
            [self._content_key(f) for f in canonical_second],
        )
        self.assertEqual(
            [self._content_key(f) for f in modular_first],
            [self._content_key(f) for f in modular_second],
        )

    def test_partial_inputs_keep_modular_result_empty_without_evidence(self):
        normalized_email = adapt_email_result(
            {"status": "ERROR", "message": "Breach database unavailable"}
        )
        self.assertEqual(
            ModularFindingsProcessor().process(normalized_email), []
        )

    def test_modular_aggregation_interface_remains_absent(self):
        # The modular processor is intentionally not adopting canonical
        # aggregation interfaces. This verifies opt-in status.
        self.assertFalse(
            hasattr(ModularFindingsProcessor, "process_module_results")
        )
        self.assertFalse(
            hasattr(ModularFindingsProcessor, "process_scan_result")
        )

    def test_opt_in_interfaces_remain_unused_by_canonical_flows(self):
        with open("app/core/scan_controller.py", encoding="utf-8") as stream:
            scan_controller = stream.read()
        with open("app/ui/main_window.py", encoding="utf-8") as stream:
            main_window = stream.read()

        self.assertNotIn("from app.core.findings import", scan_controller)
        self.assertNotIn("from app.core.findings import", main_window)


if __name__ == "__main__":
    unittest.main()
