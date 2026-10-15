import unittest

from app.core.findings import (
    EvidenceItem,
    FindingsProcessor,
    NormalizedCheckResult,
    adapt_browser_result,
    adapt_email_result,
    adapt_file_metadata_result,
    adapt_system_result,
    adapt_username_result,
)
from app.core.findings.rules.browser_rules import rule_brw_profile_001
from app.core.findings.rules.email_rules import rule_eml_breach_001
from app.core.findings.rules.file_metadata_rules import rule_file_camera_001, rule_file_gps_001
from app.core.findings.rules.system_rules import rule_sys_startup_001
from app.core.findings.rules.username_rules import rule_usr_profile_001
from app.models.common import Finding


class TestModularFindingsCompatibility(unittest.TestCase):
    """Compatibility tests for the restored modular findings package."""

    def _result(
        self,
        module: str = "email",
        status: str = "COMPLETED",
        outcome: str = "FOUND",
        evidence_items=None,
    ) -> NormalizedCheckResult:
        if evidence_items is None:
            evidence_items = []
        return NormalizedCheckResult(
            module=module,
            status=status,
            outcome=outcome,
            evidence_items=evidence_items,
        )

    def _make_evidence(
        self,
        module: str,
        item_type: str,
        label: str,
        properties=None,
        evidence_key: str = "shared-evidence-key",
    ) -> EvidenceItem:
        return EvidenceItem(
            source_module=module,
            item_type=item_type,
            label=label,
            properties=properties or {},
            source="Test Source",
            evidence_key=evidence_key,
        )

    # ---------------------------------------------------------------------
    # Rule coverage
    # ---------------------------------------------------------------------

    def test_email_rule_verified_breach(self):
        item = self._make_evidence(
            "email",
            "email_breach",
            "Breach: TestCorp",
            {
                "breach_name": "TestCorp",
                "records_exposed": 5,
                "verified": True,
                "password_risk": True,
                "exposed_data": ["Email", "Password"],
            },
            evidence_key="email:breach:testcorp",
        )

        finding = rule_eml_breach_001(self._result(), item)

        self.assertIsInstance(finding, Finding)
        self.assertEqual(finding.finding_type, "Email Breach")
        self.assertEqual(finding.title, "Confirmed Breach Exposure: TestCorp")
        self.assertEqual(finding.severity, "High")
        self.assertEqual(finding.status, "Unremediated")
        self.assertEqual(finding.category, "Concern")
        self.assertEqual(finding.rule_id, "EML-BREACH-001")
        self.assertEqual(finding.evidence, ["Email", "Password"])

    def test_email_rule_unverified_breach(self):
        item = self._make_evidence(
            "email",
            "email_breach",
            "Breach: TestCorp",
            {
                "breach_name": "TestCorp",
                "records_exposed": 5,
                "verified": False,
                "password_risk": False,
                "exposed_data": [],
            },
            evidence_key="email:breach:testcorp",
        )

        finding = rule_eml_breach_001(self._result(), item)

        self.assertEqual(finding.finding_type, "Email Breach Record")
        self.assertEqual(finding.title, "Unconfirmed Breach Record: TestCorp")
        self.assertEqual(finding.severity, "Info")
        self.assertEqual(finding.status, "Informational")
        self.assertEqual(finding.category, "Observation")
        self.assertEqual(finding.evidence, ["Breach: TestCorp"])

    def test_email_rule_rejects_other_modules(self):
        item = self._make_evidence(
            "username",
            "email_breach",
            "Breach: TestCorp",
            {"breach_name": "TestCorp"},
        )

        self.assertIsNone(rule_eml_breach_001(self._result("username"), item))

    def test_username_rule(self):
        item = self._make_evidence(
            "username",
            "social_profile",
            "GitHub Profile",
            {
                "platform": "GitHub",
                "profile_url": "https://github.com/example",
            },
            evidence_key="username:profile:github:example",
        )

        finding = rule_usr_profile_001(self._result("username"), item)

        self.assertEqual(finding.finding_type, "Public Profile")
        self.assertEqual(
            finding.title, "Public Profile Discovered on GitHub"
        )
        self.assertEqual(finding.severity, "Info")
        self.assertEqual(finding.status, "Informational")
        self.assertEqual(finding.category, "Observation")
        self.assertEqual(finding.rule_id, "USR-PROFILE-001")
        self.assertEqual(finding.evidence, "https://github.com/example")

    def test_username_rule_with_empty_url(self):
        item = self._make_evidence(
            "username",
            "social_profile",
            "GitHub Profile",
            {"platform": "GitHub", "profile_url": ""},
            evidence_key="username:profile:github:empty",
        )

        finding = rule_usr_profile_001(self._result("username"), item)

        self.assertEqual(finding.evidence, "Platform: GitHub")

    def test_system_startup_rule(self):
        item = self._make_evidence(
            "system",
            "startup_app",
            "Startup Application: Discord",
            {
                "name": "Discord",
                "command": "/usr/bin/discord",
                "source": "XDG Autostart",
                "scope": "user",
            },
            evidence_key="system:startup:discord:/usr/bin/discord",
        )

        finding = rule_sys_startup_001(self._result("system"), item)

        self.assertEqual(finding.finding_type, "Startup Application")
        self.assertEqual(
            finding.title, "Startup Application Configured: Discord"
        )
        self.assertEqual(finding.severity, "Info")
        self.assertEqual(finding.status, "Informational")
        self.assertEqual(finding.category, "Observation")
        self.assertEqual(finding.rule_id, "SYS-STARTUP-001")
        self.assertEqual(finding.evidence, "/usr/bin/discord")

    def test_file_gps_rule(self):
        item = self._make_evidence(
            "file_metadata",
            "gps_metadata",
            "GPS Metadata: GPS Coordinates",
            {
                "field": "GPS Coordinates",
                "value": "37.00, -122.00",
            },
            evidence_key="file_metadata:gps:location",
        )

        finding = rule_file_gps_001(self._result("file_metadata"), item)

        self.assertEqual(finding.finding_type, "Embedded Geolocation")
        self.assertEqual(finding.title, "Embedded GPS Location Data Detected")
        self.assertEqual(finding.severity, "Medium")
        self.assertEqual(finding.status, "Unremediated")
        self.assertEqual(finding.category, "Concern")
        self.assertEqual(finding.rule_id, "FILE-GPS-001")
        self.assertEqual(finding.evidence, "37.00, -122.00")

    def test_file_camera_rule(self):
        item = self._make_evidence(
            "file_metadata",
            "camera_metadata",
            "Camera/Device Metadata: Camera Model",
            {
                "field": "Camera Model",
                "value": "Example Camera",
                "description": "camera metadata",
            },
            evidence_key="file_metadata:camera:model",
        )

        finding = rule_file_camera_001(self._result("file_metadata"), item)

        self.assertEqual(finding.finding_type, "Device Metadata")
        self.assertEqual(
            finding.title, "Camera/Device Model Detected: Camera Model"
        )
        self.assertEqual(finding.severity, "Info")
        self.assertEqual(finding.status, "Informational")
        self.assertEqual(finding.category, "Observation")
        self.assertEqual(finding.rule_id, "FILE-CAMERA-001")
        self.assertEqual(finding.evidence, "Example Camera")

    def test_file_camera_rule_title_variants(self):
        variants = {
            "lens serial": "Lens Hardware Detected: lens serial",
            "serial number": "Device Serial Number Detected: serial number",
            "owner name": "Author/Owner Metadata Detected: owner name",
        }

        for field, expected_title in variants.items():
            with self.subTest(field=field):
                item = self._make_evidence(
                    "file_metadata",
                    "camera_metadata",
                    "Camera/Device Metadata: " + field,
                    {
                        "field": field,
                        "value": "value",
                        "description": "metadata",
                    },
                    evidence_key="file_metadata:camera:" + field.replace(" ", "_"),
                )

                finding = rule_file_camera_001(
                    self._result("file_metadata"), item
                )

                self.assertEqual(finding.title, expected_title)

    def test_browser_rule(self):
        item = self._make_evidence(
            "browser",
            "browser_profile",
            "Browser Profile (Default)",
            {
                "browser_name": "Chrome",
                "version": "123.0",
                "profile": "Default",
                "executable_path": "/opt/google/chrome/chrome",
            },
            evidence_key="browser:installation:chrome",
        )

        finding = rule_brw_profile_001(self._result("browser"), item)

        self.assertEqual(finding.finding_type, "Browser Profile")
        self.assertEqual(
            finding.title, "Browser Profile Detected: Chrome (Default)"
        )
        self.assertEqual(finding.severity, "Info")
        self.assertEqual(finding.status, "Informational")
        self.assertEqual(finding.category, "Observation")
        self.assertEqual(finding.rule_id, "BRW-PROFILE-001")
        self.assertIn("Browser: Chrome", finding.evidence)
        self.assertIn("Profile: Default", finding.evidence)
        self.assertIn("Path: /opt/google/chrome/chrome", finding.evidence)

    def test_all_rules_reject_wrong_items(self):
        simple = self._make_evidence(
            "system",
            "startup_app",
            "Wrong Item",
            {"name": "App", "command": "/bin/app", "scope": "user"},
        )
        self.assertIsNone(rule_usr_profile_001(self._result("system"), simple))
        email_item = self._make_evidence(
            "email",
            "startup_app",
            "Not System",
            {"name": "App", "command": "/bin/app", "scope": "user"},
            evidence_key="email:wrong:app",
        )
        self.assertIsNone(rule_sys_startup_001(self._result("email"), email_item))
        self.assertIsNone(rule_eml_breach_001(self._result("system"), simple))

    # ---------------------------------------------------------------------
    # Adapter coverage
    # ---------------------------------------------------------------------

    def test_email_adapter_success_breaches(self):
        result = adapt_email_result(
            {
                "status": "SUCCESS",
                "breaches": [
                    {
                        "name": "Acme Corp",
                        "records_exposed": 100,
                        "breach_date": "2024-01-01",
                        "industry": "Tech",
                        "password_risk": True,
                        "verified": True,
                        "exposed_data": ["Email", "Password"],
                    }
                ],
            }
        )

        self.assertEqual(result.module, "email")
        self.assertEqual(result.status, "COMPLETED")
        self.assertEqual(result.outcome, "FOUND")
        self.assertEqual(len(result.evidence_items), 1)
        self.assertEqual(
            result.evidence_items[0].evidence_key, "email:breach:acme_corp"
        )

    def test_email_adapter_empty_and_failed(self):
        empty = adapt_email_result({"status": "SUCCESS", "breaches": []})
        self.assertEqual(empty.status, "COMPLETED")
        self.assertEqual(empty.outcome, "NOT_FOUND")
        self.assertEqual(empty.evidence_items, [])

        failed = adapt_email_result(
            {"status": "ERROR", "message": "Rate limited"}
        )
        self.assertEqual(failed.status, "FAILED")
        self.assertEqual(failed.outcome, "UNKNOWN")
        self.assertEqual(failed.errors, ["Rate limited"])

        unexpected = adapt_email_result({"status": "SOMETHING_ELSE"})
        self.assertEqual(unexpected.status, "FAILED")
        self.assertIn("Unexpected", unexpected.errors[0])

    def test_username_adapter_all_statuses(self):
        found = adapt_username_result(
            {
                "status": "FOUND",
                "results": [
                    {
                        "platform": "GitHub",
                        "profile_url": "https://github.com/example",
                    }
                ],
            }
        )
        self.assertEqual(found.status, "COMPLETED")
        self.assertEqual(found.outcome, "FOUND")
        self.assertEqual(found.evidence_items[0].evidence_key, "username:profile:github:https://github.com/example")

        not_found = adapt_username_result({"status": "NOT_FOUND", "results": []})
        self.assertEqual(not_found.status, "COMPLETED")
        self.assertEqual(not_found.outcome, "NOT_FOUND")

        failed = adapt_username_result({"status": "ERROR", "message": "Search failed"})
        self.assertEqual(failed.status, "FAILED")
        self.assertEqual(failed.errors, ["Search failed"])

        timeout = adapt_username_result({"status": "UNKNOWN", "message": "Sherlock search timed out."})
        self.assertEqual(timeout.status, "FAILED")
        self.assertEqual(timeout.limitations, ["Search aborted before full completion; cannot confirm absence of profiles."])

    def test_username_adapter_unexpected_status(self):
        result = adapt_username_result({"status": "WEIRD"})
        self.assertEqual(result.status, "FAILED")
        self.assertIn("Unexpected", result.errors[0])

    def test_system_adapter_success_found_and_not_found(self):
        found = adapt_system_result(
            {
                "status": "SUCCESS",
                "results": {
                    "startup_applications": [
                        {
                            "name": "Discord",
                            "command": "/usr/bin/discord",
                            "source": "XDG Autostart",
                            "scope": "user",
                            "enabled": True,
                        }
                    ],
                    "startup_applications_status": "SUCCESS",
                },
            }
        )
        self.assertEqual(found.status, "COMPLETED")
        self.assertEqual(found.outcome, "FOUND")
        self.assertEqual(len(found.evidence_items), 1)
        self.assertEqual(
            found.evidence_items[0].evidence_key,
            "system:startup:discord:/usr/bin/discord",
        )

        not_found = adapt_system_result(
            {
                "status": "SUCCESS",
                "results": {
                    "startup_applications": [],
                    "startup_applications_status": "SUCCESS",
                },
            }
        )
        self.assertEqual(not_found.status, "COMPLETED")
        self.assertEqual(not_found.outcome, "NOT_FOUND")
        self.assertEqual(not_found.evidence_items, [])

    def test_system_adapter_failed_and_partial(self):
        failed = adapt_system_result({"status": "ERROR", "message": "System scan failed."})
        self.assertEqual(failed.status, "FAILED")
        self.assertEqual(failed.errors, ["System scan failed."])

        partial = adapt_system_result(
            {
                "status": "SUCCESS",
                "results": {
                    "startup_applications": [],
                    "startup_applications_status": "UNAVAILABLE",
                    "startup_applications_coverage": "Registry unavailable",
                },
            }
        )
        self.assertEqual(partial.status, "PARTIAL")
        self.assertEqual(partial.outcome, "UNKNOWN")
        self.assertIn("Startup application discovery is unavailable", partial.warnings[0])
        self.assertTrue(partial.limitations)

    def test_file_metadata_adapter_outcomes(self):
        gps = adapt_file_metadata_result(
            {
                "status": "SUCCESS",
                "results": {
                    "is_supported": True,
                    "potentially_sensitive": [
                        {
                            "category": "Location & GPS",
                            "field": "GPS Coordinates",
                            "value": "37.00, -122.00",
                            "description": "location",
                        },
                        {
                            "category": "Camera",
                            "field": "Camera Model",
                            "value": "Example Camera",
                            "description": "model",
                        },
                    ],
                },
            }
        )
        self.assertEqual(gps.status, "COMPLETED")
        self.assertEqual(gps.outcome, "FOUND")
        self.assertEqual(len(gps.evidence_items), 2)
        self.assertTrue(
            any(item.item_type == "gps_metadata" for item in gps.evidence_items)
        )
        self.assertTrue(
            any(item.item_type == "camera_metadata" for item in gps.evidence_items)
        )

        clean = adapt_file_metadata_result(
            {
                "status": "SUCCESS",
                "results": {"is_supported": True, "potentially_sensitive": []},
            }
        )
        self.assertEqual(clean.status, "COMPLETED")
        self.assertEqual(clean.outcome, "NOT_FOUND")

        unsupported = adapt_file_metadata_result(
            {
                "status": "SUCCESS",
                "results": {"is_supported": False},
            }
        )
        self.assertEqual(unsupported.status, "COMPLETED")
        self.assertEqual(unsupported.outcome, "UNKNOWN")
        self.assertTrue(unsupported.limitations)

        failed = adapt_file_metadata_result(
            {"status": "ERROR", "message": "File scan failed."}
        )
        self.assertEqual(failed.status, "FAILED")
        self.assertEqual(failed.errors, ["File scan failed."])

    def test_browser_adapter_outcomes(self):
        success = adapt_browser_result(
            {
                "status": "SUCCESS",
                "browsers": [
                    {
                        "name": "Chrome",
                        "profiles": ["Default"],
                        "detection_source": "Filesystem",
                    }
                ],
            }
        )
        self.assertEqual(success.status, "COMPLETED")
        self.assertEqual(success.outcome, "FOUND")
        self.assertEqual(success.evidence_items[0].evidence_key, "browser:profile:chrome:default")

        unavailable = adapt_browser_result(
            {
                "status": "UNAVAILABLE",
                "unavailable_sources": ["Chrome profiles"],
                "errors": ["locked"],
            }
        )
        self.assertEqual(unavailable.status, "UNAVAILABLE")
        self.assertEqual(unavailable.limitations, ["Chrome profiles"])
        self.assertEqual(unavailable.errors, ["locked"])

        partial = adapt_browser_result(
            {
                "status": "PARTIAL",
                "browsers": [
                    {"name": "Chrome", "profiles": [], "detection_source": "Filesystem"}
                ],
                "unavailable_sources": [],
                "errors": ["warning"],
            }
        )
        self.assertEqual(partial.status, "PARTIAL")
        self.assertEqual(partial.warnings, ["warning"])

        no_items = adapt_browser_result(
            {
                "status": "SUCCESS",
                "browsers": [],
            }
        )
        self.assertEqual(no_items.status, "COMPLETED")
        self.assertEqual(no_items.outcome, "NOT_FOUND")

    # ---------------------------------------------------------------------
    # Processor behavior, deduplication, and ordering
    # ---------------------------------------------------------------------

    def test_processor_returns_empty_for_failed_and_unavailable(self):
        failed = self._result(status="FAILED")
        unavailable = self._result(status="UNAVAILABLE")
        processor = FindingsProcessor()

        self.assertEqual(processor.process(failed), [])
        self.assertEqual(processor.process(unavailable), [])

    def test_processor_returns_empty_without_evidence(self):
        result = self._result(
            status="COMPLETED",
            outcome="NOT_FOUND",
            evidence_items=[],
        )

        self.assertEqual(FindingsProcessor().process(result), [])

    def test_processor_uses_rules_override(self):
        called = {"value": False}

        def custom_rule(result, item):
            called["value"] = True
            item_label = item.label
            return Finding(
                finding_id="override",
                finding_type="Custom Finding",
                title=f"Custom: {item_label}",
                description="Override",
                severity="Low",
                status="Informational",
            )

        item = self._make_evidence(
            "browser",
            "browser_profile",
            "Profile",
            evidence_key="override-key",
        )
        result = self._result("browser", evidence_items=[item])
        findings = FindingsProcessor(rules_override=[custom_rule]).process(result)

        self.assertTrue(called["value"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Custom: Profile")

    def test_processor_isolates_rule_exceptions(self):
        def broken_rule(result, item):
            raise ValueError("broken")
            return None  # pragma: no cover

        item = self._make_evidence(
            "browser", "browser_profile", "Profile", evidence_key="exception-key"
        )
        result = self._result("browser", evidence_items=[item])

        self.assertEqual(
            FindingsProcessor(rules_override=[broken_rule]).process(result), []
        )

    def test_processor_deduplicates_identical_rule_findings(self):
        item = self._make_evidence(
            "email",
            "email_breach",
            "Breach: TestCorp",
            {
                "breach_name": "TestCorp",
                "verified": True,
                "records_exposed": 5,
            },
            evidence_key="email:breach:testcorp",
        )
        result = self._result(
            module="email", evidence_items=[item, item]
        )

        modular_result = FindingsProcessor().process(result)

        self.assertEqual(len(modular_result), 1)
        self.assertEqual(modular_result[0].rule_id, "EML-BREACH-001")

    def test_processor_keeps_different_rule_ids(self):
        email_item = self._make_evidence(
            "email",
            "email_breach",
            "Breach: TestCorp",
            {
                "breach_name": "TestCorp",
                "verified": True,
                "records_exposed": 5,
            },
            evidence_key="email:breach:testcorp",
        )
        username_item = self._make_evidence(
            "username",
            "social_profile",
            "GitHub Profile",
            {"platform": "GitHub", "profile_url": "https://github.com/example"},
            evidence_key="username:profile:github:example",
        )
        result = self._result("email", evidence_items=[email_item])

        additional_system = self._make_evidence(
            "system",
            "startup_app",
            "Startup Application: Discord",
            {"name": "Discord", "command": "/usr/bin/discord", "scope": "user"},
            evidence_key="system:startup:discord",
        )

        findings = FindingsProcessor().process(
            NormalizedCheckResult(
                module="email",
                status="COMPLETED",
                outcome="FOUND",
                evidence_items=[email_item],
            )
        )
        findings.extend(
            FindingsProcessor().process(
                NormalizedCheckResult(
                    module="username",
                    status="COMPLETED",
                    outcome="FOUND",
                    evidence_items=[username_item],
                )
            )
        )
        findings.extend(
            FindingsProcessor().process(
                NormalizedCheckResult(
                    module="system",
                    status="COMPLETED",
                    outcome="FOUND",
                    evidence_items=[additional_system],
                )
            )
        )

        self.assertEqual(len(findings), 3)
        self.assertEqual(
            {finding.rule_id for finding in findings},
            {"EML-BREACH-001", "USR-PROFILE-001", "SYS-STARTUP-001"},
        )

    def test_processor_keeps_different_evidence_keys(self):
        first = self._make_evidence(
            "email",
            "email_breach",
            "Breach: One",
            {
                "breach_name": "One",
                "verified": True,
                "records_exposed": 1,
            },
            evidence_key="email:breach:one",
        )
        second = self._make_evidence(
            "email",
            "email_breach",
            "Breach: Two",
            {
                "breach_name": "Two",
                "verified": True,
                "records_exposed": 2,
            },
            evidence_key="email:breach:two",
        )

        result = self._result("email", evidence_items=[first, second])
        findings = FindingsProcessor().process(result)

        self.assertEqual(len(findings), 2)
        self.assertEqual(
            {finding.title for finding in findings},
            {"Confirmed Breach Exposure: One", "Confirmed Breach Exposure: Two"},
        )

    def test_processor_dedup_keeps_first_finding(self):
        first = self._make_evidence(
            "email",
            "email_breach",
            "Breach: TestCorp",
            {
                "breach_name": "TestCorp",
                "verified": True,
                "records_exposed": 1,
            },
            evidence_key="email:breach:testcorp",
        )
        second = self._make_evidence(
            "email",
            "email_breach",
            "Breach: TestCorp",
            {
                "breach_name": "TestCorp",
                "verified": False,
                "records_exposed": 2,
            },
            evidence_key="email:breach:testcorp",
        )

        result = self._result("email", evidence_items=[first, second])
        findings = FindingsProcessor().process(result)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "High")
        self.assertEqual(findings[0].evidence, ["Breach: TestCorp"])

    def test_processor_output_is_deterministic(self):
        items = [
            self._make_evidence(
                "email",
                "email_breach",
                "Breach: One",
                {
                    "breach_name": "One",
                    "verified": True,
                    "records_exposed": 1,
                    "exposed_data": ["Email"],
                },
                evidence_key="email:breach:one",
            ),
            self._make_evidence(
                "email",
                "email_breach",
                "Breach: Two",
                {
                    "breach_name": "Two",
                    "verified": True,
                    "records_exposed": 2,
                    "exposed_data": ["Password"],
                },
                evidence_key="email:breach:two",
            ),
        ]
        result = self._result("email", evidence_items=items)

        first_run = FindingsProcessor().process(result)
        second_run = FindingsProcessor().process(result)

        self.assertEqual(len(first_run), 2)
        self.assertEqual(len(second_run), 2)
        self.assertEqual(
            [(finding.rule_id, finding.title, finding.evidence) for finding in first_run],
            [(finding.rule_id, finding.title, finding.evidence) for finding in second_run],
        )
        self.assertEqual(
            [(finding.severity, finding.status, finding.category) for finding in first_run],
            [(finding.severity, finding.status, finding.category) for finding in second_run],
        )

    def test_modular_findings_use_canonical_model_fields(self):
        item = self._make_evidence(
            "browser",
            "browser_profile",
            "Browser Profile",
            {
                "browser_name": "Chrome",
                "version": "1.0",
                "profile": "Default",
                "executable_path": "/tmp/chrome",
            },
            evidence_key="browser:profile:chrome:default",
        )
        findings = FindingsProcessor().process(
            self._result("browser", evidence_items=[item])
        )

        finding = findings[0]
        self.assertIsInstance(finding, Finding)
        self.assertTrue(finding.finding_id)
        self.assertEqual(finding.finding_type, "Browser Profile")
        self.assertEqual(finding.title, "Browser Profile Detected: Chrome (Default)")
        self.assertEqual(finding.category, "Observation")
        self.assertEqual(finding.rule_id, "BRW-PROFILE-001")
        self.assertTrue(finding.limitations)
        self.assertEqual(finding.status, "Informational")

    def test_modular_package_is_opt_in(self):
        with open("app/core/scan_controller.py", encoding="utf-8") as stream:
            scan_controller = stream.read()
        with open("app/ui/main_window.py", encoding="utf-8") as stream:
            main_window = stream.read()

        self.assertNotIn("from app.core.findings import", scan_controller)
        self.assertNotIn("from app.core.findings import", main_window)


if __name__ == "__main__":
    unittest.main()
