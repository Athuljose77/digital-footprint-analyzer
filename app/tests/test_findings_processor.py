import unittest
import uuid
import sys
import os

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from app.models.common import ScanResult, FootprintData, Finding
from app.core.findings_processor import FindingsProcessor, _get_severity_rank, _normalize_severity_name


class TestFindingsProcessor(unittest.TestCase):
    """
    Comprehensive test suite for FindingsProcessor covering:
    - Finding normalization
    - Deduplication and evidence merging
    - Severity preservation and ranking
    - Result conversion across all 5 modules (Email, Username, System, File & Metadata, Browser)
    - Empty inputs, missing data, and module error handling
    - Valid ScanResult schema output
    """

    # =========================================================================
    # 1. FINDING NORMALIZATION
    # =========================================================================

    def test_normalize_finding_from_finding_instance(self):
        raw = Finding(
            finding_id="",
            finding_type="  Email Breach  ",
            title="  Exposed in TestCorp  ",
            description="  Exposed 500 records.  ",
            evidence=["email", "password"],
            severity="high",
            status="unremediated"
        )
        norm = FindingsProcessor.normalize_finding(raw)

        self.assertTrue(len(norm.finding_id) > 0)
        self.assertEqual(norm.finding_type, "Email Breach")
        self.assertEqual(norm.title, "Exposed in TestCorp")
        self.assertEqual(norm.description, "Exposed 500 records.")
        self.assertEqual(norm.evidence, ["email", "password"])
        self.assertEqual(norm.severity, "High")
        self.assertEqual(norm.status, "Unremediated")

    def test_normalize_finding_from_dict(self):
        data = {
            "finding_type": "Sensitive Metadata",
            "title": "GPS Location Detected",
            "description": "Found coordinates in EXIF",
            "evidence": ["37.7749 N, 122.4194 W"],
            "severity": "CRITICAL",
            "status": "open"
        }
        norm = FindingsProcessor.normalize_finding(data)

        self.assertIsInstance(norm, Finding)
        self.assertEqual(norm.finding_type, "Sensitive Metadata")
        self.assertEqual(norm.title, "GPS Location Detected")
        self.assertEqual(norm.severity, "Critical")
        self.assertEqual(norm.status, "Open")
        self.assertEqual(norm.evidence, ["37.7749 N, 122.4194 W"])
        self.assertTrue(bool(norm.finding_id))

    def test_normalize_finding_with_missing_fields(self):
        norm = FindingsProcessor.normalize_finding({})
        self.assertIsInstance(norm, Finding)
        self.assertEqual(norm.finding_type, "General")
        self.assertEqual(norm.title, "Untitled Finding")
        self.assertEqual(norm.severity, "Info")
        self.assertEqual(norm.status, "Active")
        self.assertTrue(bool(norm.finding_id))

    def test_normalize_finding_unexpected_type_fallback(self):
        norm = FindingsProcessor.normalize_finding("unexpected string instead of finding")
        self.assertIsInstance(norm, Finding)
        self.assertEqual(norm.finding_type, "Unknown")
        self.assertEqual(norm.severity, "Info")

    # =========================================================================
    # 2. DEDUPLICATION AND EVIDENCE MERGING
    # =========================================================================

    def test_deduplicate_identical_findings(self):
        f1 = Finding(
            finding_id="id-1",
            finding_type="Email Breach",
            title="Exposed in LinkedIn",
            description="Breach in 2012",
            evidence=["emails"],
            severity="Medium",
            status="Unremediated"
        )
        f2 = Finding(
            finding_id="id-2",
            finding_type="Email Breach",
            title="Exposed in LinkedIn",
            description="Breach in 2012 with passwords",
            evidence=["passwords", "emails"],  # 'emails' is duplicated
            severity="High",                   # Higher severity
            status="Unremediated"
        )
        deduped = FindingsProcessor.deduplicate_findings([f1, f2])

        self.assertEqual(len(deduped), 1)
        merged = deduped[0]
        self.assertEqual(merged.finding_type, "Email Breach")
        self.assertEqual(merged.title, "Exposed in LinkedIn")
        # Severity must be preserved as High
        self.assertEqual(merged.severity, "High")
        # Evidence must contain both unique items without duplicates
        self.assertEqual(sorted(merged.evidence), ["emails", "passwords"])
        # Description should choose the more descriptive one
        self.assertIn("passwords", merged.description)

    def test_deduplicate_preserves_distinct_findings(self):
        f1 = Finding(
            finding_id="id-1",
            finding_type="Email Breach",
            title="Exposed in ServiceA",
            description="Desc A",
            severity="Medium",
            status="Active"
        )
        f2 = Finding(
            finding_id="id-2",
            finding_type="Email Breach",
            title="Exposed in ServiceB",
            description="Desc B",
            severity="Medium",
            status="Active"
        )
        f3 = Finding(
            finding_id="id-3",
            finding_type="Sensitive Metadata",
            title="GPS Location",
            description="Desc C",
            severity="High",
            status="Active"
        )
        deduped = FindingsProcessor.deduplicate_findings([f1, f2, f3])
        self.assertEqual(len(deduped), 3)

    def test_deduplicate_evidence_merging_various_formats(self):
        f1 = Finding(
            finding_id="id-1",
            finding_type="Public Presence",
            title="Online Profiles",
            description="Profiles found",
            evidence=["https://github.com/user"],
            severity="Low",
            status="Active"
        )
        f2 = Finding(
            finding_id="id-2",
            finding_type="Public Presence",
            title="Online Profiles",
            description="Profiles found",
            evidence="https://twitter.com/user",  # string evidence merged with list
            severity="Medium",
            status="Active"
        )
        deduped = FindingsProcessor.deduplicate_findings([f1, f2])
        self.assertEqual(len(deduped), 1)
        self.assertIn("https://github.com/user", deduped[0].evidence)
        self.assertIn("https://twitter.com/user", deduped[0].evidence)

    # =========================================================================
    # 3. SEVERITY PRESERVATION AND RANKING
    # =========================================================================

    def test_severity_ranks_ordering(self):
        self.assertGreater(_get_severity_rank("Critical"), _get_severity_rank("High"))
        self.assertGreater(_get_severity_rank("High"), _get_severity_rank("Medium"))
        self.assertGreater(_get_severity_rank("Medium"), _get_severity_rank("Low"))
        self.assertGreater(_get_severity_rank("Low"), _get_severity_rank("Info"))

    def test_severity_preservation_multistep(self):
        # 3 duplicate findings with Low, Critical, and Medium
        findings = [
            Finding(finding_id="1", finding_type="T", title="Issue", description="d", severity="Low", status="Active"),
            Finding(finding_id="2", finding_type="T", title="Issue", description="d", severity="Critical", status="Active"),
            Finding(finding_id="3", finding_type="T", title="Issue", description="d", severity="Medium", status="Active"),
        ]
        deduped = FindingsProcessor.deduplicate_findings(findings)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].severity, "Critical")

    # =========================================================================
    # 4. MODULE CONVERSIONS: EMAIL MODULE
    # =========================================================================

    def test_email_dict_conversion_with_password_risk(self):
        email_data = {
            "status": "SUCCESS",
            "breaches": [
                {
                    "name": "Adobe",
                    "records_exposed": 150000000,
                    "industry": "Software",
                    "exposed_data": ["Email addresses", "Password hints", "Passwords"],
                    "password_risk": True
                },
                {
                    "name": "Canva",
                    "records_exposed": 137000000,
                    "industry": "Design",
                    "exposed_data": ["Names", "Email addresses"],
                    "password_risk": False
                }
            ]
        }
        findings = FindingsProcessor.extract_module_findings("email", email_data)
        self.assertEqual(len(findings), 2)

        adobe = next(f for f in findings if "Adobe" in f.title)
        self.assertEqual(adobe.severity, "High")
        self.assertEqual(adobe.status, "Unremediated")
        self.assertIn("Passwords", adobe.evidence)

        canva = next(f for f in findings if "Canva" in f.title)
        self.assertEqual(canva.severity, "Medium")

    # =========================================================================
    # 5. MODULE CONVERSIONS: USERNAME MODULE
    # =========================================================================

    def test_username_footprint_conversion_informational(self):
        # 1 profile -> Info severity, unverified ownership label, URLs preserved
        res_low = ScanResult(
            scan_id="u1",
            analysis_mode="Public Footprint Lookup",
            scan_type="Username",
            scan_category="Public Presence",
            status="COMPLETED",
            footprint_data=[
                FootprintData(category="Public Presence", subcategory="Social Profile", source="GitHub", data_type="URL", value="https://github.com/user", sensitivity="Low")
            ]
        )
        f_low = FindingsProcessor.extract_module_findings("username", res_low)
        self.assertEqual(len(f_low), 1)
        self.assertEqual(f_low[0].severity, "Info")
        self.assertEqual(f_low[0].status, "Informational")
        self.assertEqual(f_low[0].title, "Possible username matches — ownership unverified")
        self.assertIn("ownership is unverified", f_low[0].description.lower())
        self.assertEqual(f_low[0].evidence, ["https://github.com/user"])

        # Multiple profiles (e.g. 10 profiles) -> Remains Info severity (not High), preserves all URLs
        res_many = ScanResult(
            scan_id="u3",
            analysis_mode="Public Footprint Lookup",
            scan_type="Username",
            scan_category="Public Presence",
            status="COMPLETED",
            footprint_data=[
                FootprintData(category="Public Presence", subcategory="Social Profile", source=f"Site{i}", data_type="URL", value=f"https://site{i}.com/user", sensitivity="Low")
                for i in range(10)
            ]
        )
        f_many = FindingsProcessor.extract_module_findings("username", res_many)
        self.assertEqual(len(f_many), 1)
        self.assertEqual(f_many[0].severity, "Info")
        self.assertEqual(f_many[0].status, "Informational")
        self.assertEqual(f_many[0].title, "Possible username matches — ownership unverified")
        self.assertEqual(len(f_many[0].evidence), 10)
        self.assertIn("https://site0.com/user", f_many[0].evidence)

    def test_username_zero_profiles_produces_no_false_findings(self):
        res_empty = ScanResult(
            scan_id="u4",
            analysis_mode="Public Footprint Lookup",
            scan_type="Username",
            scan_category="Public Presence",
            status="COMPLETED",
            footprint_data=[]
        )
        findings = FindingsProcessor.extract_module_findings("username", res_empty)
        self.assertEqual(len(findings), 0)

    # =========================================================================
    # 6. MODULE CONVERSIONS: SYSTEM FOOTPRINT MODULE
    # =========================================================================

    def test_system_footprint_startup_conversion(self):
        res = ScanResult(
            scan_id="s1",
            analysis_mode="My Footprint",
            scan_type="System",
            scan_category="System Footprint",
            status="COMPLETED",
            footprint_data=[
                FootprintData(category="System", subcategory="Operating System", source="System API", data_type="String", value="Windows 11", sensitivity="Low"),
                FootprintData(category="System", subcategory="Startup Applications", source="Windows Registry", data_type="startup_application", value="OneDrive — Enabled", sensitivity="Low"),
                FootprintData(category="System", subcategory="Startup Applications", source="Windows Registry", data_type="startup_application", value="Discord — Enabled", sensitivity="Low"),
            ]
        )
        findings = FindingsProcessor.extract_module_findings("system", res)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_type, "System Configuration")
        self.assertIn("Startup Footprint (2 detected)", findings[0].title)
        self.assertEqual(findings[0].severity, "Low")

    def test_system_footprint_unavailable_startup_filtered_out(self):
        res = ScanResult(
            scan_id="s2",
            analysis_mode="My Footprint",
            scan_type="System",
            scan_category="System Footprint",
            status="COMPLETED",
            footprint_data=[
                FootprintData(category="System", subcategory="Startup Applications", source="OS", data_type="startup_application", value="Unavailable (Cannot collect startup applications)", sensitivity="Low")
            ]
        )
        findings = FindingsProcessor.extract_module_findings("system", res)
        # Should not generate a false startup finding when source is Unavailable
        self.assertEqual(len(findings), 0)

    # =========================================================================
    # 7. MODULE CONVERSIONS: FILE & METADATA MODULE
    # =========================================================================

    def test_file_metadata_sensitive_findings_categorization(self):
        res = ScanResult(
            scan_id="f1",
            analysis_mode="My Footprint",
            scan_type="File & Metadata",
            scan_category="File & Metadata Footprint",
            status="COMPLETED",
            footprint_data=[
                FootprintData(category="File & Metadata", subcategory="File Information", source="File System", data_type="file_info", value="photo.jpg", sensitivity="Low"),
                FootprintData(category="File & Metadata", subcategory="Potentially Sensitive", source="Location & GPS", data_type="sensitive_metadata", value="GPS: 37.77 N, 122.41 W", sensitivity="High"),
                FootprintData(category="File & Metadata", subcategory="Potentially Sensitive", source="Personal Identification", data_type="sensitive_metadata", value="Artist: John Doe", sensitivity="Medium"),
            ]
        )
        findings = FindingsProcessor.extract_module_findings("file & metadata", res)
        self.assertEqual(len(findings), 2)

        gps_finding = next(f for f in findings if "Location" in f.title)
        self.assertEqual(gps_finding.severity, "High")
        self.assertEqual(gps_finding.status, "Unremediated")

        author_finding = next(f for f in findings if "Personal" in f.title)
        self.assertEqual(author_finding.severity, "Medium")

    # =========================================================================
    # 8. MODULE CONVERSIONS: BROWSER FOOTPRINT MODULE
    # =========================================================================

    def test_browser_footprint_conversion(self):
        browser_data = {
            "status": "COMPLETED",
            "coverage": {
                "browsers_searched": ["Chrome", "Edge", "Firefox"],
                "browsers_detected": ["Chrome"],
                "sources_failed": ["Firefox Profiles (Locked)"]
            },
            "errors": ["Non-fatal permission warning"]
        }
        findings = FindingsProcessor.extract_module_findings("browser", browser_data)
        self.assertEqual(len(findings), 3)

        cov = next(f for f in findings if f.finding_type == "Scan Coverage")
        self.assertEqual(cov.severity, "Info")

        unavail = next(f for f in findings if f.finding_type == "Unavailable Sources")
        self.assertEqual(unavail.severity, "Info")

        warnings = next(f for f in findings if f.finding_type == "Scan Warnings")
        self.assertEqual(warnings.severity, "Low")

    # =========================================================================
    # 9. EMPTY INPUTS, MISSING DATA, AND MODULE ERROR HANDLING
    # =========================================================================

    def test_empty_results_handling(self):
        # Empty dictionary
        res_empty_dict = FindingsProcessor.process_module_results({})
        self.assertIsInstance(res_empty_dict, ScanResult)
        self.assertEqual(res_empty_dict.status, "COMPLETED")
        self.assertEqual(len(res_empty_dict.findings), 0)

        # Empty list
        res_empty_list = FindingsProcessor.process_module_results([])
        self.assertIsInstance(res_empty_list, ScanResult)
        self.assertEqual(len(res_empty_list.findings), 0)

    def test_module_error_handling_graceful(self):
        # Scan with 1 successful module and 1 explicit module error
        email_res = ScanResult(
            scan_id="e1",
            analysis_mode="Public Footprint Lookup",
            scan_type="Email",
            scan_category="Email Exposure",
            status="COMPLETED",
            findings=[
                Finding(finding_id="1", finding_type="Email Breach", title="Exposed in Dropbox", description="Leak", severity="Medium", status="Active")
            ]
        )
        combined = FindingsProcessor.process_module_results(
            module_results={"email": email_res},
            module_errors={"username": "Sherlock timed out while checking services."}
        )
        self.assertIsInstance(combined, ScanResult)
        self.assertTrue(any("Dropbox" in f.title for f in combined.findings))
        self.assertTrue(any("Module Limitation: Username" in f.title for f in combined.findings))
        limit_finding = next(f for f in combined.findings if "Limitation" in f.title)
        self.assertEqual(limit_finding.severity, "Info")
        self.assertEqual(limit_finding.status, "Limitation")

    def test_all_modules_failed_status(self):
        combined = FindingsProcessor.process_module_results(
            module_results={},
            module_errors={"email": "Network down", "system": "Access denied"}
        )
        self.assertEqual(combined.status, "ERROR")
        self.assertIn("errors on all attempted modules", combined.message.lower())
        self.assertEqual(len(combined.findings), 2)

    def test_malformed_module_data_safe_recovery(self):
        # Pass completely invalid object as module result
        combined = FindingsProcessor.process_module_results(
            module_results={"broken_mod": object()}  # Raw object without dict/ScanResult interface
        )
        self.assertIsInstance(combined, ScanResult)
        # Should not crash, should create a limitation finding or ignore safely
        self.assertTrue(len(combined.findings) >= 0)

    # =========================================================================
    # 10. SCANRESULT OUTPUT VALIDATION
    # =========================================================================

    def test_scan_result_schema_and_sorting(self):
        email_res = ScanResult(
            scan_id="e1",
            analysis_mode="Public Footprint Lookup",
            scan_type="Email",
            scan_category="Email Exposure",
            status="COMPLETED",
            findings=[
                Finding(finding_id="1", finding_type="Email Breach", title="Exposed in Service A", description="", severity="Low", status="Active"),
                Finding(finding_id="2", finding_type="Email Breach", title="Exposed in Service B", description="", severity="Critical", status="Active"),
                Finding(finding_id="3", finding_type="Email Breach", title="Exposed in Service C", description="", severity="High", status="Active"),
            ]
        )
        unified = FindingsProcessor.process_module_results({"email": email_res})

        # Validate Pydantic ScanResult fields
        self.assertTrue(bool(unified.scan_id))
        self.assertEqual(unified.analysis_mode, "Full Footprint Analysis")
        self.assertEqual(unified.scan_type, "Full Scan")
        self.assertEqual(unified.status, "COMPLETED")
        self.assertEqual(unified.risks, [])
        self.assertEqual(unified.recommendations, [])

        # Validate findings are sorted in descending severity order: Critical -> High -> Low
        severities = [f.severity for f in unified.findings]
        self.assertEqual(severities, ["Critical", "High", "Low"])

    def test_process_scan_result_in_place(self):
        sr = ScanResult(
            scan_id="u1",
            analysis_mode="Public Footprint Lookup",
            scan_type="Username",
            scan_category="Public Presence",
            status="COMPLETED",
            footprint_data=[
                FootprintData(category="Public Presence", subcategory="Social Profile", source="Reddit", data_type="URL", value="https://reddit.com/u/user", sensitivity="Low"),
                FootprintData(category="Public Presence", subcategory="Social Profile", source="GitHub", data_type="URL", value="https://github.com/user", sensitivity="Low"),
                FootprintData(category="Public Presence", subcategory="Social Profile", source="Twitter", data_type="URL", value="https://twitter.com/user", sensitivity="Low"),
            ]
        )
        self.assertEqual(len(sr.findings), 0)
        processed = FindingsProcessor.process_scan_result(sr)
        self.assertEqual(len(processed.findings), 1)
        self.assertEqual(processed.findings[0].finding_type, "Public Presence")
        self.assertEqual(processed.findings[0].title, "Possible username matches — ownership unverified")
        self.assertEqual(processed.findings[0].severity, "Info")
        self.assertEqual(processed.findings[0].status, "Informational")


# =============================================================================
# 11. SCAN CONTROLLER INTEGRATION TESTS
# =============================================================================

import asyncio
from unittest.mock import patch, AsyncMock

from app.core.scan_controller import (
    run_email_scan,
    run_username_scan,
    run_system_scan,
    run_file_metadata_scan,
    run_browser_scan,
)


class TestScanControllerIntegration(unittest.TestCase):
    """
    Verifies that app.core.scan_controller connects properly to FindingsProcessor
    for all 5 scanning modules, returning valid ScanResult objects with normalized findings.
    """

    def test_controller_email_scan_processes_findings(self):
        mock_data = {
            "status": "SUCCESS",
            "breaches": [
                {
                    "name": "AcmeCorp",
                    "records_exposed": 1000,
                    "industry": "Tech",
                    "exposed_data": ["Passwords", "Emails"],
                    "password_risk": True
                }
            ]
        }
        with patch("app.core.scan_controller.check_email", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = mock_data
            with patch.object(FindingsProcessor, "process_scan_result", wraps=FindingsProcessor.process_scan_result) as spy_proc:
                res = asyncio.run(run_email_scan("target@example.com"))

                spy_proc.assert_called_once()
                self.assertEqual(res.status, "COMPLETED")
                self.assertEqual(len(res.findings), 1)
                finding = res.findings[0]
                self.assertEqual(finding.finding_type, "Email Breach")
                self.assertEqual(finding.severity, "High")
                self.assertIn("AcmeCorp", finding.title)

    def test_controller_email_scan_empty_breaches_no_invented_findings(self):
        with patch("app.core.scan_controller.check_email", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = {"status": "SUCCESS", "breaches": []}
            res = asyncio.run(run_email_scan("clean@example.com"))
            self.assertEqual(res.status, "COMPLETED")
            self.assertEqual(res.findings, [])
            self.assertEqual(res.message, "No known breaches found.")

    def test_controller_username_scan_synthesizes_public_presence(self):
        mock_data = {
            "status": "FOUND",
            "results": [
                {"platform": "GitHub", "profile_url": "https://github.com/target"},
                {"platform": "Twitter", "profile_url": "https://twitter.com/target"},
                {"platform": "Reddit", "profile_url": "https://reddit.com/u/target"},
                {"platform": "Instagram", "profile_url": "https://instagram.com/target"},
            ]
        }
        with patch("app.core.scan_controller.check_username", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = mock_data
            with patch.object(FindingsProcessor, "process_scan_result", wraps=FindingsProcessor.process_scan_result) as spy_proc:
                res = asyncio.run(run_username_scan("target"))

                spy_proc.assert_called_once()
                self.assertEqual(res.status, "COMPLETED")
                self.assertEqual(len(res.findings), 1)
                finding = res.findings[0]
                self.assertEqual(finding.finding_type, "Public Presence")
                self.assertEqual(finding.severity, "Info")
                self.assertEqual(finding.status, "Informational")
                self.assertEqual(finding.title, "Possible username matches — ownership unverified")
                self.assertIn("ownership is unverified", finding.description.lower())
                self.assertEqual(len(finding.evidence), 4)

    def test_controller_username_scan_not_found_no_invented_findings(self):
        with patch("app.core.scan_controller.check_username", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = {"status": "NOT_FOUND"}
            res = asyncio.run(run_username_scan("ghost_user_12345"))
            self.assertEqual(res.status, "COMPLETED")
            self.assertEqual(res.findings, [])
            self.assertEqual(res.message, "No profiles found.")

    def test_controller_system_scan_synthesizes_startup_findings(self):
        mock_data = {
            "status": "SUCCESS",
            "results": {
                "os": "Windows",
                "os_version": "11",
                "installed_applications": [],
                "installed_applications_status": "SUCCESS",
                "running_processes": [],
                "running_processes_status": "SUCCESS",
                "startup_applications": [
                    {"name": "SecurityTool", "source": "Registry", "scope": "User", "command": "tool.exe", "enabled": "True"},
                    {"name": "ChatApp", "source": "Registry", "scope": "User", "command": "chat.exe", "enabled": "True"},
                ],
                "startup_applications_status": "SUCCESS"
            }
        }
        with patch("app.core.scan_controller.check_system", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = mock_data
            with patch.object(FindingsProcessor, "process_scan_result", wraps=FindingsProcessor.process_scan_result) as spy_proc:
                res = asyncio.run(run_system_scan())

                spy_proc.assert_called_once()
                self.assertEqual(res.status, "COMPLETED")
                self.assertEqual(len(res.findings), 1)
                finding = res.findings[0]
                self.assertEqual(finding.finding_type, "System Configuration")
                self.assertIn("Startup Footprint (2 detected)", finding.title)

    def test_controller_file_metadata_scan_processes_sensitive_findings(self):
        mock_data = {
            "status": "SUCCESS",
            "message": "Analysis completed.",
            "results": {
                "file_info": {"file_name": "vacation.jpg", "file_size": "2MB", "file_type": "JPEG Image"},
                "metadata": {"Make": "Canon", "Model": "EOS"},
                "is_supported": True,
                "potentially_sensitive": [
                    {"category": "Location & GPS", "field": "GPS Coordinates", "value": "37.77 N, 122.41 W", "description": "Reveals GPS coordinates."},
                    {"category": "Personal Identification", "field": "Artist", "value": "Alice Photographer", "description": "Exposes author name."}
                ]
            }
        }
        with patch("app.core.scan_controller.check_file_metadata", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = mock_data
            with patch.object(FindingsProcessor, "process_scan_result", wraps=FindingsProcessor.process_scan_result) as spy_proc:
                res = asyncio.run(run_file_metadata_scan("vacation.jpg"))

                spy_proc.assert_called_once()
                self.assertEqual(res.status, "COMPLETED")
                self.assertEqual(len(res.findings), 2)
                gps = next(f for f in res.findings if "Location" in f.title)
                self.assertEqual(gps.severity, "High")
                self.assertEqual(gps.status, "Unremediated")

    def test_controller_file_metadata_scan_clean_file_no_findings(self):
        mock_data = {
            "status": "SUCCESS",
            "message": "Analysis completed.",
            "results": {
                "file_info": {"file_name": "clean.txt", "file_size": "100B", "file_type": "Plain Text"},
                "metadata": {},
                "is_supported": False,
                "potentially_sensitive": []
            }
        }
        with patch("app.core.scan_controller.check_file_metadata", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = mock_data
            res = asyncio.run(run_file_metadata_scan("clean.txt"))
            self.assertEqual(res.status, "COMPLETED")
            self.assertEqual(res.findings, [])

    def test_controller_browser_scan_processes_findings(self):
        mock_data = {
            "status": "SUCCESS",
            "browsers": [
                {"name": "Chrome", "version": "120.0", "detection_source": "Registry", "executable_path": "chrome.exe", "profiles": ["Default"], "extension_count": 1}
            ],
            "extensions": [
                {"name": "AdBlocker", "version": "1.0", "description": "Blocks ads", "extension_id": "ext-1", "browser": "Chrome", "profile": "Default"}
            ],
            "coverage": {
                "browsers_searched": ["Chrome", "Edge"],
                "browsers_detected": ["Chrome"],
                "browsers_not_detected": ["Edge"],
                "unsupported_browsers": [],
                "profiles_scanned": 1,
                "extensions_found": 1,
                "sources_failed": []
            },
            "errors": []
        }
        with patch("app.core.scan_controller.check_browsers", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = mock_data
            with patch.object(FindingsProcessor, "process_scan_result", wraps=FindingsProcessor.process_scan_result) as spy_proc:
                res = asyncio.run(run_browser_scan())

                spy_proc.assert_called_once()
                self.assertEqual(res.status, "COMPLETED")
                self.assertTrue(len(res.findings) >= 1)
                cov = next(f for f in res.findings if f.finding_type == "Scan Coverage")
                self.assertEqual(cov.severity, "Info")

    def test_controller_error_preservation(self):
        with patch("app.core.scan_controller.check_email", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = {"status": "ERROR", "message": "API Failure"}
            res = asyncio.run(run_email_scan("fail@example.com"))
            self.assertEqual(res.status, "ERROR")
            self.assertEqual(res.message, "API Failure")


if __name__ == "__main__":
    unittest.main()

