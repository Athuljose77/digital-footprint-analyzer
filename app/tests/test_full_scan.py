"""Phase A tests for Full Scan orchestration.

Covers local-only coordination of System, Browser, and optional File
modules through app.core.scan_controller.run_full_scan.
"""
import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from app.core import scan_controller
from app.core.scan_controller import run_full_scan
from app.models.common import Finding, FootprintData, ScanResult


def _module_result(
    scan_type="System",
    category="System Footprint",
    status="COMPLETED",
    message="ok",
    footprint=(),
    findings=(),
):
    return ScanResult(
        scan_id=f"{scan_type}-id",
        analysis_mode="My Footprint",
        scan_type=scan_type,
        scan_category=category,
        status=status,
        message=message,
        footprint_data=list(footprint),
        findings=list(findings),
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


def _finding(title, severity="Info", evidence=None):
    return Finding(
        finding_id=f"finding-{title}",
        finding_type="Test Type",
        title=title,
        description=f"Description for {title}",
        evidence=list(evidence) if evidence is not None else [title],
        severity=severity,
        status="Informational",
    )


class TestRunFullScan(unittest.TestCase):
    def test_all_success_with_file(self):
        system = _module_result(
            "System",
            "System Footprint",
            footprint=[_footprint("System", "Operating System", "TestOS")],
            findings=[_finding("System finding", "Low")],
        )
        browser = _module_result(
            "Browser",
            "Browser Footprint",
            footprint=[_footprint("Browser", "Detected Browser", "TestBrowser")],
            findings=[_finding("Browser finding", "Info")],
        )
        file_result = _module_result(
            "File & Metadata",
            "File & Metadata Footprint",
            footprint=[_footprint("File & Metadata", "File Information", "file.txt")],
            findings=[_finding("File finding", "High")],
        )
        with (
            patch.object(
                scan_controller, "run_system_scan", AsyncMock(return_value=system)
            ),
            patch.object(
                scan_controller, "run_browser_scan", AsyncMock(return_value=browser)
            ),
            patch.object(
                scan_controller,
                "run_file_metadata_scan",
                AsyncMock(return_value=file_result),
            ) as mock_file,
        ):
            combined = asyncio.run(run_full_scan("/tmp/explicit-file.png"))

        mock_file.assert_awaited_once_with("/tmp/explicit-file.png")
        self.assertEqual(combined.scan_type, "Full Scan")
        self.assertEqual(combined.scan_category, "Unified Footprint")
        self.assertEqual(combined.analysis_mode, "Full Footprint Analysis")
        self.assertEqual(combined.status, "COMPLETED")
        values = [item.value for item in combined.footprint_data]
        self.assertIn("TestOS", values)
        self.assertIn("TestBrowser", values)
        self.assertIn("file.txt", values)
        titles = [item.title for item in combined.findings]
        self.assertIn("System finding", titles)
        self.assertIn("Browser finding", titles)
        self.assertIn("File finding", titles)
        severities = [item.severity for item in combined.findings]
        self.assertEqual(severities, sorted(
            severities,
            key={"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get,
        ))

    def test_file_skipped_without_path(self):
        system = _module_result("System", "System Footprint")
        browser = _module_result("Browser", "Browser Footprint")
        with (
            patch.object(
                scan_controller, "run_system_scan", AsyncMock(return_value=system)
            ),
            patch.object(
                scan_controller, "run_browser_scan", AsyncMock(return_value=browser)
            ),
            patch.object(
                scan_controller, "run_file_metadata_scan", AsyncMock()
            ) as mock_file,
        ):
            combined = asyncio.run(run_full_scan(None))

        mock_file.assert_not_awaited()
        self.assertEqual(combined.status, "COMPLETED")
        self.assertIn("no file selected", (combined.message or "").lower())

    def test_blank_file_path_is_skipped(self):
        system = _module_result("System", "System Footprint")
        browser = _module_result("Browser", "Browser Footprint")
        with (
            patch.object(
                scan_controller, "run_system_scan", AsyncMock(return_value=system)
            ),
            patch.object(
                scan_controller, "run_browser_scan", AsyncMock(return_value=browser)
            ),
            patch.object(
                scan_controller, "run_file_metadata_scan", AsyncMock()
            ) as mock_file,
        ):
            combined = asyncio.run(run_full_scan("   "))

        mock_file.assert_not_awaited()
        self.assertIn("no file selected", (combined.message or "").lower())

    def test_partial_when_file_fails(self):
        system = _module_result(
            "System",
            "System Footprint",
            footprint=[_footprint("System", "Operating System", "TestOS")],
            findings=[_finding("System finding", "Low")],
        )
        browser = _module_result("Browser", "Browser Footprint")
        failed_file = _module_result(
            "File & Metadata",
            "File & Metadata Footprint",
            status="ERROR",
            message="File scan failed.",
        )
        with (
            patch.object(
                scan_controller, "run_system_scan", AsyncMock(return_value=system)
            ),
            patch.object(
                scan_controller, "run_browser_scan", AsyncMock(return_value=browser)
            ),
            patch.object(
                scan_controller,
                "run_file_metadata_scan",
                AsyncMock(return_value=failed_file),
            ),
        ):
            combined = asyncio.run(run_full_scan("/tmp/explicit-file.png"))

        self.assertEqual(combined.status, "PARTIAL")
        values = [item.value for item in combined.footprint_data]
        self.assertIn("TestOS", values)
        self.assertIn("System finding", [item.title for item in combined.findings])
        self.assertTrue(
            any("File" in item.title for item in combined.findings),
            "expected a file limitation finding",
        )

    def test_total_failure(self):
        failed = lambda name, category: _module_result(
            name, category, status="ERROR", message=f"{name} failed."
        )
        with (
            patch.object(
                scan_controller,
                "run_system_scan",
                AsyncMock(return_value=failed("System", "System Footprint")),
            ),
            patch.object(
                scan_controller,
                "run_browser_scan",
                AsyncMock(return_value=failed("Browser", "Browser Footprint")),
            ),
            patch.object(
                scan_controller,
                "run_file_metadata_scan",
                AsyncMock(
                    return_value=failed(
                        "File & Metadata", "File & Metadata Footprint"
                    )
                ),
            ),
        ):
            combined = asyncio.run(run_full_scan("/tmp/explicit-file.png"))

        self.assertEqual(combined.status, "ERROR")
        self.assertEqual(combined.footprint_data, [])

    def test_exception_isolated(self):
        browser = _module_result("Browser", "Browser Footprint")
        file_result = _module_result("File & Metadata", "File & Metadata Footprint")
        with (
            patch.object(
                scan_controller,
                "run_system_scan",
                AsyncMock(side_effect=RuntimeError("boom")),
            ),
            patch.object(
                scan_controller, "run_browser_scan", AsyncMock(return_value=browser)
            ),
            patch.object(
                scan_controller,
                "run_file_metadata_scan",
                AsyncMock(return_value=file_result),
            ),
        ):
            combined = asyncio.run(run_full_scan("/tmp/explicit-file.png"))

        self.assertEqual(combined.status, "PARTIAL")
        self.assertTrue(
            any("System" in item.title for item in combined.findings),
            "expected a system limitation finding",
        )

    def test_failed_module_does_not_erase_success(self):
        system = _module_result(
            "System",
            "System Footprint",
            footprint=[_footprint("System", "Operating System", "KeptOS")],
        )
        failed_browser = _module_result(
            "Browser", "Browser Footprint", status="ERROR", message="nope"
        )
        with (
            patch.object(
                scan_controller, "run_system_scan", AsyncMock(return_value=system)
            ),
            patch.object(
                scan_controller,
                "run_browser_scan",
                AsyncMock(return_value=failed_browser),
            ),
        ):
            combined = asyncio.run(run_full_scan(None))

        self.assertEqual(combined.status, "PARTIAL")
        self.assertIn(
            "KeptOS", [item.value for item in combined.footprint_data]
        )


class TestRunFullScanFailureSemantics(unittest.TestCase):
    """Phase B: exhaustive failure/status semantics for run_full_scan."""

    def _run(self, system, browser, file_result=None, path=None, include_file=True):
        patches = [
            patch.object(
                scan_controller, "run_system_scan", AsyncMock(return_value=system)
            ),
            patch.object(
                scan_controller, "run_browser_scan", AsyncMock(return_value=browser)
            ),
        ]
        if include_file:
            patches.append(
                patch.object(
                    scan_controller,
                    "run_file_metadata_scan",
                    AsyncMock(return_value=file_result),
                )
            )
        else:
            patches.append(
                patch.object(scan_controller, "run_file_metadata_scan", AsyncMock())
            )
        with patches[0], patches[1], patches[2] as mock_file:
            combined = asyncio.run(run_full_scan(path))
        return combined, mock_file

    def test_system_fails_browser_succeeds(self):
        failed_system = _module_result(
            "System", "System Footprint", status="ERROR", message="sys down"
        )
        browser = _module_result(
            "Browser",
            "Browser Footprint",
            footprint=[_footprint("Browser", "Detected Browser", "KeptBrowser")],
            findings=[_finding("Browser keeps working", "Info")],
        )
        combined, _ = self._run(
            failed_system, browser, path=None, include_file=False
        )
        self.assertEqual(combined.status, "PARTIAL")
        self.assertIn(
            "KeptBrowser", [item.value for item in combined.footprint_data]
        )
        self.assertIn(
            "Browser keeps working", [item.title for item in combined.findings]
        )
        limitation = next(
            item for item in combined.findings if "System" in item.title
        )
        self.assertEqual(limitation.finding_type, "Scan Limitation")

    def test_error_module_is_not_counted_as_success(self):
        system = _module_result("System", "System Footprint")
        failed_browser = _module_result(
            "Browser", "Browser Footprint", status="ERROR", message="bad"
        )
        combined, _ = self._run(system, failed_browser, path=None, include_file=False)
        self.assertNotEqual(combined.status, "COMPLETED")
        self.assertEqual(combined.status, "PARTIAL")

    def test_partial_module_result_counts_as_success_in_canonical_aggregator(self):
        # Documents the canonical aggregator contract (only ERROR counts as
        # failed). Full Scan itself now upgrades this to PARTIAL via the
        # approved Phase C policy; see test_partial_module_produces_partial_aggregate.
        from app.core.findings_processor import FindingsProcessor

        system = _module_result("System", "System Footprint")
        partial_browser = _module_result(
            "Browser",
            "Browser Footprint",
            status="PARTIAL",
            message="some sources failed",
            footprint=[_footprint("Browser", "Detected Browser", "PartialBrowser")],
            findings=[_finding("Partial browser note", "Info")],
        )
        combined = FindingsProcessor.process_module_results(
            {"system": system, "browser": partial_browser}
        )
        self.assertEqual(combined.status, "COMPLETED")
        self.assertIn(
            "PartialBrowser", [item.value for item in combined.footprint_data]
        )

    def test_browser_unavailable_produces_partial_with_limitation(self):
        unavailable = {
            "status": "UNAVAILABLE",
            "browsers": [],
            "extensions": [],
            "coverage": {},
            "unavailable_sources": ["No supported browser found"],
            "errors": [],
        }
        system = _module_result(
            "System",
            "System Footprint",
            footprint=[_footprint("System", "Operating System", "RealOS")],
        )
        with (
            patch.object(
                scan_controller, "run_system_scan", AsyncMock(return_value=system)
            ),
            patch.object(
                scan_controller,
                "check_browsers",
                AsyncMock(return_value=unavailable),
            ),
        ):
            combined = asyncio.run(run_full_scan(None))
        # Approved Phase C policy: browser unavailability downgrades the
        # Full Scan aggregate to PARTIAL with an explicit limitation finding,
        # while successful System data and browser coverage evidence stay.
        self.assertEqual(combined.status, "PARTIAL")
        self.assertIn("RealOS", [item.value for item in combined.footprint_data])
        self.assertTrue(
            any(
                "Unavailable" in str(item.value)
                for item in combined.footprint_data
            ),
            "expected browser coverage evidence to be preserved",
        )
        limitation = next(
            item
            for item in combined.findings
            if item.title == "Module Limitation: Browser"
        )
        self.assertEqual(limitation.finding_type, "Scan Limitation")
        self.assertEqual(limitation.status, "Limitation")

    def test_individual_browser_unavailable_still_completed(self):
        from app.core.scan_controller import run_browser_scan

        unavailable = {
            "status": "UNAVAILABLE",
            "browsers": [],
            "extensions": [],
            "coverage": {},
            "unavailable_sources": ["No supported browser found"],
            "errors": [],
        }
        with patch.object(
            scan_controller,
            "check_browsers",
            AsyncMock(return_value=unavailable),
        ):
            result = asyncio.run(run_browser_scan())
        # Individual Browser scan contract is unchanged by the Full Scan policy.
        self.assertEqual(result.status, "COMPLETED")
        self.assertIn("not available", (result.message or "").lower())

    def test_partial_module_produces_partial_aggregate(self):
        system = _module_result(
            "System",
            "System Footprint",
            footprint=[_footprint("System", "Operating System", "SysOS")],
            findings=[_finding("System finding", "Low")],
        )
        partial_browser = _module_result(
            "Browser",
            "Browser Footprint",
            status="PARTIAL",
            message="Some browser sources failed.",
            footprint=[_footprint("Browser", "Detected Browser", "PartialBrowser")],
            findings=[_finding("Partial browser note", "Info")],
        )
        combined, _ = self._run(
            system, partial_browser, path=None, include_file=False
        )
        self.assertEqual(combined.status, "PARTIAL")
        self.assertIn(
            "PartialBrowser", [item.value for item in combined.footprint_data]
        )
        self.assertIn(
            "Partial browser note", [item.title for item in combined.findings]
        )

    def test_progress_stages_reported_in_order(self):
        system = _module_result("System", "System Footprint")
        browser = _module_result("Browser", "Browser Footprint")
        file_result = _module_result("File & Metadata", "File & Metadata Footprint")
        stages = []
        with (
            patch.object(
                scan_controller, "run_system_scan", AsyncMock(return_value=system)
            ),
            patch.object(
                scan_controller, "run_browser_scan", AsyncMock(return_value=browser)
            ),
            patch.object(
                scan_controller,
                "run_file_metadata_scan",
                AsyncMock(return_value=file_result),
            ),
        ):
            combined = asyncio.run(
                run_full_scan("/tmp/explicit-file.png", progress_callback=stages.append)
            )
        self.assertEqual(combined.status, "COMPLETED")
        self.assertEqual(
            stages,
            [
                "Starting System scan...",
                "Starting Browser scan...",
                "Starting File scan...",
                "Aggregating Full Scan results...",
            ],
        )

    def test_progress_skips_file_stage_without_path(self):
        system = _module_result("System", "System Footprint")
        browser = _module_result("Browser", "Browser Footprint")
        stages = []
        with (
            patch.object(
                scan_controller, "run_system_scan", AsyncMock(return_value=system)
            ),
            patch.object(
                scan_controller, "run_browser_scan", AsyncMock(return_value=browser)
            ),
            patch.object(scan_controller, "run_file_metadata_scan", AsyncMock()),
        ):
            asyncio.run(run_full_scan(None, progress_callback=stages.append))
        self.assertNotIn("Starting File scan...", stages)
        self.assertEqual(
            stages,
            [
                "Starting System scan...",
                "Starting Browser scan...",
                "Aggregating Full Scan results...",
            ],
        )

    def test_progress_callback_errors_do_not_break_scan(self):
        system = _module_result("System", "System Footprint")
        browser = _module_result("Browser", "Browser Footprint")

        def _bad_callback(stage):
            raise RuntimeError("progress listener failed")

        with (
            patch.object(
                scan_controller, "run_system_scan", AsyncMock(return_value=system)
            ),
            patch.object(
                scan_controller, "run_browser_scan", AsyncMock(return_value=browser)
            ),
            patch.object(scan_controller, "run_file_metadata_scan", AsyncMock()),
        ):
            combined = asyncio.run(
                run_full_scan(None, progress_callback=_bad_callback)
            )
        self.assertEqual(combined.status, "COMPLETED")

    def test_limitation_findings_do_not_fabricate_exposure(self):
        failed_system = _module_result(
            "System", "System Footprint", status="ERROR", message="sys down"
        )
        browser = _module_result(
            "Browser",
            "Browser Footprint",
            footprint=[_footprint("Browser", "Detected Browser", "B")],
        )
        combined, _ = self._run(
            failed_system, browser, path=None, include_file=False
        )
        limitation_titles = [
            item.title for item in combined.findings if "System" in item.title
        ]
        self.assertTrue(limitation_titles)
        for item in combined.findings:
            self.assertNotIn(item.finding_type, ("Email Breach", "Public Presence"))
            self.assertNotIn("Exposed in", item.title)

    def test_evidence_merged_and_highest_severity_kept(self):
        low = Finding(
            finding_id="dup-low",
            finding_type="Shared Type",
            title="Shared Title",
            description="short",
            evidence=["alpha"],
            severity="Low",
            status="Informational",
        )
        high = Finding(
            finding_id="dup-high",
            finding_type="Shared Type",
            title="Shared Title",
            description="a much longer and richer description",
            evidence=["beta"],
            severity="High",
            status="Unremediated",
        )
        system = _module_result("System", "System Footprint", findings=[low])
        browser = _module_result("Browser", "Browser Footprint", findings=[high])
        combined, _ = self._run(system, browser, path=None, include_file=False)
        merged = [
            item
            for item in combined.findings
            if item.title == "Shared Title"
        ]
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].severity, "High")
        self.assertEqual(sorted(merged[0].evidence), ["alpha", "beta"])
        self.assertEqual(
            merged[0].description, "a much longer and richer description"
        )

    def test_browser_exception_isolated(self):
        system = _module_result(
            "System",
            "System Footprint",
            footprint=[_footprint("System", "Operating System", "SysOS")],
        )
        with (
            patch.object(
                scan_controller, "run_system_scan", AsyncMock(return_value=system)
            ),
            patch.object(
                scan_controller,
                "run_browser_scan",
                AsyncMock(side_effect=RuntimeError("browser boom")),
            ),
            patch.object(scan_controller, "run_file_metadata_scan", AsyncMock()),
        ):
            combined = asyncio.run(run_full_scan(None))
        self.assertEqual(combined.status, "PARTIAL")
        self.assertIn("SysOS", [item.value for item in combined.footprint_data])
        self.assertTrue(
            any("Browser" in item.title for item in combined.findings)
        )

    def test_file_exception_isolated(self):
        system = _module_result("System", "System Footprint")
        browser = _module_result("Browser", "Browser Footprint")
        with (
            patch.object(
                scan_controller, "run_system_scan", AsyncMock(return_value=system)
            ),
            patch.object(
                scan_controller, "run_browser_scan", AsyncMock(return_value=browser)
            ),
            patch.object(
                scan_controller,
                "run_file_metadata_scan",
                AsyncMock(side_effect=RuntimeError("file boom")),
            ),
        ):
            combined = asyncio.run(run_full_scan("/tmp/explicit-file.png"))
        self.assertEqual(combined.status, "PARTIAL")
        self.assertTrue(
            any("File" in item.title for item in combined.findings)
        )

    def test_no_file_scan_or_traversal_without_path(self):
        system = _module_result("System", "System Footprint")
        browser = _module_result("Browser", "Browser Footprint")
        with (
            patch.object(
                scan_controller, "run_system_scan", AsyncMock(return_value=system)
            ),
            patch.object(
                scan_controller, "run_browser_scan", AsyncMock(return_value=browser)
            ),
            patch.object(
                scan_controller, "run_file_metadata_scan", AsyncMock()
            ) as mock_file,
            patch("os.walk") as mock_walk,
            patch("pathlib.Path.rglob") as mock_rglob,
        ):
            combined = asyncio.run(run_full_scan("  \n "))
        mock_file.assert_not_awaited()
        mock_walk.assert_not_called()
        mock_rglob.assert_not_called()
        self.assertIn("no file selected", (combined.message or "").lower())

    def test_public_lookups_never_called(self):
        system = _module_result("System", "System Footprint")
        browser = _module_result("Browser", "Browser Footprint")
        with (
            patch.object(
                scan_controller, "run_system_scan", AsyncMock(return_value=system)
            ),
            patch.object(
                scan_controller, "run_browser_scan", AsyncMock(return_value=browser)
            ),
            patch.object(scan_controller, "run_file_metadata_scan", AsyncMock()),
            patch.object(
                scan_controller, "run_email_scan", AsyncMock()
            ) as mock_email,
            patch.object(
                scan_controller, "run_username_scan", AsyncMock()
            ) as mock_username,
            patch.object(scan_controller, "check_email", AsyncMock()) as mock_check_email,
            patch.object(
                scan_controller, "check_username", AsyncMock()
            ) as mock_check_username,
        ):
            asyncio.run(run_full_scan(None))
        mock_email.assert_not_called()
        mock_username.assert_not_called()
        mock_check_email.assert_not_awaited()
        mock_check_username.assert_not_awaited()


class TestScanTimestamps(unittest.TestCase):
    """started_at/finished_at are real wall-clock values, not blanks.

    History records and exported reports read these fields, so a scan that
    never stamps them renders "Started: —" and an empty history timestamp.
    """

    def test_module_runners_are_decorated(self):
        for name in (
            "run_email_scan",
            "run_username_scan",
            "run_system_scan",
            "run_file_metadata_scan",
            "run_browser_scan",
            "run_full_scan",
        ):
            runner = getattr(scan_controller, name)
            self.assertTrue(
                getattr(runner, "__wrapped__", None) is not None,
                f"{name} is not wrapped by _timestamped_scan",
            )

    def test_decorator_stamps_result_and_preserves_calls(self):
        seen = []

        @scan_controller._timestamped_scan
        async def fake(positional, *, keyword=None):
            seen.append((positional, keyword))
            return _module_result("Test", "Test Footprint")

        result = asyncio.run(fake("value", keyword="kw"))

        self.assertEqual(seen, [("value", "kw")])
        self.assertTrue(result.started_at.endswith("Z"))
        self.assertTrue(result.finished_at.endswith("Z"))
        self.assertLessEqual(result.started_at, result.finished_at)

    def test_full_scan_result_is_timestamped(self):
        system = _module_result("System", "System Footprint")
        browser = _module_result("Browser", "Browser Footprint")
        with (
            patch.object(
                scan_controller, "run_system_scan", AsyncMock(return_value=system)
            ),
            patch.object(
                scan_controller, "run_browser_scan", AsyncMock(return_value=browser)
            ),
        ):
            combined = asyncio.run(run_full_scan(None))

        self.assertTrue(combined.started_at.endswith("Z"))
        self.assertTrue(combined.finished_at.endswith("Z"))
        self.assertLessEqual(combined.started_at, combined.finished_at)


if __name__ == "__main__":
    unittest.main()
