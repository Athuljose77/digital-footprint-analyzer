"""Verification pipeline tests: discovery -> verification -> findings -> UI.

These cover the desktop side of the username work: candidates that were
confirmed by the platform page are marked as such, candidates that could not
be confirmed are never presented as profiles, and the user's choice to allow
(or skip) the verification requests reaches the service. Everything runs
offline: the network layer is replaced by fakes.
"""

import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from PySide6.QtWidgets import QApplication

import app.ui.main_window as main_window_module
import app.ui.workers as workers_module
from app.core.scan_controller import run_username_scan
from app.models.common import ScanResult
from app.ui.main_window import MainWindow
from app.ui.workers import ScanWorker

app = QApplication.instance()
if app is None:
    app = QApplication([])


def service_result(status="FOUND", results=None, confirmed=0, inconclusive=0,
                   checked=0, message="ok"):
    return {
        "username": "target",
        "status": status,
        "message": message,
        "results": results or [],
        "candidates_count": len(results or []),
        "checked_count": checked,
        "confirmed_count": confirmed,
        "inconclusive_count": inconclusive,
        "not_found_count": 0,
        "verification_enabled": True,
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:05Z",
    }


def profile(platform, url, verification):
    return {
        "platform": platform,
        "status": "FOUND",
        "profile_url": url,
        "verification": verification,
        "verification_note": "test",
        "http_status": 200,
        "checked": True,
        "checked_at": "2026-01-01T00:00:03Z",
    }


class TestControllerVerification(unittest.TestCase):
    def run_scan(self, service_payload):
        with patch("app.core.scan_controller.check_username",
                   AsyncMock(return_value=service_payload)) as check:
            result = asyncio.run(run_username_scan("target"))
        return result, check

    def test_confirmed_profiles_are_recorded_as_confirmed(self):
        payload = service_result(
            results=[profile("GitHub", "https://github.com/target", "confirmed")],
            confirmed=1, checked=1, message="Confirmed 1 profile(s).")
        result, _ = self.run_scan(payload)

        self.assertEqual(result.status, "COMPLETED")
        self.assertEqual(result.message, "Confirmed 1 profile(s).")
        self.assertEqual(len(result.footprint_data), 1)
        self.assertEqual(result.footprint_data[0].subcategory, "Confirmed Profile")
        self.assertEqual(result.footprint_data[0].value, "https://github.com/target")

        finding = result.findings[0]
        self.assertEqual(finding.finding_type, "Public Presence")
        self.assertIn("confirmed by fetching the platform page itself",
                      finding.description)
        self.assertIn("does not prove who owns it", finding.description)
        # Ownership is still not claimed.
        self.assertIn("ownership is unverified", finding.description.lower())

    def test_unverified_candidates_are_kept_but_not_confirmed(self):
        payload = service_result(
            status="UNKNOWN",
            results=[profile("Reddit", "https://reddit.com/u/target", "inconclusive")],
            inconclusive=1, checked=1,
            message="1 candidate(s) were found but none could be confirmed.")
        result, _ = self.run_scan(payload)

        self.assertEqual(result.status, "COMPLETED")
        self.assertIn("unverified profile candidate", result.message)
        self.assertEqual(len(result.footprint_data), 1)
        self.assertEqual(result.footprint_data[0].subcategory, "Social Profile")
        self.assertNotIn("confirmed by fetching", result.findings[0].description)
        self.assertIn("ownership is unverified", result.findings[0].description.lower())

    def test_not_found_still_reports_no_profiles(self):
        result, _ = self.run_scan(service_result(status="NOT_FOUND",
                                                 message="No profiles found."))
        self.assertEqual(result.status, "COMPLETED")
        self.assertEqual(result.message, "No profiles found.")
        self.assertEqual(result.findings, [])

    def test_error_status_is_passed_through(self):
        result, _ = self.run_scan(service_result(status="ERROR",
                                                 message="Username is too long."))
        self.assertEqual(result.status, "ERROR")
        self.assertEqual(result.message, "Username is too long.")

    def test_option_like_handle_is_refused_offline(self):
        # The real service validates before starting a subprocess, so this
        # never touches the network or spawns anything.
        with patch("subprocess.run") as run:
            result = asyncio.run(run_username_scan("-tor"))
        run.assert_not_called()
        self.assertEqual(result.status, "ERROR")
        self.assertIn("cannot start with", result.message)


class TestWorkerVerificationOption(unittest.TestCase):
    def run_worker(self, worker):
        received = []
        errors = []
        worker.result_ready.connect(received.append)
        worker.error_occurred.connect(errors.append)
        worker.run()
        return received, errors

    def test_choice_is_forwarded_to_the_service(self):
        expected = ScanResult(
            scan_id="u1", analysis_mode="Public Footprint Lookup",
            scan_type="Username", scan_category="Public Presence",
            status="COMPLETED", message="done")
        with patch.object(workers_module, "run_username_scan",
                          AsyncMock(return_value=expected)) as mock_scan:
            received, errors = self.run_worker(
                ScanWorker("Username", "target",
                           options={"verify_candidates": False}))
        self.assertEqual(received, [expected])
        self.assertEqual(errors, [])
        self.assertFalse(mock_scan.await_args.kwargs["verify"])

    def test_absent_choice_keeps_the_original_call_shape(self):
        expected = ScanResult(
            scan_id="u2", analysis_mode="Public Footprint Lookup",
            scan_type="Username", scan_category="Public Presence",
            status="COMPLETED", message="done")
        with patch.object(workers_module, "run_username_scan",
                          AsyncMock(return_value=expected)) as mock_scan:
            self.run_worker(ScanWorker("Username", "target"))
        self.assertNotIn("verify", mock_scan.await_args.kwargs)


class TestPublicLookupPrivacy(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    def test_the_page_says_the_lookup_goes_external(self):
        text = self.window.privacy_note.text().lower()
        self.assertIn("public platforms", text)
        self.assertIn("directly from this device", text)
        self.assertIn("nothing is uploaded", text)

    def test_verification_is_on_by_default_and_explained(self):
        self.assertTrue(self.window.verify_candidates_checkbox.isChecked())
        tooltip = self.window.verify_candidates_checkbox.toolTip().lower()
        self.assertIn("fetched once", tooltip)
        self.assertIn("uncheck", tooltip)

    def test_choice_reaches_the_worker(self):
        self.window.target_input.setText("someuser")
        self.window.scan_type_combo.setCurrentText("Username")
        self.window.verify_candidates_checkbox.setChecked(False)
        with patch.object(main_window_module, "ScanWorker") as worker_class:
            self.window.start_scan()
        options = worker_class.call_args.kwargs["options"]
        self.assertFalse(options["verify_candidates"])
        self.assertIn("network_timeout", options)


if __name__ == "__main__":
    unittest.main()
