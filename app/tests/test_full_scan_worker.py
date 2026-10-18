"""Phase C tests for Full Scan worker dispatch.

Verifies app/ui/workers.py routes "Full Scan" to run_full_scan, preserves
existing dispatch, guards concurrency via the MainWindow pattern, and
surfaces worker errors through the established signals.
"""
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from PySide6.QtWidgets import QApplication

import app.ui.workers as workers_module
from app.ui.workers import ScanWorker
from app.models.common import ScanResult
from app.services.system_service import DEFAULT_PROCESS_COLLECTOR_MODE

app = QApplication.instance()
if app is None:
    app = QApplication([])


def _result(scan_type="Full Scan", status="COMPLETED"):
    return ScanResult(
        scan_id=f"{scan_type}-id",
        analysis_mode="Full Footprint Analysis"
        if scan_type == "Full Scan"
        else "My Footprint",
        scan_type=scan_type,
        scan_category="Unified Footprint",
        status=status,
        message="done",
    )


class TestFullScanWorkerDispatch(unittest.TestCase):
    def _run_worker(self, worker):
        received = []
        errors = []
        progress = []
        worker.result_ready.connect(received.append)
        worker.error_occurred.connect(errors.append)
        worker.progress_changed.connect(progress.append)
        worker.run()
        return received, errors, progress

    def test_full_scan_without_file_passes_none(self):
        expected = _result("Full Scan")
        with patch.object(
            workers_module, "run_full_scan", AsyncMock(return_value=expected)
        ) as mock_full:
            received, errors, _ = self._run_worker(ScanWorker("Full Scan", ""))
        mock_full.assert_awaited_once()
        args, kwargs = mock_full.await_args
        self.assertIsNone(args[0])
        self.assertIn("progress_callback", kwargs)
        self.assertEqual(received, [expected])
        self.assertEqual(errors, [])

    def test_full_scan_with_file_passes_explicit_path(self):
        expected = _result("Full Scan")
        with patch.object(
            workers_module, "run_full_scan", AsyncMock(return_value=expected)
        ) as mock_full:
            received, errors, _ = self._run_worker(
                ScanWorker("Full Scan", "/tmp/explicit-file.png")
            )
        mock_full.assert_awaited_once()
        args, _ = mock_full.await_args
        self.assertEqual(args[0], "/tmp/explicit-file.png")
        self.assertEqual(received, [expected])
        self.assertEqual(errors, [])

    def test_existing_dispatch_still_works(self):
        cases = [
            ("System", "run_system_scan", ()),
            ("Browser", "run_browser_scan", ()),
            ("File & Metadata", "run_file_metadata_scan", ("/tmp/a.png",)),
            ("Email", "run_email_scan", ("user@example.com",)),
            ("Username", "run_username_scan", ("someuser",)),
        ]
        for scan_type, func_name, expected_args in cases:
            with self.subTest(scan_type=scan_type):
                target = expected_args[0] if expected_args else ""
                expected = _result(scan_type)
                with patch.object(
                    workers_module, func_name, AsyncMock(return_value=expected)
                ) as mock_fn:
                    received, errors, _ = self._run_worker(
                        ScanWorker(scan_type, target)
                    )
                mock_fn.assert_awaited_once_with(*expected_args)
                self.assertEqual(received, [expected])
                self.assertEqual(errors, [])

    def test_full_scan_does_not_touch_public_lookups(self):
        expected = _result("Full Scan")
        with (
            patch.object(
                workers_module, "run_full_scan", AsyncMock(return_value=expected)
            ),
            patch.object(workers_module, "run_email_scan", AsyncMock()) as mock_email,
            patch.object(
                workers_module, "run_username_scan", AsyncMock()
            ) as mock_username,
        ):
            self._run_worker(ScanWorker("Full Scan", ""))
        mock_email.assert_not_awaited()
        mock_username.assert_not_awaited()

    def test_unknown_scan_type_reports_error(self):
        received, errors, _ = self._run_worker(ScanWorker("Nope", ""))
        self.assertEqual(received, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("Unknown scan type", errors[0])

    def test_worker_exception_uses_error_signal(self):
        with patch.object(
            workers_module,
            "run_full_scan",
            AsyncMock(side_effect=RuntimeError("worker boom")),
        ):
            received, errors, _ = self._run_worker(ScanWorker("Full Scan", ""))
        self.assertEqual(received, [])
        self.assertEqual(errors, ["worker boom"])

    def test_result_emitted_once(self):
        expected = _result("Full Scan")
        with patch.object(
            workers_module, "run_full_scan", AsyncMock(return_value=expected)
        ):
            received, errors, _ = self._run_worker(ScanWorker("Full Scan", ""))
        self.assertEqual(len(received), 1)
        self.assertEqual(errors, [])

    def test_progress_forwarded_through_callback(self):
        expected = _result("Full Scan")

        async def _fake_full_scan(file_path=None, progress_callback=None):
            progress_callback("Starting System scan...")
            progress_callback("Aggregating Full Scan results...")
            return expected

        with patch.object(
            workers_module, "run_full_scan", side_effect=_fake_full_scan
        ):
            _, _, progress = self._run_worker(ScanWorker("Full Scan", ""))
        self.assertEqual(
            progress, ["Starting System scan...", "Aggregating Full Scan results..."]
        )

    def test_running_worker_blocks_second_scan(self):
        from app.ui.main_window import MainWindow
        import app.ui.main_window as main_window_module

        window = MainWindow()
        try:
            busy = MagicMock()
            busy.isRunning.return_value = True
            window.worker = busy
            with patch.object(
                main_window_module, "ScanWorker"
            ) as mock_worker_cls:
                window.start_system_scan()
                window.start_browser_scan()
            mock_worker_cls.assert_not_called()
            self.assertIs(window.worker, busy)
        finally:
            window.close()

    def test_idle_worker_starts_individual_scan(self):
        from app.ui.main_window import MainWindow
        import app.ui.main_window as main_window_module

        window = MainWindow()
        try:
            window.worker = None
            with patch.object(
                main_window_module, "ScanWorker"
            ) as mock_worker_cls:
                window.start_system_scan()
            # Scan type and target are the contract; the call also forwards
            # the saved process-collector preference.
            self.assertEqual(mock_worker_cls.call_count, 1)
            args, kwargs = mock_worker_cls.call_args
            self.assertEqual(args[0], "System")
            self.assertEqual(args[1], "")
            self.assertEqual(kwargs["options"]["process_mode"],
                             DEFAULT_PROCESS_COLLECTOR_MODE)
            mock_worker_cls.return_value.start.assert_called_once_with()
        finally:
            window.close()


if __name__ == "__main__":
    unittest.main()
