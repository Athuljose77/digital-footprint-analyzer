from PySide6.QtCore import QThread, Signal
import asyncio
from app.core.scan_controller import run_email_scan, run_username_scan, run_system_scan, run_file_metadata_scan, run_browser_scan, run_full_scan
from app.models.common import ScanResult

class ScanWorker(QThread):
    result_ready = Signal(ScanResult)
    error_occurred = Signal(str)
    progress_changed = Signal(str)

    def __init__(self, scan_type: str, target: str = "", options: dict = None):
        """Run one scan off the UI thread.

        Args:
            scan_type: which scan to run.
            target: scan target (email, username, file path).
            options: optional user preferences applied to this scan, e.g.
                {"process_mode": ..., "network_timeout": ...}. None or a
                missing key keeps each service's own default, so existing
                callers behave exactly as before.
        """
        super().__init__()
        self.scan_type = scan_type
        self.target = target
        self.options = dict(options or {})

    def run(self):
        try:
            # We need to run the async function in a new event loop
            # because QThread runs in its own thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            timeout = self.options.get("network_timeout")
            process_mode = self.options.get("process_mode")

            # Preference kwargs are only passed when the user actually set
            # one, so an unset preference keeps the exact original call
            # shape and each service falls back to its own default.
            if self.scan_type == "Email":
                coro = (run_email_scan(self.target) if timeout is None
                        else run_email_scan(self.target, timeout=timeout))
                result = loop.run_until_complete(coro)
            elif self.scan_type == "Username":
                coro = (run_username_scan(self.target) if timeout is None
                        else run_username_scan(self.target, timeout=timeout))
                result = loop.run_until_complete(coro)
            elif self.scan_type == "System":
                coro = (run_system_scan() if process_mode is None
                        else run_system_scan(process_mode=process_mode))
                result = loop.run_until_complete(coro)
            elif self.scan_type == "File & Metadata":
                result = loop.run_until_complete(run_file_metadata_scan(self.target))
            elif self.scan_type == "Browser":
                result = loop.run_until_complete(run_browser_scan())
            elif self.scan_type == "Full Scan":
                # Target carries the optional explicitly selected file path;
                # empty means System + Browser with File Metadata skipped.
                result = loop.run_until_complete(
                    run_full_scan(
                        self.target or None,
                        progress_callback=self.progress_changed.emit,
                    )
                )
            else:
                raise ValueError("Unknown scan type")

            self.result_ready.emit(result)
            loop.close()
        except Exception as e:
            self.error_occurred.emit(str(e))
