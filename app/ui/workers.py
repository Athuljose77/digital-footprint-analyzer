from PySide6.QtCore import QThread, Signal
import asyncio
from app.core.scan_controller import run_email_scan, run_username_scan, run_system_scan, run_file_metadata_scan
from app.models.common import ScanResult

class ScanWorker(QThread):
    result_ready = Signal(ScanResult)
    error_occurred = Signal(str)

    def __init__(self, scan_type: str, target: str = ""):
        super().__init__()
        self.scan_type = scan_type
        self.target = target

    def run(self):
        try:
            # We need to run the async function in a new event loop
            # because QThread runs in its own thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            if self.scan_type == "Email":
                result = loop.run_until_complete(run_email_scan(self.target))
            elif self.scan_type == "Username":
                result = loop.run_until_complete(run_username_scan(self.target))
            elif self.scan_type == "System":
                result = loop.run_until_complete(run_system_scan())
            elif self.scan_type == "File & Metadata":
                result = loop.run_until_complete(run_file_metadata_scan(self.target))
            else:
                raise ValueError("Unknown scan type")
            
            self.result_ready.emit(result)
            loop.close()
        except Exception as e:
            self.error_occurred.emit(str(e))
