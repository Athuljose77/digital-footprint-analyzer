import unittest
import os
import sys

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from PySide6.QtWidgets import QApplication
from app.models.common import ScanResult, FootprintData, Finding
from app.ui.main_window import MainWindow

# Ensure QApplication singleton exists for widget testing
app = QApplication.instance()
if app is None:
    app = QApplication([])


class TestUIFindingsVisibility(unittest.TestCase):
    """
    Focused tests verifying:
    1. File & Metadata scan findings are visible in self.file_results_area (not discarded by early return).
    2. Status is explicitly displayed across all 5 scan modules.
    3. Findings in System Footprint are placed before lengthy installed-application details.
    4. Empty findings are handled cleanly without fabricating findings.
    """

    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    # =========================================================================
    # 1. FILE & METADATA FINDINGS VISIBILITY
    # =========================================================================

    def test_file_metadata_displays_both_footprint_and_findings(self):
        finding = Finding(
            finding_id="f-1",
            finding_type="Sensitive Metadata",
            title="Location Metadata Detected in File",
            description="Geographic coordinates found in EXIF",
            evidence=["37.7749 N, 122.4194 W"],
            severity="High",
            status="Unremediated"
        )
        result = ScanResult(
            scan_id="file-scan-1",
            analysis_mode="My Footprint",
            scan_type="File & Metadata",
            scan_category="File & Metadata Footprint",
            status="COMPLETED",
            message="Analysis completed.",
            footprint_data=[
                FootprintData(category="File & Metadata", subcategory="File Information", source="File System", data_type="file_info", value="vacation.jpg", sensitivity="Low"),
                FootprintData(category="File & Metadata", subcategory="Embedded Metadata", source="EXIF", data_type="tag", value="Make: Canon", sensitivity="Low"),
                FootprintData(category="File & Metadata", subcategory="Potentially Sensitive", source="Location & GPS", data_type="sensitive", value="GPS: 37.77 N", sensitivity="High"),
            ],
            findings=[finding]
        )

        self.window.on_scan_complete(result)
        text = self.window.file_results_area.toPlainText()

        # Verify footprint sections are preserved
        self.assertIn("=== FILE & METADATA FOOTPRINT ===", text)
        self.assertIn("[File Details]", text)
        self.assertIn("vacation.jpg", text)
        self.assertIn("[Extracted Metadata", text)
        self.assertIn("Make: Canon", text)
        self.assertIn("[Potentially Sensitive Metadata", text)

        # Verify processed findings are displayed and not discarded by early return
        self.assertIn("=== FINDINGS ===", text)
        self.assertIn("[High] Location Metadata Detected in File", text)
        self.assertIn("Status: Unremediated", text)
        self.assertIn("Description: Geographic coordinates found in EXIF", text)
        self.assertIn("Evidence: 37.7749 N, 122.4194 W", text)

    def test_file_metadata_empty_findings_does_not_fabricate(self):
        result = ScanResult(
            scan_id="file-scan-2",
            analysis_mode="My Footprint",
            scan_type="File & Metadata",
            scan_category="File & Metadata Footprint",
            status="COMPLETED",
            message="Analysis completed.",
            footprint_data=[
                FootprintData(category="File & Metadata", subcategory="File Information", source="File System", data_type="file_info", value="clean.txt", sensitivity="Low")
            ],
            findings=[]
        )

        self.window.on_scan_complete(result)
        text = self.window.file_results_area.toPlainText()

        self.assertIn("=== FILE & METADATA FOOTPRINT ===", text)
        self.assertNotIn("=== FINDINGS ===", text)

    # =========================================================================
    # 2. SYSTEM FOOTPRINT FINDINGS PLACEMENT
    # =========================================================================

    def test_system_findings_placed_before_installed_applications(self):
        finding = Finding(
            finding_id="sys-f-1",
            finding_type="System Configuration",
            title="Persistent Startup Footprint (2 detected)",
            description="Applications configured to start automatically on system boot were detected.",
            evidence=["App1.exe", "App2.exe"],
            severity="Low",
            status="Informational"
        )
        installed = [
            FootprintData(category="System", subcategory="Installed Applications", source="Registry", data_type="app", value=f"App_{i}", sensitivity="Low")
            for i in range(10)
        ]
        system_info = [
            FootprintData(category="System", subcategory="Operating System", source="System API", data_type="String", value="Windows 11", sensitivity="Low"),
            FootprintData(category="System", subcategory="CPU", source="System API", data_type="String", value="Intel i7", sensitivity="Low"),
        ]
        result = ScanResult(
            scan_id="sys-scan-1",
            analysis_mode="My Footprint",
            scan_type="System",
            scan_category="System Footprint",
            status="COMPLETED",
            message="System scan completed.",
            footprint_data=system_info + installed,
            findings=[finding]
        )

        self.window.on_scan_complete(result)
        text = self.window.sys_results_area.toPlainText()

        # Both sections must be present
        self.assertIn("=== FINDINGS ===", text)
        self.assertIn("Installed Applications (10 detected):", text)

        # FINDINGS must appear before Installed Applications in the text
        idx_findings = text.index("=== FINDINGS ===")
        idx_installed = text.index("Installed Applications (10 detected):")
        self.assertLess(idx_findings, idx_installed, "Findings section must be placed before installed applications!")

        # Verify finding content
        self.assertIn("[Low] Persistent Startup Footprint (2 detected)", text)
        self.assertIn("Status: Informational", text)

    # =========================================================================
    # 3. CONSISTENT STATUS DISPLAY ACROSS MODULES
    # =========================================================================

    def test_status_displayed_in_email_scan(self):
        result = ScanResult(
            scan_id="email-1",
            analysis_mode="Public Footprint Lookup",
            scan_type="Email",
            scan_category="Email Exposure",
            status="COMPLETED",
            findings=[
                Finding(finding_id="1", finding_type="Email Breach", title="Exposed in BreachCorp", description="Records leaked", evidence=["email"], severity="High", status="Unremediated")
            ]
        )
        self.window.on_scan_complete(result)
        text = self.window.results_area.toPlainText()

        self.assertIn("[High] Exposed in BreachCorp", text)
        self.assertIn("Status: Unremediated", text)

    def test_status_displayed_in_username_scan(self):
        result = ScanResult(
            scan_id="user-1",
            analysis_mode="Public Footprint Lookup",
            scan_type="Username",
            scan_category="Public Presence",
            status="COMPLETED",
            footprint_data=[
                FootprintData(category="Public Presence", subcategory="Social Profile", source="GitHub", data_type="URL", value="https://github.com/test", sensitivity="Low")
            ],
            findings=[
                Finding(finding_id="2", finding_type="Public Presence", title="Possible username matches — ownership unverified", description="Profiles found", evidence=["https://github.com/test"], severity="Info", status="Informational")
            ]
        )
        self.window.on_scan_complete(result)
        text = self.window.results_area.toPlainText()

        self.assertIn("[Info] Possible username matches — ownership unverified", text)
        self.assertIn("Status: Informational", text)

    def test_status_displayed_in_browser_scan(self):
        result = ScanResult(
            scan_id="browser-1",
            analysis_mode="My Footprint",
            scan_type="Browser",
            scan_category="Browser Footprint",
            status="COMPLETED",
            findings=[
                Finding(finding_id="3", finding_type="Scan Coverage", title="Browser Scan Coverage", description="Coverage info", evidence=["Chrome"], severity="Info", status="Informational")
            ]
        )
        self.window.on_scan_complete(result)
        text = self.window.browser_results_area.toPlainText()

        self.assertIn("[Info] Browser Scan Coverage", text)
        self.assertIn("Status: Informational", text)


if __name__ == "__main__":
    unittest.main()
