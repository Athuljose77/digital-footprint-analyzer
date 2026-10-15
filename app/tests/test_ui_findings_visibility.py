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
    1. File & Metadata scan findings are visible in the split Findings view.
    2. Status is explicitly displayed via the scan status label.
    3. System collected evidence remains accessible separately.
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
            status="Unremediated",
            category="Concern",
            rule_id=None,
            limitations=None,
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
        findings_html = self.window.file_findings_area.toHtml()

        # Verify processed findings are displayed and not discarded by early return
        self.assertIn("Location Metadata Detected in File", findings_html)
        self.assertIn("Geographic coordinates found in EXIF", findings_html)
        self.assertIn("37.7749 N, 122.4194 W", findings_html)

        evidence_html = self.window.file_results_area.toHtml()
        # Verify footprint sections are preserved in collected evidence
        self.assertIn("vacation.jpg", evidence_html)
        self.assertIn("Make: Canon", evidence_html)

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
        findings_html = self.window.file_findings_area.toHtml()

        self.assertIn("No findings were generated for this scan.", findings_html)

    # =========================================================================
    # 2. SYSTEM FOOTPRINT FINDINGS ACCESSIBILITY
    # =========================================================================

    def test_system_findings_are_available_in_split_view(self):
        finding = Finding(
            finding_id="sys-f-1",
            finding_type="System Configuration",
            title="Persistent Startup Footprint (2 detected)",
            description="Applications configured to start automatically on system boot were detected.",
            evidence=["App1.exe", "App2.exe"],
            severity="Low",
            status="Informational",
            category="Observation",
            rule_id=None,
            limitations=None,
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
        findings_html = self.window.sys_findings_area.toHtml()
        evidence_html = self.window.sys_results_area.toHtml()

        self.assertIn("Persistent Startup Footprint (2 detected)", findings_html)
        self.assertIn("Installed Applications (10 detected):", evidence_html)
        self.assertEqual(self.window.sys_sub_tabs.tabText(0), "Findings (1)")
        self.assertEqual(self.window.sys_sub_tabs.tabText(1), "Collected Evidence (12)")

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
        findings_html = self.window.public_findings_area.toHtml()

        self.assertIn("Exposed in BreachCorp", findings_html)

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
        findings_html = self.window.public_findings_area.toHtml()

        self.assertIn("Possible username matches — ownership unverified", findings_html)

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
        findings_html = self.window.browser_findings_area.toHtml()

        self.assertIn("Browser Scan Coverage", findings_html)


if __name__ == "__main__":
    unittest.main()
