"""Synthetic demo scan used by the desktop UI and sample report.

The demo result is deliberately self-contained: it never touches the network,
reads device data, or writes scan history. All values are invented and are
safe to show to new users, reviewers, and screenshots.
"""

from app.core.findings_processor import with_provenance
from app.models.common import Finding, FootprintData, ScanResult

DEMO_SCAN_ID = "demo-scan"
DEMO_TARGET = "demo@example.com"


def build_demo_result() -> ScanResult:
    """Return a clearly synthetic Full Scan result for demo mode."""
    findings = [
        with_provenance(
            Finding(
                finding_id="demo-email-breach",
                finding_type="Email Breach",
                title="Demo address appears in a breach data set",
                description=(
                    "A synthetic demo address appears in a simulated breach "
                    "record. This is sample data, not a real lookup."
                ),
                evidence=["emails: 3"],
                severity="High",
                status="Unremediated",
                category="Exposure",
                rule_id="EML-BREACH-001",
            ),
            explicit_module="email",
            explicit_verification="provider-verified",
        ),
        with_provenance(
            Finding(
                finding_id="demo-browser-extension",
                finding_type="Browser Extension",
                title="Demo browser extension can read browsing data",
                description=(
                    "A simulated extension has broad permissions. Review "
                    "extensions you do not recognise."
                ),
                evidence=[
                    "extension: Demo Helper 1.0",
                    "permissions: tabs, history",
                ],
                severity="Medium",
                status="Unremediated",
                category="Configuration",
                rule_id="BRS-EXT-001",
            ),
            explicit_module="browser",
            explicit_verification="direct-observation",
        ),
    ]
    footprint = [
        FootprintData(
            category="System",
            subcategory="Operating System",
            source="Synthetic demo",
            data_type="String",
            value="DemoOS 1.0",
            sensitivity="Low",
        ),
        FootprintData(
            category="Browser",
            subcategory="Extensions",
            source="Synthetic demo",
            data_type="String",
            value="1 demo extension",
            sensitivity="Medium",
        ),
        FootprintData(
            category="File",
            subcategory="Image",
            source="Synthetic demo",
            data_type="String",
            value="demo-photo.jpg",
            sensitivity="Low",
        ),
    ]
    result = ScanResult(
        scan_id=DEMO_SCAN_ID,
        analysis_mode="Full Footprint Analysis",
        scan_type="Full Scan",
        scan_category="Unified Footprint",
        status="PARTIAL",
        message="Synthetic demo scan. No real device data was collected.",
        footprint_data=footprint,
        findings=findings,
        module_coverage=[
            {"name": "System", "key": "system", "state": "completed",
             "note": "Synthetic demo data"},
            {"name": "Browser", "key": "browser", "state": "limited",
             "note": "Synthetic demo data; one profile"},
            {"name": "File", "key": "file_metadata", "state": "skipped",
             "note": "No file selected in this demo"},
        ],
    )
    result.started_at = "2026-11-03T10:00:00Z"
    result.finished_at = "2026-11-03T10:00:05Z"
    return result
