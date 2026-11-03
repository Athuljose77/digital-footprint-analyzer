#!/usr/bin/env python3
"""Generate the checked-in synthetic sample report.

Everything in this report is invented demo data. It must never be replaced
with output from a real scan.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from app.core.findings_processor import with_provenance
from app.core.remediation import build_plan
from app.core.reporting import (
    FORMAT_CSV,
    FORMAT_JSON,
    FORMAT_PDF,
    build_report_bundle,
    export_report,
)
from app.core.risk import build_risk_summary
from app.models.common import Finding, FootprintData, ScanResult

OUTPUT_DIR = ROOT / "docs" / "sample-report"


def sample_result() -> ScanResult:
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
                evidence=["extension: Demo Helper 1.0", "permissions: tabs, history"],
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
        scan_id="demo-scan",
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


def main() -> None:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])

    result = sample_result()
    risk = build_risk_summary(result)
    plan = build_plan(result)
    bundle = build_report_bundle(
        result,
        risk_summary=risk,
        plan=plan,
        target="demo@example.com",
    )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for fmt, filename in (
        (FORMAT_PDF, "sample-report.pdf"),
        (FORMAT_JSON, "sample-report.json"),
        (FORMAT_CSV, "sample-report.csv"),
    ):
        path = export_report(bundle, OUTPUT_DIR / filename, fmt)
        print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
