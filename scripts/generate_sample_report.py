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

from app.core.demo import DEMO_TARGET, build_demo_result
from app.core.remediation import build_plan
from app.core.reporting import (
    FORMAT_CSV,
    FORMAT_JSON,
    FORMAT_PDF,
    build_report_bundle,
    export_report,
)
from app.core.risk import build_risk_summary

OUTPUT_DIR = ROOT / "docs" / "sample-report"


def main() -> None:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])

    result = build_demo_result()
    risk = build_risk_summary(result)
    plan = build_plan(result)
    bundle = build_report_bundle(
        result,
        risk_summary=risk,
        plan=plan,
        target=DEMO_TARGET,
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
