"""Report generation: one bundle, three formats.

PDF, JSON, and CSV all render from the same :class:`ReportBundle`, which is
built from the same risk summary the dashboard displays. See
docs/REPORT_SCHEMA.md.
"""

from app.core.reporting.builder import build_report_bundle
from app.core.reporting.csv_export import COLUMNS, build_rows, encode_csv, render_csv
from app.core.reporting.errors import ReportExportError
from app.core.reporting.exporter import (
    EXTENSIONS,
    FORMAT_CSV,
    FORMAT_JSON,
    FORMAT_PDF,
    FORMAT_LABELS,
    FORMATS,
    export_report,
    normalize_path,
    render,
)
from app.core.reporting.json_export import bundle_to_dict, render_json
from app.core.reporting.models import (
    SCHEMA_VERSION,
    ReportAction,
    ReportAssessment,
    ReportBundle,
    ReportCoverage,
    ReportFinding,
)
from app.core.reporting.pdf_export import build_html, render_pdf

__all__ = [
    "build_report_bundle",
    "COLUMNS",
    "build_rows",
    "encode_csv",
    "render_csv",
    "ReportExportError",
    "EXTENSIONS",
    "FORMAT_CSV",
    "FORMAT_JSON",
    "FORMAT_PDF",
    "FORMAT_LABELS",
    "FORMATS",
    "export_report",
    "normalize_path",
    "render",
    "bundle_to_dict",
    "render_json",
    "SCHEMA_VERSION",
    "ReportAction",
    "ReportAssessment",
    "ReportBundle",
    "ReportCoverage",
    "ReportFinding",
    "build_html",
    "render_pdf",
]
